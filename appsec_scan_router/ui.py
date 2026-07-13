from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import re
import secrets
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .auth import (
    AuthManager,
    GitHubEnterpriseOAuthConfig,
    GoogleOAuthConfig,
    SessionRecord,
    TestLoginConfig,
    auth_state_dir,
    expired_session_cookie,
    session_cookie,
)
from .constants import (
    APPLICATION_TYPE_LABELS,
    DEFAULT_OUT_PREFIX,
    DEFAULT_POSTGRES_DATABASE,
    DEFAULT_POSTGRES_HOST,
    DEFAULT_POSTGRES_PORT,
    DEFAULT_POSTGRES_SCHEMA,
    DEFAULT_POSTGRES_TABLE,
    DEFAULT_POSTGRES_USER,
    DEFAULT_SOURCE_WORKERS,
    KNOWN_INVENTORY_TYPES,
)
from .github import (
    configured_github_app_id,
    configured_github_installation_id,
    configured_github_owners,
)
from .observability import configure_logging, log_github_app_context, observability_dsn
from .postgres import database_status, export_inventory_csv, export_inventory_json, search_inventory
from .runtime import REPORT_EXTENSIONS, SCAN_STATUSES_DONE, ScanManager, ScanRun
from .scan_request import (
    build_scan_command,
    normalize_database_config,
    normalize_scan_config,
    redact_command,
    scan_environment,
)
from .scheduling import ScanScheduler
from .source_discovery import discover_source_targets
from .target_filters import parse_source_target_filter_values, target_filter_value


DEFAULT_UI_HOST = "127.0.0.1"
DEFAULT_UI_PORT = 48731
DEFAULT_MAX_JSON_BODY_BYTES = 1_048_576
HOST_HEADER_RE = re.compile(r"^[A-Za-z0-9.:\-\[\]]+$")
SECURITY_HEADER_VALUES = {
    "Content-Security-Policy": "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow",
    "X-XSS-Protection": "0",
}


LOGGER = logging.getLogger("appsec_scan_router")


class ApplicationInventoryServiceHandler(BaseHTTPRequestHandler):
    server_version = "ApplicationInventoryService"
    sys_version = ""
    manager: ScanManager
    scheduler: ScanScheduler
    auth: AuthManager
    observability_dsn: str = ""
    observability_schema: str = DEFAULT_POSTGRES_SCHEMA
    health_cache: dict[str, Any] | None = None
    health_cache_at: float = 0.0

    def handle_one_request(self) -> None:
        started = time.monotonic()
        try:
            super().handle_one_request()
        finally:
            method = clean_text(getattr(self, "command", ""))
            path = urlparse(clean_text(getattr(self, "path", ""))).path
            if method and path:
                LOGGER.info(
                    "HTTP request %s %s status=%s",
                    method,
                    path,
                    getattr(self, "response_status", 0),
                    extra={
                        "event_type": "http.request",
                        "duration_ms": round((time.monotonic() - started) * 1000, 2),
                        "status": str(getattr(self, "response_status", 0)),
                        "metadata": {"method": method, "path": path},
                    },
                )

    def send_response(self, code: int, message: str | None = None) -> None:
        self.response_status = code
        super().send_response(code, message)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            self.send_static("index.html", "text/html; charset=utf-8")
            return
        if path.startswith("/static/"):
            self.handle_static(path)
            return
        if path == "/api/health":
            self.handle_health()
            return
        if path == "/api/metrics":
            self.handle_metrics()
            return
        if path == "/api/config":
            self.send_json(default_ui_config(self.manager.reports_root))
            return
        if path == "/api/session":
            self.send_json({"session": self.auth.status(self.current_session())})
            return
        if path == "/api/auth/github-enterprise/start":
            self.handle_github_enterprise_auth_start()
            return
        if path == "/api/auth/github-enterprise/callback":
            self.handle_github_enterprise_auth_callback(parsed.query)
            return
        if path == "/api/auth/google/start":
            self.handle_google_auth_start()
            return
        if path == "/api/auth/google/callback":
            self.handle_google_auth_callback(parsed.query)
            return
        if path == "/api/auth/test/start":
            self.handle_test_auth_start()
            return
        if path == "/api/scans":
            record = self.require_session()
            if not record:
                return
            self.send_json({"scans": self.manager.list_scans(owner_scope(record))})
            return
        if path == "/api/schedules":
            record = self.require_session()
            if not record:
                return
            self.send_json({"schedules": self.scheduler.list_schedules(owner_scope(record))})
            return
        if path.startswith("/api/scans/"):
            self.handle_scan_get(path)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/scans":
            self.handle_start_scan()
            return
        if path == "/api/schedules":
            self.handle_create_schedule()
            return
        if path == "/api/auth/logout":
            self.handle_logout()
            return
        if path == "/api/credentials/delete":
            self.handle_delete_credential()
            return
        if path == "/api/database/status":
            self.handle_database_status()
            return
        if path == "/api/database/export":
            self.handle_database_export()
            return
        if path == "/api/database/search":
            self.handle_database_search()
            return
        if path == "/api/source-targets":
            self.handle_source_targets()
            return
        if path.startswith("/api/scans/") and path.rsplit("/", 1)[-1] in {"pause", "resume", "stop"}:
            self.handle_scan_action(path)
            return
        if path.startswith("/api/schedules/") and path.rsplit("/", 1)[-1] in {"enable", "disable", "run"}:
            self.handle_schedule_action(path)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/schedules/"):
            self.handle_delete_schedule(path)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def handle_static(self, path: str) -> None:
        name = Path(unquote(path.removeprefix("/static/"))).name
        content_type = {
            ".css": "text/css; charset=utf-8",
            ".jpg": "image/jpeg",
            ".js": "text/javascript; charset=utf-8",
            ".png": "image/png",
            ".svg": "image/svg+xml",
        }.get(Path(name).suffix, "application/octet-stream")
        self.send_static(name, content_type)

    def handle_scan_get(self, path: str) -> None:
        record = self.require_session()
        if not record:
            return
        parts = [part for part in path.split("/") if part]
        if len(parts) < 3:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        scan_id = parts[2]
        run = self.manager.get_scan(scan_id)
        if not run:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if run_owner_id(run) != owner_scope(record):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if len(parts) == 3:
            self.send_json({"scan": run.summary()})
            return
        if len(parts) == 4 and parts[3] == "logs":
            self.send_json({"logs": list(run.logs)})
            return
        if len(parts) == 4 and parts[3] == "events":
            self.stream_scan_events(run)
            return
        if len(parts) == 5 and parts[3] == "reports":
            self.send_report(run, parts[4])
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def handle_start_scan(self) -> None:
        try:
            payload = self.read_json()
            record = self.current_session()
            if not self.valid_csrf(record):
                return
            payload = dict(payload)
            payload["ownerUserId"] = owner_scope(record)
            payload["ownerUserLogin"] = owner_login(record)
            payload = self.auth.apply_credentials(payload, record)
            run = self.manager.start_scan(payload)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.send_json({"scan": run.summary()}, HTTPStatus.CREATED)

    def handle_scan_action(self, path: str) -> None:
        record = self.current_session()
        if not self.valid_csrf(record):
            return
        parts = [part for part in path.split("/") if part]
        if len(parts) != 4:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        scan_id, action = parts[2], parts[3]
        run = self.manager.get_scan(scan_id)
        if not run or run_owner_id(run) != owner_scope(record):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        operation = {
            "pause": self.manager.pause_scan,
            "resume": self.manager.resume_scan,
            "stop": self.manager.stop_scan,
        }[action]
        try:
            updated = operation(scan_id)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            return
        self.send_json({"scan": updated.summary()})

    def handle_create_schedule(self) -> None:
        try:
            record = self.current_session()
            if not self.valid_csrf(record):
                return
            payload = self.read_json()
            scan_config = payload.get("scan")
            if not isinstance(scan_config, dict):
                raise ValueError("Schedule scan configuration is required.")
            scan_config = dict(scan_config)
            scan_config["ownerUserId"] = owner_scope(record)
            scan_config["ownerUserLogin"] = owner_login(record)
            scan_config = self.auth.apply_credentials(scan_config, record)
            schedule = self.scheduler.create_schedule(
                name=clean_text(payload.get("name")),
                frequency=clean_text(payload.get("frequency")),
                run_at=clean_text(payload.get("runAt")),
                config=scan_config,
                owner_user_id=owner_scope(record),
                owner_user_login=owner_login(record),
            )
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.send_json({"schedule": schedule.summary()}, HTTPStatus.CREATED)

    def handle_schedule_action(self, path: str) -> None:
        record = self.current_session()
        if not self.valid_csrf(record):
            return
        parts = [part for part in path.split("/") if part]
        if len(parts) != 4:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        schedule_id, action = parts[2], parts[3]
        if action == "run":
            schedule = self.scheduler.run_now(schedule_id, owner_scope(record))
        else:
            schedule = self.scheduler.set_enabled(schedule_id, owner_scope(record), action == "enable")
        if not schedule:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_json({"schedule": schedule.summary()})

    def handle_delete_schedule(self, path: str) -> None:
        record = self.current_session()
        if not self.valid_csrf(record):
            return
        parts = [part for part in path.split("/") if part]
        if len(parts) != 3 or not self.scheduler.delete_schedule(parts[2], owner_scope(record)):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_json({"deleted": True})

    def handle_github_enterprise_auth_start(self) -> None:
        try:
            self.redirect(self.auth.github_enterprise_oauth.authorization_url(self.redirect_uri("github-enterprise")))
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_github_enterprise_auth_callback(self, query: str) -> None:
        params = parse_qs(query)
        code = clean_text(first_query_value(params, "code"))
        state = clean_text(first_query_value(params, "state"))
        if not code or not state:
            self.redirect("/?auth=failed&provider=github-enterprise")
            return
        try:
            user, token = self.auth.github_enterprise_oauth.complete_with_token(
                code,
                state,
                self.redirect_uri("github-enterprise"),
            )
            record = self.auth.create_session(user, provider_token=token)
        except ValueError:
            self.redirect("/?auth=failed&provider=github-enterprise")
            return
        self.redirect("/?auth=success&provider=github-enterprise", session_cookie(record.id, secure_cookie()))

    def handle_google_auth_start(self) -> None:
        try:
            self.redirect(self.auth.google_oauth.authorization_url(self.redirect_uri("google")))
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_google_auth_callback(self, query: str) -> None:
        params = parse_qs(query)
        code = clean_text(first_query_value(params, "code"))
        state = clean_text(first_query_value(params, "state"))
        if not code or not state:
            self.redirect("/?auth=failed&provider=google")
            return
        try:
            user = self.auth.google_oauth.complete(code, state, self.redirect_uri("google"))
            record = self.auth.create_session(user)
        except ValueError:
            self.redirect("/?auth=failed&provider=google")
            return
        self.redirect("/?auth=success&provider=google", session_cookie(record.id, secure_cookie()))

    def handle_test_auth_start(self) -> None:
        try:
            record = self.auth.create_test_session()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.redirect("/?auth=success&provider=test", session_cookie(record.id, secure_cookie()))

    def handle_logout(self) -> None:
        record = self.current_session()
        if record and not self.valid_csrf(record):
            return
        if record:
            self.auth.logout(record.id)
        self.send_json({"session": self.auth.status(None)}, headers={"Set-Cookie": expired_session_cookie(secure_cookie())})

    def handle_delete_credential(self) -> None:
        try:
            record = self.current_session()
            if not self.valid_csrf(record):
                return
            payload = self.read_json()
            self.auth.delete_credential(clean_text(payload.get("provider")), record)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.send_json({"session": self.auth.status(record)})

    def handle_database_status(self) -> None:
        try:
            record = self.current_session()
            if not self.valid_csrf(record):
                return
            config = normalize_database_config(self.read_json())
            status = database_status(
                config["postgresDsn"],
                schema=config["postgresSchema"],
                table=config["postgresTable"],
                owner_user_id=owner_scope(record),
            )
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.send_json({"database": status})

    def handle_health(self) -> None:
        now = time.monotonic()
        database = self.health_cache
        if now - self.health_cache_at >= 10.0:
            database = None
            if self.observability_dsn:
                database = database_status(
                    self.observability_dsn,
                    schema=self.observability_schema,
                    table=DEFAULT_POSTGRES_TABLE,
                )
            type(self).health_cache = database
            type(self).health_cache_at = now
        self.send_json(
            {
                "status": "ok" if database is None or database.get("connected") else "degraded",
                "service": "application-inventory-service",
                "database": database,
                "observability": {
                    "enabled": bool(self.observability_dsn),
                    "schema": self.observability_schema,
                    "table": f"{self.observability_schema}.observability_events",
                },
            }
        )

    def handle_metrics(self) -> None:
        metrics = self.manager.metrics()
        metrics.update(self.scheduler.metrics())
        self.send_json(
            {
                "service": "application-inventory-service",
                "metrics": metrics,
                "observability": {
                    "enabled": bool(self.observability_dsn),
                    "schema": self.observability_schema,
                    "table": f"{self.observability_schema}.observability_events",
                },
            }
        )

    def handle_database_export(self) -> None:
        try:
            record = self.current_session()
            if not self.valid_csrf(record):
                return
            payload = self.read_json()
            config = normalize_database_config(payload)
            export_format = clean_choice(payload.get("format"), {"csv", "json"}, "csv")
            query = clean_text(payload.get("query"))
            if export_format == "json":
                content = export_inventory_json(
                    config["postgresDsn"],
                    schema=config["postgresSchema"],
                    owner_user_id=owner_scope(record),
                    query=query,
                    table=config["postgresTable"],
                )
                filename = "application_inventory_database_export.json"
                content_type = "application/json"
            else:
                content = export_inventory_csv(
                    config["postgresDsn"],
                    schema=config["postgresSchema"],
                    owner_user_id=owner_scope(record),
                    query=query,
                    table=config["postgresTable"],
                )
                filename = "application_inventory_database_export.csv"
                content_type = "text/csv"
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            self.send_json({"error": database_export_error(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.send_bytes(
            content,
            content_type,
            headers={"Content-Disposition": attachment_header(filename)},
        )

    def handle_database_search(self) -> None:
        try:
            record = self.current_session()
            if not self.valid_csrf(record):
                return
            payload = self.read_json()
            config = normalize_database_config(payload)
            result = search_inventory(
                config["postgresDsn"],
                schema=config["postgresSchema"],
                owner_user_id=owner_scope(record),
                query=clean_text(payload.get("query")),
                limit=positive_int(payload.get("limit"), 100),
                offset=max(0, integer_value(payload.get("offset"), 0)),
                table=config["postgresTable"],
            )
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            self.send_json({"error": database_export_error(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.send_json({"search": result})

    def handle_source_targets(self) -> None:
        try:
            record = self.current_session()
            if not self.valid_csrf(record):
                return
            payload = self.auth.apply_credentials(self.read_json(), record)
            targets = discover_source_targets(payload)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if targets.get("errors") and targets.get("targets"):
            status = HTTPStatus.MULTI_STATUS
        elif targets.get("errors"):
            status = HTTPStatus.BAD_GATEWAY
        else:
            status = HTTPStatus.OK
        self.send_json(targets, status)

    def send_static(self, name: str, content_type: str) -> None:
        try:
            content = static_content(name)
        except FileNotFoundError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "private, max-age=300")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            return

    def send_report(self, run: ScanRun, filename: str) -> None:
        clean_name = Path(unquote(filename)).name
        path = (run.reports_dir / clean_name).resolve()
        try:
            path.relative_to(run.reports_dir.resolve())
        except ValueError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not path.is_file() or path.suffix.lower() not in REPORT_EXTENSIONS:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_length = path.stat().st_size
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", report_content_type(path))
        self.send_header("Content-Disposition", attachment_header(path.name))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Length", str(content_length))
        self.end_headers()
        try:
            with path.open("rb") as report_file:
                shutil.copyfileobj(report_file, self.wfile, length=1024 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            return

    def stream_scan_events(self, run: ScanRun) -> None:
        listener = run.add_listener()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.write_event("status", run.summary())
            for line in run.summary()["logsTail"]:
                self.write_event("log", {"line": line})
            if run.status in SCAN_STATUSES_DONE:
                self.write_event("done", run.summary())
                return
            while True:
                try:
                    item = listener.get(timeout=20)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                if item is None:
                    self.write_event("done", run.summary())
                    return
                self.write_event(item["event"], item["data"])
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            return
        finally:
            run.remove_listener(listener)

    def write_event(self, event: str, data: dict[str, Any]) -> None:
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()
        self.wfile.write(payload)
        self.wfile.flush()

    def read_json(self) -> dict[str, Any]:
        raw_length = clean_text(self.headers.get("Content-Length", "0") or "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Content-Length must be a valid integer.") from exc
        if length <= 0:
            return {}
        if length > max_json_body_bytes():
            raise ValueError("Request body is too large.")
        body = self.rfile.read(length)
        try:
            data = json.loads(body.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError("Request body must be UTF-8 encoded JSON.") from exc
        except json.JSONDecodeError as exc:
            raise ValueError("Request body must be valid JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("Request body must be a JSON object.")
        return data

    def send_json(
        self,
        payload: dict[str, Any],
        status: HTTPStatus = HTTPStatus.OK,
        headers: dict[str, str] | None = None,
    ) -> None:
        content = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Length", str(len(content)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            return

    def send_bytes(
        self,
        content: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Length", str(len(content)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, format: str, *args: Any) -> None:
        return

    def redirect(self, location: str, cookie: str = "") -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def end_headers(self) -> None:
        for name, value in security_headers().items():
            self.send_header(name, value)
        super().end_headers()

    def current_session(self) -> SessionRecord | None:
        return self.auth.session(self.headers.get("Cookie", ""))

    def require_session(self) -> SessionRecord | None:
        record = self.current_session()
        if not record:
            self.send_json({"error": "Sign in first."}, HTTPStatus.UNAUTHORIZED)
            return None
        return record

    def valid_csrf(self, record: SessionRecord | None) -> bool:
        if not record:
            self.send_json({"error": "Sign in first."}, HTTPStatus.UNAUTHORIZED)
            return False
        if not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), record.csrf_token):
            self.send_json({"error": "Session validation failed. Refresh and try again."}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def redirect_uri(self, provider: str) -> str:
        public_url = env_value("APPLICATION_INVENTORY_SERVICE_PUBLIC_URL", "APPSEC_INVENTORY_SERVICE_PUBLIC_URL")
        if public_url:
            base_url = safe_public_url(public_url)
        else:
            proto = self.headers.get("X-Forwarded-Proto") or ("https" if secure_cookie() else "http")
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or f"{self.server.server_name}:{self.server.server_port}"
            base_url = safe_request_base_url(proto, host)
        return f"{base_url}/api/auth/{provider}/callback"




























def default_ui_config(reports_root: Path) -> dict[str, Any]:
    github_enterprise_oauth_config = GitHubEnterpriseOAuthConfig.from_env()
    google_oauth_config = GoogleOAuthConfig.from_env()
    test_login_config = TestLoginConfig.from_env()
    github_repositories = parse_source_target_filter_values(
        [env_value("APPLICATION_INVENTORY_GITHUB_REPOSITORIES", "APPSEC_INVENTORY_GITHUB_REPOSITORIES")]
    )
    return {
        "defaults": {
            "provider": "azure-devops",
            "githubUrls": list(configured_github_owners()),
            "githubRepositories": [target_filter_value(item) for item in github_repositories],
            "outPrefix": DEFAULT_OUT_PREFIX,
            "applicationTypes": [],
            "applicationTypeChoices": [
                {"value": value, "label": APPLICATION_TYPE_LABELS.get(value, value.replace("_", " ").title())}
                for value in KNOWN_INVENTORY_TYPES
            ],
            "minConfidence": "medium",
            "activityMode": "contributors",
            "maxWorkers": 8,
            "sourceWorkers": DEFAULT_SOURCE_WORKERS,
            "branchWorkers": 16,
            "contentWorkers": 16,
            "maxCommitsPerRepo": 0,
            "timeout": 30,
            "branchAgeDays": 90,
            "storeCountry": "US",
            "storeCountries": ["US"],
            "storeTimeout": 15,
            "postgresEnabled": True,
            "postgresHost": env_value("APPLICATION_INVENTORY_POSTGRES_HOST", "APPSEC_INVENTORY_POSTGRES_HOST") or DEFAULT_POSTGRES_HOST,
            "postgresPort": DEFAULT_POSTGRES_PORT,
            "postgresDatabase": DEFAULT_POSTGRES_DATABASE,
            "postgresUser": DEFAULT_POSTGRES_USER,
            "postgresSchema": env_value("APPLICATION_INVENTORY_POSTGRES_SCHEMA", "APPSEC_INVENTORY_POSTGRES_SCHEMA") or DEFAULT_POSTGRES_SCHEMA,
            "postgresTable": DEFAULT_POSTGRES_TABLE,
        },
        "auth": {
            "githubEnterpriseLoginEnabled": github_enterprise_oauth_config.enabled,
            "googleLoginEnabled": google_oauth_config.enabled,
            "testLoginEnabled": test_login_config.enabled,
            "authProviders": [
                {
                    "id": "github-enterprise",
                    "label": "GitHub Enterprise",
                    "enabled": github_enterprise_oauth_config.enabled,
                    "startUrl": "/api/auth/github-enterprise/start",
                },
                {
                    "id": "google",
                    "label": "Google SSO",
                    "enabled": google_oauth_config.enabled,
                    "startUrl": "/api/auth/google/start",
                },
                {
                    "id": "test",
                    "label": "Test User",
                    "enabled": test_login_config.enabled,
                    "startUrl": "/api/auth/test/start",
                },
            ],
            "secureStorage": True,
        },
        "reportsRoot": str(reports_root),
    }


@lru_cache(maxsize=32)
def static_content(name: str) -> bytes:
    return files("appsec_scan_router").joinpath("ui_static").joinpath(name).read_bytes()


def report_content_type(path: Path) -> str:
    return {
        ".csv": "text/csv",
        ".json": "application/json",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".txt": "text/plain",
    }.get(path.suffix.lower(), "application/octet-stream")


def new_scan_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def env_value(*names: str) -> str:
    for name in names:
        value = clean_text(os.getenv(name))
        if value:
            return value
    return ""


def env_flag(*names: str) -> bool:
    return env_value(*names).lower() in {"1", "true", "yes", "on"}


def max_json_body_bytes() -> int:
    return positive_int(
        env_value("APPLICATION_INVENTORY_SERVICE_MAX_JSON_BODY_BYTES", "APPSEC_INVENTORY_SERVICE_MAX_JSON_BODY_BYTES"),
        DEFAULT_MAX_JSON_BODY_BYTES,
    )






def security_headers() -> dict[str, str]:
    headers = dict(SECURITY_HEADER_VALUES)
    if secure_cookie():
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers


def attachment_header(filename: str) -> str:
    clean_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(filename).name).strip("._")
    return f'attachment; filename="{clean_name or "download"}"'


def safe_public_url(value: str) -> str:
    parsed = urlparse(clean_text(value).rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Public URL must be an HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("Public URL must not contain credentials.")
    if parsed.scheme == "http" and secure_cookie():
        raise ValueError("Public URL must use HTTPS when secure cookies are enabled.")
    if not HOST_HEADER_RE.match(parsed.netloc):
        raise ValueError("Public URL host is invalid.")
    return f"{parsed.scheme}://{parsed.netloc}"


def safe_request_base_url(proto: str, host: str) -> str:
    clean_proto = clean_text(proto).split(",", 1)[0].lower()
    clean_host = clean_text(host).split(",", 1)[0]
    if clean_proto not in {"http", "https"}:
        clean_proto = "https" if secure_cookie() else "http"
    if not clean_host or any(character in clean_host for character in "\r\n/@") or not HOST_HEADER_RE.match(clean_host):
        raise ValueError("Request host is invalid.")
    return f"{clean_proto}://{clean_host}"


def database_export_error(error: Exception) -> str:
    text = clean_text(error)
    if not text:
        return "Database export failed."
    if "password" in text.lower() or "postgresql://" in text.lower():
        return "Database export failed. Check the configured database credentials."
    return text


def first_query_value(params: dict[str, list[str]], name: str) -> str:
    values = params.get(name, [])
    return values[0] if values else ""


def owner_scope(record: SessionRecord | None) -> str:
    return record.user.id if record else "anonymous"


def owner_login(record: SessionRecord | None) -> str:
    return record.user.login if record else "anonymous"


def run_owner_id(run: ScanRun) -> str:
    return str(run.config.get("ownerUserId") or "anonymous")


def scan_log_extra(run: ScanRun, event_type: str, status: str = "") -> dict[str, Any]:
    return {
        "event_type": event_type,
        "scan_id": run.id,
        "owner_user_id": run.config.get("ownerUserId", ""),
        "owner_user_login": run.config.get("ownerUserLogin", ""),
        "provider": run.config.get("provider", ""),
        "organization": run.config.get("orgDisplay") or run.config.get("org", ""),
        "status": status,
    }






def clean_choice(value: Any, allowed: set[str], default: str) -> str:
    text = clean_text(value)
    return text if text in allowed else default








def positive_int(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def integer_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default




def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def secure_cookie() -> bool:
    return env_flag("APPLICATION_INVENTORY_SERVICE_COOKIE_SECURE", "APPSEC_INVENTORY_SERVICE_COOKIE_SECURE")


def serve(host: str, port: int, reports_dir: Path) -> None:
    manager = ScanManager(
        reports_root=reports_dir.resolve(),
        normalize_config=normalize_scan_config,
        build_command=build_scan_command,
        build_environment=scan_environment,
        redact_command=redact_command,
        max_concurrent_scans=positive_int(
            env_value(
                "APPLICATION_INVENTORY_SERVICE_MAX_CONCURRENT_SCANS",
                "APPSEC_INVENTORY_SERVICE_MAX_CONCURRENT_SCANS",
            ),
            2,
        ),
    )
    auth = AuthManager(manager.reports_root)
    scheduler = ScanScheduler(manager, auth_state_dir(manager.reports_root))
    observability_schema = env_value(
        "APPLICATION_INVENTORY_OBSERVABILITY_SCHEMA",
        "APPSEC_INVENTORY_OBSERVABILITY_SCHEMA",
        "APPLICATION_INVENTORY_POSTGRES_SCHEMA",
        "APPSEC_INVENTORY_POSTGRES_SCHEMA",
    ) or DEFAULT_POSTGRES_SCHEMA
    configured_observability_dsn = observability_dsn()
    configure_logging(
        env_flag("APPLICATION_INVENTORY_SERVICE_VERBOSE", "APPSEC_INVENTORY_SERVICE_VERBOSE"),
        dsn=configured_observability_dsn,
        schema=observability_schema,
        source="ui",
    )
    handler = type(
        "ConfiguredApplicationInventoryServiceHandler",
        (ApplicationInventoryServiceHandler,),
        {
            "manager": manager,
            "scheduler": scheduler,
            "auth": auth,
            "observability_dsn": configured_observability_dsn,
            "observability_schema": observability_schema,
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    scheduler.start()
    LOGGER.info("UI service started host=%s port=%s", host, port, extra={"event_type": "service.started"})
    log_github_app_context(configured_github_app_id(), configured_github_installation_id())
    print(f"Application Inventory Service UI listening on http://{host}:{port}")
    print(f"Reports root: {manager.reports_root}")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("Application Inventory Service UI stopped.")
    finally:
        server.server_close()
        scheduler.close()
        manager.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="application-inventory-service-ui",
        description="Run the Application Inventory Service web UI.",
    )
    parser.add_argument(
        "--host",
        default=env_value("APPLICATION_INVENTORY_SERVICE_UI_HOST", "APPSEC_INVENTORY_SERVICE_UI_HOST")
        or os.getenv("APPSEC_SCAN_ROUTER_UI_HOST", DEFAULT_UI_HOST),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(
            env_value("APPLICATION_INVENTORY_SERVICE_UI_PORT", "APPSEC_INVENTORY_SERVICE_UI_PORT")
            or os.getenv("APPSEC_SCAN_ROUTER_UI_PORT", str(DEFAULT_UI_PORT))
        ),
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(
            env_value("APPLICATION_INVENTORY_SERVICE_REPORTS_DIR", "APPSEC_INVENTORY_SERVICE_REPORTS_DIR")
            or os.getenv("APPSEC_SCAN_ROUTER_REPORTS_DIR", "reports")
        ),
    )
    return parser.parse_args(argv)


AppSecScanRouterHandler = ApplicationInventoryServiceHandler


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.port < 1 or args.port > 65535:
        raise SystemExit("--port must be between 1 and 65535.")
    serve(args.host, args.port, args.reports_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
