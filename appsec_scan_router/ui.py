from __future__ import annotations

import argparse
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

from .auth import AuthManager, GitHubOAuthConfig, SessionRecord, expired_session_cookie, session_cookie
from .constants import (
    APPLICATION_TYPE_LABELS,
    DEFAULT_OUT_PREFIX,
    DEFAULT_POSTGRES_DATABASE,
    DEFAULT_POSTGRES_PASSWORD,
    DEFAULT_POSTGRES_PORT,
    DEFAULT_POSTGRES_TABLE,
    DEFAULT_POSTGRES_USER,
    KNOWN_INVENTORY_TYPES,
)
from .scanner import normalize_application_types, store_lookup_allowed


DEFAULT_UI_HOST = "127.0.0.1"
DEFAULT_UI_PORT = 48731
MAX_LOG_LINES = 5000
REPORT_EXTENSIONS = frozenset({".csv", ".json", ".xlsx", ".txt"})
SCAN_STATUSES_DONE = frozenset({"succeeded", "failed", "stopped"})
BRANCH_PROGRESS_PATTERN = re.compile(r"Progress: (?P<branches>\d+)/(?P<branch_total>\d+) resolved branches scanned")
REPO_PROGRESS_PATTERN = re.compile(
    r"Progress: (?P<repos>\d+)/(?P<repo_total>\d+) repositories prepared; "
    r"(?P<branches>\d+)/(?P<branch_total>\d+) resolved branches scanned"
)
TARGET_COUNT_PATTERN = re.compile(r"Scanning resolved default or fallback branches for (?P<repo_total>\d+) repositories")
SCAN_PROGRESS_PATTERN = re.compile(r"SCAN_PROGRESS (?P<payload>\{.*\})")


@dataclass
class ScanRun:
    id: str
    config: dict[str, Any]
    command: tuple[str, ...]
    display_command: tuple[str, ...]
    reports_dir: Path
    status: str = "queued"
    started_at: str = ""
    ended_at: str = ""
    exit_code: int | None = None
    stop_requested: bool = False
    process: subprocess.Popen[str] | None = None
    logs: list[str] = field(default_factory=list)
    listeners: list[queue.Queue[dict[str, Any] | None]] = field(default_factory=list)
    lock: threading.RLock = field(default_factory=threading.RLock)

    def append_log(self, line: str) -> None:
        clean_line = line.rstrip("\n")
        if not clean_line:
            return
        with self.lock:
            self.logs.append(clean_line)
            if len(self.logs) > MAX_LOG_LINES:
                self.logs = self.logs[-MAX_LOG_LINES:]
        self.publish("log", {"line": clean_line})

    def set_status(self, status: str, exit_code: int | None = None) -> None:
        with self.lock:
            self.status = status
            self.exit_code = exit_code
            if status == "running" and not self.started_at:
                self.started_at = utc_now()
            if status in SCAN_STATUSES_DONE and not self.ended_at:
                self.ended_at = utc_now()
        self.publish("status", self.summary())

    def publish(self, event: str, data: dict[str, Any]) -> None:
        stale: list[queue.Queue[dict[str, Any] | None]] = []
        with self.lock:
            listeners = list(self.listeners)
        for listener in listeners:
            try:
                listener.put_nowait({"event": event, "data": data})
            except queue.Full:
                stale.append(listener)
        if stale:
            with self.lock:
                self.listeners = [listener for listener in self.listeners if listener not in stale]

    def add_listener(self) -> queue.Queue[dict[str, Any] | None]:
        listener: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=250)
        with self.lock:
            self.listeners.append(listener)
        return listener

    def remove_listener(self, listener: queue.Queue[dict[str, Any] | None]) -> None:
        with self.lock:
            self.listeners = [candidate for candidate in self.listeners if candidate is not listener]

    def close_listeners(self) -> None:
        with self.lock:
            listeners = list(self.listeners)
            self.listeners.clear()
        for listener in listeners:
            listener.put(None)

    def report_files(self) -> list[dict[str, Any]]:
        if not self.reports_dir.exists():
            return []
        reports: list[dict[str, Any]] = []
        for path in sorted(self.reports_dir.iterdir()):
            if not path.is_file() or path.suffix.lower() not in REPORT_EXTENSIONS:
                continue
            stat = path.stat()
            reports.append(
                {
                    "name": path.name,
                    "size": stat.st_size,
                    "updatedAt": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    "url": f"/api/scans/{self.id}/reports/{path.name}",
                }
            )
        return reports

    def summary(self) -> dict[str, Any]:
        with self.lock:
            logs_tail = self.logs[-300:]
            detected = sum(1 for line in self.logs if "DETECTED asset=" in line or "DETECTED app=" in line)
            provider = str(self.config.get("provider", "azure-devops"))
            target = str(self.config.get("repo") or self.config.get("project") or "all")
            return {
                "id": self.id,
                "status": self.status,
                "provider": provider,
                "org": str(self.config.get("org", "")),
                "target": target,
                "outPrefix": str(self.config.get("outPrefix", DEFAULT_OUT_PREFIX)),
                "applicationTypes": list(self.config.get("applicationTypes", [])),
                "ownerUserId": str(self.config.get("ownerUserId", "anonymous")),
                "ownerUserLogin": str(self.config.get("ownerUserLogin", "anonymous")),
                "postgresEnabled": bool(self.config.get("postgresEnabled")),
                "postgresTable": str(self.config.get("postgresTable", DEFAULT_POSTGRES_TABLE)),
                "startedAt": self.started_at,
                "endedAt": self.ended_at,
                "exitCode": self.exit_code,
                "detectedCount": detected,
                "progress": scan_progress(self.logs, self.started_at, self.ended_at, self.status),
                "reportsDir": str(self.reports_dir),
                "command": " ".join(self.display_command),
                "reports": self.report_files(),
                "logsTail": logs_tail,
            }


class ScanManager:
    def __init__(self, reports_root: Path) -> None:
        self.reports_root = reports_root
        self.reports_root.mkdir(parents=True, exist_ok=True)
        self.scans: dict[str, ScanRun] = {}
        self.lock = threading.RLock()

    def list_scans(self, owner_user_id: str = "") -> list[dict[str, Any]]:
        with self.lock:
            runs = list(self.scans.values())
        if owner_user_id:
            runs = [run for run in runs if run_owner_id(run) == owner_user_id]
        return [run.summary() for run in sorted(runs, key=lambda item: item.id, reverse=True)]

    def get_scan(self, scan_id: str) -> ScanRun | None:
        with self.lock:
            return self.scans.get(scan_id)

    def start_scan(self, config: dict[str, Any]) -> ScanRun:
        normalized = normalize_scan_config(config)
        scan_id = new_scan_id()
        reports_dir = self.reports_root / scan_id
        reports_dir.mkdir(parents=True, exist_ok=False)
        command = tuple(build_scan_command(normalized, reports_dir))
        display_command = tuple(redact_command(command))
        run = ScanRun(
            id=scan_id,
            config=normalized,
            command=command,
            display_command=display_command,
            reports_dir=reports_dir,
        )
        with self.lock:
            self.scans[scan_id] = run
        thread = threading.Thread(target=self._run_scan, args=(run,), name=f"scan-{scan_id}", daemon=True)
        thread.start()
        return run

    def stop_scan(self, scan_id: str) -> ScanRun | None:
        run = self.get_scan(scan_id)
        if not run:
            return None
        with run.lock:
            process = run.process
            running = run.status == "running"
            run.stop_requested = True
        if process and running and process.poll() is None:
            run.append_log("Stop requested from UI.")
            process.terminate()
        return run

    def _run_scan(self, run: ScanRun) -> None:
        env = scan_environment(run.config)
        run.set_status("running")
        run.append_log(f"Command: {' '.join(run.display_command)}")
        try:
            process = subprocess.Popen(
                run.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
            with run.lock:
                run.process = process
            if process.stdout:
                for line in process.stdout:
                    run.append_log(line)
            exit_code = process.wait()
        except FileNotFoundError as exc:
            run.append_log(str(exc))
            run.set_status("failed", 127)
            run.close_listeners()
            return
        except Exception as exc:
            run.append_log(str(exc))
            run.set_status("failed", 1)
            run.close_listeners()
            return

        if run.stop_requested:
            run.set_status("stopped", exit_code)
        elif exit_code == 0:
            run.set_status("succeeded", exit_code)
        else:
            run.set_status("failed", exit_code)
        run.close_listeners()


class AppSecScanRouterHandler(BaseHTTPRequestHandler):
    manager: ScanManager
    auth: AuthManager

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
            self.send_json({"status": "ok"})
            return
        if path == "/api/config":
            self.send_json(default_ui_config(self.manager.reports_root))
            return
        if path == "/api/session":
            self.send_json({"session": self.auth.status(self.current_session())})
            return
        if path == "/api/auth/github/start":
            self.handle_github_auth_start()
            return
        if path == "/api/auth/github/callback":
            self.handle_github_auth_callback(parsed.query)
            return
        if path == "/api/scans":
            self.send_json({"scans": self.manager.list_scans(owner_scope(self.current_session()))})
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
        if path == "/api/auth/logout":
            self.handle_logout()
            return
        if path == "/api/credentials/delete":
            self.handle_delete_credential()
            return
        if path.startswith("/api/scans/") and path.endswith("/stop"):
            scan_id = path.removeprefix("/api/scans/").removesuffix("/stop").strip("/")
            run = self.manager.get_scan(scan_id)
            if not run:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if run_owner_id(run) != owner_scope(self.current_session()):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            run = self.manager.stop_scan(scan_id)
            self.send_json({"scan": run.summary()})
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def handle_static(self, path: str) -> None:
        name = Path(unquote(path.removeprefix("/static/"))).name
        content_type = {
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
        }.get(Path(name).suffix, "application/octet-stream")
        self.send_static(name, content_type)

    def handle_scan_get(self, path: str) -> None:
        parts = [part for part in path.split("/") if part]
        if len(parts) < 3:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        scan_id = parts[2]
        run = self.manager.get_scan(scan_id)
        if not run:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if run_owner_id(run) != owner_scope(self.current_session()):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if len(parts) == 3:
            self.send_json({"scan": run.summary()})
            return
        if len(parts) == 4 and parts[3] == "logs":
            self.send_json({"logs": run.logs})
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
            if payload.get("saveToken") and not self.valid_csrf(record):
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

    def handle_github_auth_start(self) -> None:
        try:
            self.redirect(self.auth.oauth.authorization_url(self.redirect_uri()))
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_github_auth_callback(self, query: str) -> None:
        params = parse_qs(query)
        code = clean_text(first_query_value(params, "code"))
        state = clean_text(first_query_value(params, "state"))
        if not code or not state:
            self.redirect("/?auth=failed")
            return
        try:
            user = self.auth.oauth.complete(code, state, self.redirect_uri())
            record = self.auth.create_session(user)
        except ValueError:
            self.redirect("/?auth=failed")
            return
        self.redirect("/?auth=success", session_cookie(record.id, secure_cookie()))

    def handle_logout(self) -> None:
        record = self.current_session()
        if record and not self.valid_csrf(record):
            return
        if record:
            self.auth.logout(record.id)
        self.send_json({"session": self.auth.status(None)}, headers={"Set-Cookie": expired_session_cookie()})

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

    def send_static(self, name: str, content_type: str) -> None:
        try:
            resource = files("appsec_scan_router").joinpath("ui_static").joinpath(name)
            content = resource.read_bytes()
        except FileNotFoundError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

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
        content = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", report_content_type(path))
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

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
                item = listener.get(timeout=20)
                if item is None:
                    self.write_event("done", run.summary())
                    return
                self.write_event(item["event"], item["data"])
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            return
        finally:
            run.remove_listener(listener)

    def write_event(self, event: str, data: dict[str, Any]) -> None:
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n".encode("utf-8")
        self.wfile.write(payload)
        self.wfile.flush()

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        body = self.rfile.read(length)
        try:
            data = json.loads(body.decode("utf-8"))
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
        content = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def redirect(self, location: str, cookie: str = "") -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def current_session(self) -> SessionRecord | None:
        return self.auth.session(self.headers.get("Cookie", ""))

    def valid_csrf(self, record: SessionRecord | None) -> bool:
        if not record:
            self.send_json({"error": "Sign in with GitHub first."}, HTTPStatus.UNAUTHORIZED)
            return False
        if self.headers.get("X-CSRF-Token", "") != record.csrf_token:
            self.send_json({"error": "Session validation failed. Refresh and try again."}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def redirect_uri(self) -> str:
        proto = self.headers.get("X-Forwarded-Proto") or ("https" if secure_cookie() else "http")
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or f"{self.server.server_name}:{self.server.server_port}"
        return f"{proto}://{host}/api/auth/github/callback"


def normalize_scan_config(config: dict[str, Any]) -> dict[str, Any]:
    provider = clean_choice(config.get("provider"), {"azure-devops", "github-enterprise"}, "azure-devops")
    org = clean_text(config.get("org"))
    if not org:
        raise ValueError("Organization is required.")
    base_url = clean_text(config.get("baseUrl"))
    if provider == "github-enterprise" and not base_url:
        raise ValueError("GitHub Enterprise API URL is required.")
    application_types = list(normalize_ui_application_types(config.get("applicationTypes")))
    normalized = {
        "provider": provider,
        "org": org,
        "project": clean_text(config.get("project")),
        "repo": clean_text(config.get("repo")),
        "baseUrl": base_url,
        "token": clean_text(config.get("token")),
        "outPrefix": DEFAULT_OUT_PREFIX,
        "applicationTypes": application_types,
        "ownerUserId": clean_text(config.get("ownerUserId")) or "anonymous",
        "ownerUserLogin": clean_text(config.get("ownerUserLogin")) or "anonymous",
        "saveToken": bool(config.get("saveToken")),
        "postgresEnabled": bool(config.get("postgresEnabled", True)),
        "postgresDsn": clean_text(config.get("postgresDsn") or os.getenv("APPSEC_INVENTORY_POSTGRES_DSN")),
        "postgresHost": clean_text(config.get("postgresHost") or "host.docker.internal"),
        "postgresPort": positive_int(config.get("postgresPort"), DEFAULT_POSTGRES_PORT),
        "postgresDatabase": clean_text(config.get("postgresDatabase") or DEFAULT_POSTGRES_DATABASE),
        "postgresUser": clean_text(config.get("postgresUser") or DEFAULT_POSTGRES_USER),
        "postgresPassword": clean_text(config.get("postgresPassword") or os.getenv("APPSEC_INVENTORY_POSTGRES_PASSWORD") or DEFAULT_POSTGRES_PASSWORD),
        "postgresTable": clean_text(config.get("postgresTable") or DEFAULT_POSTGRES_TABLE),
        "minConfidence": clean_choice(config.get("minConfidence"), {"low", "medium", "high"}, "low"),
        "activityMode": clean_choice(config.get("activityMode"), {"contributors", "latest"}, "contributors"),
        "maxWorkers": positive_int(config.get("maxWorkers"), 8),
        "branchWorkers": positive_int(config.get("branchWorkers"), 16),
        "contentWorkers": positive_int(config.get("contentWorkers"), 16),
        "maxCommitsPerRepo": nonnegative_int(config.get("maxCommitsPerRepo"), 0),
        "timeout": positive_int(config.get("timeout"), 30),
        "branchAgeDays": positive_int(config.get("branchAgeDays"), 90),
        "storeLookup": bool(config.get("storeLookup")) and store_lookup_allowed(application_types),
        "storeCountry": clean_text(config.get("storeCountry") or "US").upper()[:2],
        "storeTimeout": positive_int(config.get("storeTimeout"), 15),
        "verbose": bool(config.get("verbose")),
    }
    if normalized["project"] and normalized["repo"] and normalized["project"] != normalized["repo"]:
        raise ValueError("Project and repository cannot be different values.")
    if normalized["postgresEnabled"] and not normalized["postgresDsn"]:
        normalized["postgresDsn"] = postgres_dsn_from_config(normalized)
    return normalized


def build_scan_command(config: dict[str, Any], reports_dir: Path) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "appsec_scan_router",
        "--provider",
        config["provider"],
        "--org",
        config["org"],
        "--out-dir",
        str(reports_dir),
        "--out-prefix",
        config["outPrefix"],
        "--min-confidence",
        config["minConfidence"],
        "--activity-mode",
        config["activityMode"],
        "--max-workers",
        str(config["maxWorkers"]),
        "--branch-workers",
        str(config["branchWorkers"]),
        "--content-workers",
        str(config["contentWorkers"]),
        "--max-commits-per-repo",
        str(config["maxCommitsPerRepo"]),
        "--timeout",
        str(config["timeout"]),
        "--branch-age-days",
        str(config["branchAgeDays"]),
        "--owner-user-id",
        config["ownerUserId"],
        "--owner-user-login",
        config["ownerUserLogin"],
        "--store-country",
        config["storeCountry"],
        "--store-timeout",
        str(config["storeTimeout"]),
    ]
    for application_type in config["applicationTypes"]:
        command.extend(["--application-type", application_type])
    if config["postgresEnabled"]:
        command.extend(["--postgres-table", config["postgresTable"]])
    if config["provider"] == "github-enterprise":
        command.extend(["--base-url", config["baseUrl"]])
        target = config["repo"] or config["project"]
        if target:
            command.extend(["--repo", target])
    elif config["project"]:
        command.extend(["--project", config["project"]])
    if config["storeLookup"]:
        command.append("--store-lookup")
    if config["verbose"]:
        command.append("--verbose")
    return command


def redact_command(command: tuple[str, ...] | list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for index, part in enumerate(command):
        if skip_next:
            redacted.append("[redacted]")
            skip_next = False
            continue
        redacted.append(part)
        if part in {"--pat", "--postgres-dsn"} and index + 1 < len(command):
            skip_next = True
    return redacted


def scan_environment(config: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    token = clean_text(config.get("token"))
    if token and config.get("provider") == "github-enterprise":
        env["GITHUB_TOKEN"] = token
    elif token:
        env["ADO_PAT"] = token
    postgres_dsn = clean_text(config.get("postgresDsn"))
    if postgres_dsn:
        env["APPSEC_INVENTORY_POSTGRES_DSN"] = postgres_dsn
        env["APPSEC_INVENTORY_POSTGRES_TABLE"] = clean_text(config.get("postgresTable") or DEFAULT_POSTGRES_TABLE)
    env["APPSEC_INVENTORY_OWNER_USER_ID"] = clean_text(config.get("ownerUserId") or "anonymous")
    env["APPSEC_INVENTORY_OWNER_USER_LOGIN"] = clean_text(config.get("ownerUserLogin") or "anonymous")
    return env


def scan_progress(
    logs: list[str],
    started_at: str,
    ended_at: str,
    status: str,
) -> dict[str, Any]:
    repo_done = 0
    repo_total = 0
    branch_done = 0
    branch_total = 0
    for line in logs:
        progress_match = SCAN_PROGRESS_PATTERN.search(line)
        if progress_match:
            try:
                payload = json.loads(progress_match.group("payload"))
            except ValueError:
                payload = {}
            repo_done = nonnegative_int(payload.get("repositoriesPrepared"), repo_done)
            repo_total = nonnegative_int(payload.get("repositoriesTotal"), repo_total)
            branch_done = nonnegative_int(payload.get("branchesScanned"), branch_done)
            branch_total = nonnegative_int(payload.get("branchesTotal"), branch_total)
            continue
        target_match = TARGET_COUNT_PATTERN.search(line)
        if target_match:
            repo_total = int(target_match.group("repo_total"))
        repo_match = REPO_PROGRESS_PATTERN.search(line)
        if repo_match:
            repo_done = int(repo_match.group("repos"))
            repo_total = int(repo_match.group("repo_total"))
            branch_done = int(repo_match.group("branches"))
            branch_total = int(repo_match.group("branch_total"))
            continue
        branch_match = BRANCH_PROGRESS_PATTERN.search(line)
        if branch_match:
            branch_done = int(branch_match.group("branches"))
            branch_total = int(branch_match.group("branch_total"))

    if status in SCAN_STATUSES_DONE:
        return {
            "percent": 100 if status == "succeeded" else progress_percent(repo_done, repo_total, branch_done, branch_total),
            "etaSeconds": 0,
            "repositoriesPrepared": repo_done,
            "repositoriesTotal": repo_total,
            "branchesScanned": branch_done,
            "branchesTotal": branch_total,
        }

    percent = progress_percent(repo_done, repo_total, branch_done, branch_total)
    return {
        "percent": percent,
        "etaSeconds": estimated_remaining_seconds(started_at, percent),
        "repositoriesPrepared": repo_done,
        "repositoriesTotal": repo_total,
        "branchesScanned": branch_done,
        "branchesTotal": branch_total,
    }


def progress_percent(repo_done: int, repo_total: int, branch_done: int, branch_total: int) -> int:
    if repo_total > 0:
        repo_ratio = bounded_ratio(repo_done, repo_total)
        branch_ratio = bounded_ratio(branch_done, branch_total) if branch_total > 0 else 0
        if repo_done >= repo_total:
            return min(99, round(40 + (branch_ratio * 59)))
        return min(99, round((repo_ratio * 40) + (branch_ratio * 50)))
    if branch_total > 0:
        return min(99, round(bounded_ratio(branch_done, branch_total) * 99))
    return 0


def bounded_ratio(done: int, total: int) -> float:
    if total <= 0:
        return 0
    return max(0, min(1, done / total))


def estimated_remaining_seconds(started_at: str, percent: int) -> int | None:
    started = parse_iso_datetime(started_at)
    if started is None:
        return None
    elapsed = max(1, (datetime.now(timezone.utc) - started).total_seconds())
    if percent <= 0 or percent >= 99:
        return None
    rate = percent / elapsed
    if rate <= 0:
        return None
    return max(1, round((99 - percent) / rate))


def parse_iso_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def default_ui_config(reports_root: Path) -> dict[str, Any]:
    oauth_config = GitHubOAuthConfig.from_env()
    return {
        "defaults": {
            "provider": "azure-devops",
            "outPrefix": DEFAULT_OUT_PREFIX,
            "applicationTypes": [],
            "applicationTypeChoices": [
                {"value": value, "label": APPLICATION_TYPE_LABELS.get(value, value.replace("_", " ").title())}
                for value in KNOWN_INVENTORY_TYPES
            ],
            "minConfidence": "medium",
            "activityMode": "latest",
            "maxWorkers": 8,
            "branchWorkers": 16,
            "contentWorkers": 16,
            "maxCommitsPerRepo": 0,
            "timeout": 30,
            "branchAgeDays": 90,
            "storeCountry": "US",
            "storeTimeout": 15,
            "postgresEnabled": True,
            "postgresHost": os.getenv("APPSEC_INVENTORY_POSTGRES_HOST", "host.docker.internal"),
            "postgresPort": DEFAULT_POSTGRES_PORT,
            "postgresDatabase": DEFAULT_POSTGRES_DATABASE,
            "postgresUser": DEFAULT_POSTGRES_USER,
            "postgresTable": DEFAULT_POSTGRES_TABLE,
        },
        "auth": {
            "githubLoginEnabled": oauth_config.enabled,
            "secureStorage": True,
        },
        "reportsRoot": str(reports_root),
    }


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


def first_query_value(params: dict[str, list[str]], name: str) -> str:
    values = params.get(name, [])
    return values[0] if values else ""


def owner_scope(record: SessionRecord | None) -> str:
    return record.user.id if record else "anonymous"


def owner_login(record: SessionRecord | None) -> str:
    return record.user.login if record else "anonymous"


def run_owner_id(run: ScanRun) -> str:
    return str(run.config.get("ownerUserId") or "anonymous")


def clean_choice(value: Any, allowed: set[str], default: str) -> str:
    text = clean_text(value)
    return text if text in allowed else default


def safe_prefix(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-")
    return text or DEFAULT_OUT_PREFIX


def normalize_ui_application_types(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raw_values = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        raw_values = [str(part).strip() for part in value]
    else:
        raw_values = []
    return normalize_application_types(raw_values)


def postgres_dsn_from_config(config: dict[str, Any]) -> str:
    host = clean_text(config.get("postgresHost"))
    database = clean_text(config.get("postgresDatabase"))
    user = clean_text(config.get("postgresUser"))
    password = clean_text(config.get("postgresPassword"))
    port = positive_int(config.get("postgresPort"), DEFAULT_POSTGRES_PORT)
    if not host:
        raise ValueError("PostgreSQL host is required when database sync is enabled.")
    if not database:
        raise ValueError("PostgreSQL database is required when database sync is enabled.")
    if not user:
        raise ValueError("PostgreSQL user is required when database sync is enabled.")
    auth = quote(user, safe="")
    if password:
        auth = f"{auth}:{quote(password, safe='')}"
    return f"postgresql://{auth}@{host}:{port}/{quote(database, safe='')}"


def positive_int(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def nonnegative_int(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number >= 0 else default


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def secure_cookie() -> bool:
    return clean_text(os.getenv("APPSEC_INVENTORY_SERVICE_COOKIE_SECURE")).lower() in {"1", "true", "yes"}


def serve(host: str, port: int, reports_dir: Path) -> None:
    manager = ScanManager(reports_dir.resolve())
    auth = AuthManager(manager.reports_root)
    handler = type("ConfiguredAppSecScanRouterHandler", (AppSecScanRouterHandler,), {"manager": manager, "auth": auth})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"AppSec Inventory Service UI listening on http://{host}:{port}")
    print(f"Reports root: {manager.reports_root}")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("AppSec Inventory Service UI stopped.")
    finally:
        server.server_close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="appsec-inventory-service-ui",
        description="Run the AppSec Inventory Service web UI.",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("APPSEC_INVENTORY_SERVICE_UI_HOST")
        or os.getenv("APPSEC_SCAN_ROUTER_UI_HOST", DEFAULT_UI_HOST),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(
            os.getenv("APPSEC_INVENTORY_SERVICE_UI_PORT")
            or os.getenv("APPSEC_SCAN_ROUTER_UI_PORT", str(DEFAULT_UI_PORT))
        ),
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(
            os.getenv("APPSEC_INVENTORY_SERVICE_REPORTS_DIR")
            or os.getenv("APPSEC_SCAN_ROUTER_REPORTS_DIR", "reports")
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.port < 1 or args.port > 65535:
        raise SystemExit("--port must be between 1 and 65535.")
    serve(args.host, args.port, args.reports_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
