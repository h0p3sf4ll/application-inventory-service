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
from urllib.parse import unquote, urlparse


DEFAULT_UI_HOST = "127.0.0.1"
DEFAULT_UI_PORT = 48731
MAX_LOG_LINES = 5000
REPORT_EXTENSIONS = frozenset({".csv", ".json", ".xlsx"})
SCAN_STATUSES_DONE = frozenset({"succeeded", "failed", "stopped"})


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
            detected = sum(1 for line in self.logs if "DETECTED app=" in line)
            provider = str(self.config.get("provider", "azure-devops"))
            target = str(self.config.get("repo") or self.config.get("project") or "all")
            return {
                "id": self.id,
                "status": self.status,
                "provider": provider,
                "org": str(self.config.get("org", "")),
                "target": target,
                "outPrefix": str(self.config.get("outPrefix", "appsec_scan_router")),
                "startedAt": self.started_at,
                "endedAt": self.ended_at,
                "exitCode": self.exit_code,
                "detectedCount": detected,
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

    def list_scans(self) -> list[dict[str, Any]]:
        with self.lock:
            runs = list(self.scans.values())
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

    def do_GET(self) -> None:
        path = urlparse(self.path).path
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
        if path == "/api/scans":
            self.send_json({"scans": self.manager.list_scans()})
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
        if path.startswith("/api/scans/") and path.endswith("/stop"):
            scan_id = path.removeprefix("/api/scans/").removesuffix("/stop").strip("/")
            run = self.manager.stop_scan(scan_id)
            if not run:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
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
            run = self.manager.start_scan(payload)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.send_json({"scan": run.summary()}, HTTPStatus.CREATED)

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

    def send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        content = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        return


def normalize_scan_config(config: dict[str, Any]) -> dict[str, Any]:
    provider = clean_choice(config.get("provider"), {"azure-devops", "github-enterprise"}, "azure-devops")
    org = clean_text(config.get("org"))
    if not org:
        raise ValueError("Organization is required.")
    base_url = clean_text(config.get("baseUrl"))
    if provider == "github-enterprise" and not base_url:
        raise ValueError("GitHub Enterprise API URL is required.")
    normalized = {
        "provider": provider,
        "org": org,
        "project": clean_text(config.get("project")),
        "repo": clean_text(config.get("repo")),
        "baseUrl": base_url,
        "token": clean_text(config.get("token")),
        "outPrefix": safe_prefix(clean_text(config.get("outPrefix")) or "appsec_scan_router"),
        "minConfidence": clean_choice(config.get("minConfidence"), {"low", "medium", "high"}, "low"),
        "activityMode": clean_choice(config.get("activityMode"), {"contributors", "latest"}, "contributors"),
        "maxWorkers": positive_int(config.get("maxWorkers"), 8),
        "branchWorkers": positive_int(config.get("branchWorkers"), 16),
        "contentWorkers": positive_int(config.get("contentWorkers"), 16),
        "maxCommitsPerRepo": nonnegative_int(config.get("maxCommitsPerRepo"), 0),
        "timeout": positive_int(config.get("timeout"), 30),
        "branchAgeDays": positive_int(config.get("branchAgeDays"), 90),
        "storeLookup": bool(config.get("storeLookup")),
        "storeCountry": clean_text(config.get("storeCountry") or "US").upper()[:2],
        "storeTimeout": positive_int(config.get("storeTimeout"), 15),
        "verbose": bool(config.get("verbose")),
    }
    if normalized["project"] and normalized["repo"] and normalized["project"] != normalized["repo"]:
        raise ValueError("Project and repository cannot be different values.")
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
        "--store-country",
        config["storeCountry"],
        "--store-timeout",
        str(config["storeTimeout"]),
    ]
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
        if part == "--pat" and index + 1 < len(command):
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
    return env


def default_ui_config(reports_root: Path) -> dict[str, Any]:
    return {
        "defaults": {
            "provider": "azure-devops",
            "outPrefix": "appsec_scan_router",
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
        },
        "reportsRoot": str(reports_root),
    }


def report_content_type(path: Path) -> str:
    return {
        ".csv": "text/csv",
        ".json": "application/json",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }.get(path.suffix.lower(), "application/octet-stream")


def new_scan_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def clean_choice(value: Any, allowed: set[str], default: str) -> str:
    text = clean_text(value)
    return text if text in allowed else default


def safe_prefix(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-")
    return text or "appsec_scan_router"


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


def serve(host: str, port: int, reports_dir: Path) -> None:
    manager = ScanManager(reports_dir.resolve())
    handler = type("ConfiguredAppSecScanRouterHandler", (AppSecScanRouterHandler,), {"manager": manager})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"AppSec Scan Router UI listening on http://{host}:{port}")
    print(f"Reports root: {manager.reports_root}")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("AppSec Scan Router UI stopped.")
    finally:
        server.server_close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="appsec-scan-router-ui",
        description="Run the AppSec Scan Router web UI.",
    )
    parser.add_argument("--host", default=os.getenv("APPSEC_SCAN_ROUTER_UI_HOST", DEFAULT_UI_HOST))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("APPSEC_SCAN_ROUTER_UI_PORT", str(DEFAULT_UI_PORT))),
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(os.getenv("APPSEC_SCAN_ROUTER_REPORTS_DIR", "reports")),
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
