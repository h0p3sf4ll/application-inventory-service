from __future__ import annotations

import json
import logging
import os
import queue
import signal
import subprocess
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import DEFAULT_OUT_PREFIX, DEFAULT_POSTGRES_SCHEMA, DEFAULT_POSTGRES_TABLE
from .github import configured_github_app_id, configured_github_installation_id
from .observability import log_github_app_context


LOGGER = logging.getLogger("appsec_scan_router")
MAX_LOG_LINES = 5000
REPORT_EXTENSIONS = frozenset({".csv", ".json", ".xlsx", ".txt"})
SCAN_STATUSES_DONE = frozenset({"succeeded", "failed", "stopped"})
SCAN_STATUSES_ACTIVE = frozenset({"queued", "running", "paused"})


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
    logs: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_LOG_LINES))
    log_tail: deque[str] = field(default_factory=lambda: deque(maxlen=300))
    listeners: list[queue.Queue[dict[str, Any] | None]] = field(default_factory=list)
    lock: threading.RLock = field(default_factory=threading.RLock)
    detected_count: int = 0
    progress: dict[str, int] = field(
        default_factory=lambda: {
            "repositoriesPrepared": 0,
            "repositoriesTotal": 0,
            "branchesScanned": 0,
            "branchesTotal": 0,
        }
    )
    started_monotonic: float = 0.0
    paused_monotonic: float = 0.0
    paused_seconds: float = 0.0
    _report_cache: list[dict[str, Any]] = field(default_factory=list)
    _report_cache_at: float = 0.0

    def append_log(self, line: str) -> None:
        clean_line = line.rstrip("\n")
        if not clean_line:
            return
        with self.lock:
            self.logs.append(clean_line)
            self.log_tail.append(clean_line)
            self._record_log_metrics(clean_line)
        self.publish("log", {"line": clean_line})

    def set_status(self, status: str, exit_code: int | None = None) -> None:
        now = time.monotonic()
        with self.lock:
            previous = self.status
            self.status = status
            self.exit_code = exit_code
            if status == "running" and not self.started_at:
                self.started_at = utc_now()
                self.started_monotonic = now
            if status == "paused" and previous == "running":
                self.paused_monotonic = now
            if previous == "paused" and status != "paused" and self.paused_monotonic:
                self.paused_seconds += now - self.paused_monotonic
                self.paused_monotonic = 0.0
            if status in SCAN_STATUSES_DONE and not self.ended_at:
                self.ended_at = utc_now()
        self.publish("status", self.summary())

    def publish(self, event: str, data: dict[str, Any]) -> None:
        stale: list[queue.Queue[dict[str, Any] | None]] = []
        with self.lock:
            listeners = tuple(self.listeners)
        payload = {"event": event, "data": data}
        for listener in listeners:
            if listener.full():
                stale.append(listener)
                continue
            listener.put_nowait(payload)
        if stale:
            stale_ids = {id(listener) for listener in stale}
            with self.lock:
                self.listeners = [listener for listener in self.listeners if id(listener) not in stale_ids]

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
            listeners = tuple(self.listeners)
            self.listeners.clear()
        for listener in listeners:
            try:
                listener.put_nowait(None)
            except queue.Full:
                continue

    def report_files(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        with self.lock:
            if self._report_cache_at and (self.status in SCAN_STATUSES_DONE or now - self._report_cache_at < 2.0):
                return list(self._report_cache)
        reports: list[dict[str, Any]] = []
        if self.reports_dir.exists():
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
        with self.lock:
            self._report_cache = reports
            self._report_cache_at = now
        return list(reports)

    def active_seconds(self) -> int:
        with self.lock:
            if not self.started_monotonic:
                return 0
            end = time.monotonic() if self.status not in SCAN_STATUSES_DONE else self.started_monotonic + self._elapsed_seconds()
            paused = self.paused_seconds
            if self.paused_monotonic:
                paused += time.monotonic() - self.paused_monotonic
            return max(0, round(end - self.started_monotonic - paused))

    def summary(self) -> dict[str, Any]:
        reports = self.report_files()
        with self.lock:
            provider = str(self.config.get("provider", "azure-devops"))
            return {
                "id": self.id,
                "status": self.status,
                "provider": provider,
                "org": str(self.config.get("orgDisplay") or self.config.get("org", "")),
                "target": scan_target_summary(self.config),
                "outPrefix": str(self.config.get("outPrefix", DEFAULT_OUT_PREFIX)),
                "applicationTypes": list(self.config.get("applicationTypes", [])),
                "ownerUserId": str(self.config.get("ownerUserId", "anonymous")),
                "ownerUserLogin": str(self.config.get("ownerUserLogin", "anonymous")),
                "postgresEnabled": bool(self.config.get("postgresEnabled")),
                "postgresSchema": str(self.config.get("postgresSchema", DEFAULT_POSTGRES_SCHEMA)),
                "postgresTable": str(self.config.get("postgresTable", DEFAULT_POSTGRES_TABLE)),
                "startedAt": self.started_at,
                "endedAt": self.ended_at,
                "exitCode": self.exit_code,
                "detectedCount": self.detected_count,
                "progress": dict(self.progress),
                "activeSeconds": self.active_seconds(),
                "reportsDir": str(self.reports_dir),
                "command": " ".join(self.display_command),
                "reports": reports,
                "logsTail": list(self.log_tail),
            }

    def _record_log_metrics(self, line: str) -> None:
        if "DETECTED asset=" in line or "DETECTED app=" in line:
            self.detected_count += 1
        marker = "SCAN_PROGRESS "
        if marker not in line:
            return
        try:
            payload = json.loads(line.split(marker, 1)[1])
        except (ValueError, TypeError):
            return
        for key in self.progress:
            value = payload.get(key)
            if isinstance(value, int) and value >= 0:
                self.progress[key] = value

    def _elapsed_seconds(self) -> float:
        if not self.started_at or not self.ended_at:
            return max(0.0, time.monotonic() - self.started_monotonic)
        try:
            started = datetime.fromisoformat(self.started_at.replace("Z", "+00:00"))
            ended = datetime.fromisoformat(self.ended_at.replace("Z", "+00:00"))
        except ValueError:
            return max(0.0, time.monotonic() - self.started_monotonic)
        return max(0.0, (ended - started).total_seconds())


class ScanManager:
    def __init__(
        self,
        reports_root: Path,
        normalize_config: Callable[[dict[str, Any]], dict[str, Any]],
        build_command: Callable[[dict[str, Any], Path], list[str]],
        build_environment: Callable[[dict[str, Any]], dict[str, str]],
        redact_command: Callable[[tuple[str, ...] | list[str]], list[str]],
        max_concurrent_scans: int = 2,
    ) -> None:
        self.reports_root = reports_root
        self.reports_root.mkdir(parents=True, exist_ok=True)
        self.normalize_config = normalize_config
        self.build_command = build_command
        self.build_environment = build_environment
        self.redact_command = redact_command
        self.scans: dict[str, ScanRun] = {}
        self.lock = threading.RLock()
        self._slots = threading.BoundedSemaphore(max(1, max_concurrent_scans))
        self._threads: set[threading.Thread] = set()
        self._closing = False

    def list_scans(self, owner_user_id: str = "") -> list[dict[str, Any]]:
        with self.lock:
            runs = tuple(self.scans.values())
        if owner_user_id:
            runs = tuple(run for run in runs if run_owner_id(run) == owner_user_id)
        return [run.summary() for run in sorted(runs, key=lambda item: item.id, reverse=True)]

    def get_scan(self, scan_id: str) -> ScanRun | None:
        with self.lock:
            return self.scans.get(scan_id)

    def metrics(self) -> dict[str, int]:
        with self.lock:
            statuses = [run.status for run in self.scans.values()]
        return {
            "scansTotal": len(statuses),
            "scansQueued": statuses.count("queued"),
            "scansRunning": statuses.count("running"),
            "scansPaused": statuses.count("paused"),
            "scansSucceeded": statuses.count("succeeded"),
            "scansFailed": statuses.count("failed"),
            "scansStopped": statuses.count("stopped"),
        }

    def start_scan(self, config: dict[str, Any]) -> ScanRun:
        with self.lock:
            if self._closing:
                raise ValueError("The scan service is shutting down.")
        normalized = self.normalize_config(config)
        scan_id = new_scan_id()
        reports_dir = self.reports_root / scan_id
        reports_dir.mkdir(parents=True, exist_ok=False)
        command = tuple(self.build_command(normalized, reports_dir))
        run = ScanRun(
            id=scan_id,
            config=normalized,
            command=command,
            display_command=tuple(self.redact_command(command)),
            reports_dir=reports_dir,
        )
        with self.lock:
            self.scans[scan_id] = run
        LOGGER.info(
            "Scan queued scan_id=%s provider=%s",
            scan_id,
            normalized.get("provider", ""),
            extra=scan_log_extra(run, "scan.queued"),
        )
        if normalized.get("provider") in {"github-enterprise", "mixed"}:
            log_github_app_context(
                normalized.get("githubAppId") or configured_github_app_id(),
                normalized.get("githubAppInstallationId") or configured_github_installation_id(),
                scan_id=scan_id,
                owner_user_id=normalized.get("ownerUserId", ""),
                owner_user_login=normalized.get("ownerUserLogin", ""),
            )
        thread = threading.Thread(target=self._run_scan, args=(run,), name=f"scan-{scan_id}", daemon=True)
        with self.lock:
            self._threads.add(thread)
        thread.start()
        return run

    def pause_scan(self, scan_id: str) -> ScanRun | None:
        run = self.get_scan(scan_id)
        if not run:
            return None
        with run.lock:
            process = run.process
            status = run.status
        if status != "running" or not process or process.poll() is not None:
            raise ValueError("Only a running scan can be paused.")
        try:
            pause_process(process)
        except ProcessLookupError as exc:
            raise ValueError("The scan ended before it could be paused.") from exc
        run.append_log("Scan paused from UI.")
        run.set_status("paused")
        LOGGER.info("Scan paused scan_id=%s", run.id, extra=scan_log_extra(run, "scan.paused", status="paused"))
        return run

    def resume_scan(self, scan_id: str) -> ScanRun | None:
        run = self.get_scan(scan_id)
        if not run:
            return None
        with run.lock:
            process = run.process
            status = run.status
        if status != "paused" or not process or process.poll() is not None:
            raise ValueError("Only a paused scan can be resumed.")
        try:
            resume_process(process)
        except ProcessLookupError as exc:
            raise ValueError("The scan ended before it could be resumed.") from exc
        run.append_log("Scan resumed from UI.")
        run.set_status("running")
        LOGGER.info("Scan resumed scan_id=%s", run.id, extra=scan_log_extra(run, "scan.resumed", status="running"))
        return run

    def stop_scan(self, scan_id: str) -> ScanRun | None:
        run = self.get_scan(scan_id)
        if not run:
            return None
        with run.lock:
            process = run.process
            status = run.status
            run.stop_requested = True
        if status == "queued":
            run.append_log("Queued scan cancelled from UI.")
        elif process and status in {"running", "paused"} and process.poll() is None:
            run.append_log("Stop requested from UI.")
            try:
                terminate_process(process, resume_first=status == "paused")
            except ProcessLookupError:
                return run
        return run

    def close(self) -> None:
        with self.lock:
            self._closing = True
            runs = tuple(self.scans.values())
            threads = tuple(self._threads)
        for run in runs:
            if run.status in SCAN_STATUSES_ACTIVE:
                self.stop_scan(run.id)
        deadline = time.monotonic() + 5
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        for run in runs:
            with run.lock:
                process = run.process
            if process and process.poll() is None:
                try:
                    kill_process(process)
                except ProcessLookupError:
                    continue
        deadline = time.monotonic() + 2
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=max(0.0, deadline - time.monotonic()))

    def _run_scan(self, run: ScanRun) -> None:
        acquired = False
        try:
            while not acquired:
                if run.stop_requested:
                    run.set_status("stopped", 0)
                    run.close_listeners()
                    return
                acquired = self._slots.acquire(timeout=0.5)
            if run.stop_requested:
                run.set_status("stopped", 0)
                run.close_listeners()
                return
            child_config = dict(run.config)
            child_config["scanId"] = run.id
            environment = self.build_environment(child_config)
            run.set_status("running")
            LOGGER.info("Scan started scan_id=%s", run.id, extra=scan_log_extra(run, "scan.started", status="running"))
            run.append_log(f"Command: {' '.join(run.display_command)}")
            try:
                process = subprocess.Popen(
                    run.command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    env=environment,
                    start_new_session=os.name == "posix",
                )
                with run.lock:
                    run.process = process
                if process.stdout:
                    try:
                        for line in process.stdout:
                            run.append_log(line)
                    finally:
                        process.stdout.close()
                exit_code = process.wait()
            except FileNotFoundError as exc:
                run.append_log(str(exc))
                run.set_status("failed", 127)
                LOGGER.error("Scan failed scan_id=%s", run.id, extra=scan_log_extra(run, "scan.failed", status="failed"))
                run.close_listeners()
                return
            except Exception as exc:
                run.append_log(str(exc))
                run.set_status("failed", 1)
                LOGGER.exception("Scan failed scan_id=%s", run.id, extra=scan_log_extra(run, "scan.failed", status="failed"))
                run.close_listeners()
                return

            if run.stop_requested:
                run.set_status("stopped", exit_code)
            elif exit_code == 0:
                run.set_status("succeeded", exit_code)
            else:
                run.set_status("failed", exit_code)
            LOGGER.info(
                "Scan completed scan_id=%s status=%s exit_code=%s",
                run.id,
                run.status,
                exit_code,
                extra=scan_log_extra(run, "scan.completed", status=run.status),
            )
            run.close_listeners()
        finally:
            if acquired:
                self._slots.release()
            with self.lock:
                self._threads.discard(threading.current_thread())


def pause_process(process: subprocess.Popen[str]) -> None:
    if os.name != "posix" or not hasattr(signal, "SIGSTOP"):
        raise ValueError("Pause and resume require a POSIX host such as Linux or macOS.")
    os.killpg(os.getpgid(process.pid), signal.SIGSTOP)


def resume_process(process: subprocess.Popen[str]) -> None:
    if os.name != "posix" or not hasattr(signal, "SIGCONT"):
        raise ValueError("Pause and resume require a POSIX host such as Linux or macOS.")
    os.killpg(os.getpgid(process.pid), signal.SIGCONT)


def terminate_process(process: subprocess.Popen[str], resume_first: bool = False) -> None:
    if os.name == "posix":
        process_group = os.getpgid(process.pid)
        if resume_first and hasattr(signal, "SIGCONT"):
            os.killpg(process_group, signal.SIGCONT)
        os.killpg(process_group, signal.SIGTERM)
        return
    process.terminate()


def kill_process(process: subprocess.Popen[str]) -> None:
    if os.name == "posix" and hasattr(signal, "SIGKILL"):
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        return
    process.kill()


def scan_target_summary(config: dict[str, Any]) -> str:
    target_filters = config.get("targetFilters") if isinstance(config.get("targetFilters"), list) else []
    if target_filters:
        if len(target_filters) == 1:
            target = target_filters[0]
            project = str(target.get("project") or "").strip()
            organization = str(target.get("org") or "").strip()
            return f"{organization}/{project}" if organization else project
        return f"{len(target_filters)} selected targets"
    return str(config.get("repo") or config.get("project") or "all")


def run_owner_id(run: ScanRun) -> str:
    return str(run.config.get("ownerUserId") or "anonymous")


def scan_log_extra(run: ScanRun, event_type: str, status: str = "") -> dict[str, Any]:
    return {
        "event_type": event_type,
        "scan_id": run.id,
        "owner_user_id": run_owner_id(run),
        "owner_user_login": str(run.config.get("ownerUserLogin") or "anonymous"),
        "provider": str(run.config.get("provider") or ""),
        "status": status or run.status,
    }


def new_scan_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
