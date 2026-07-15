from __future__ import annotations

import json
import logging
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import (
    DEFAULT_OUT_PREFIX,
    DEFAULT_POSTGRES_SCHEMA,
    DEFAULT_POSTGRES_TABLE,
)
from .github import configured_github_app_id, configured_github_installation_id
from .observability import log_github_app_context
from .scan_persistence import ScanStateStore, valid_scan_id


LOGGER = logging.getLogger("appsec_scan_router")
MAX_LOG_LINES = 5000
MAX_PERSISTED_SCANS = 500
REPORT_EXTENSIONS = frozenset({".csv", ".json", ".log", ".xlsx", ".txt"})
SCAN_STATUSES_DONE = frozenset({"succeeded", "failed", "stopped"})
SCAN_STATUSES_ACTIVE = frozenset({"queued", "running", "paused"})
FAILURE_LOG_PATTERN = re.compile(
    r"\b(?:critical|errors?|failed|failures?|fatal|exception|traceback)\b"
    r"|\bcould not\b|\bunable to\b|\bmissing\b.+\bconfiguration\b"
    r"|\b(?:http|status)(?:\s+status)?[\s:=]+[45]\d{2}\b",
    re.IGNORECASE,
)
NEGATED_FAILURE_PATTERN = re.compile(
    r"\b(?:no|zero|0)\s+(?:errors?|failures?)\b"
    r"|\b(?:errors?|failures?)\s*[:=]\s*0\b",
    re.IGNORECASE,
)
CONFIRMED_FINDING_PATTERN = re.compile(
    r"\bDETECTED\s+(?:asset|app)=|\bfound\s+\d+\s+inventory\b",
    re.IGNORECASE,
)


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
    process_pid: int | None = None
    process_group_id: int | None = None
    recovered: bool = False
    log_path: Path | None = None
    failure_log_path: Path | None = None
    logs: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_LOG_LINES))
    log_tail: deque[str] = field(default_factory=lambda: deque(maxlen=300))
    failure_tail: deque[str] = field(default_factory=lambda: deque(maxlen=300))
    listeners: list[queue.Queue[dict[str, Any] | None]] = field(default_factory=list)
    lock: threading.RLock = field(default_factory=threading.RLock)
    detected_count: int = 0
    failure_count: int = 0
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
    _log_offset: int = 0
    _log_sequence: int = 0
    _report_cache: list[dict[str, Any]] = field(default_factory=list)
    _report_cache_at: float = 0.0

    def append_log(self, line: str, persist_failure: bool = True) -> None:
        clean_line = line.rstrip("\n")
        if not clean_line:
            return
        failure = is_failure_log_line(clean_line)
        with self.lock:
            self._log_sequence += 1
            sequence = self._log_sequence
            self.logs.append(clean_line)
            self.log_tail.append(clean_line)
            if failure:
                self.failure_tail.append(clean_line)
                self.failure_count += 1
                self._report_cache_at = 0.0
            self._record_log_metrics(clean_line)
        if failure and persist_failure and self.failure_log_path is not None:
            try:
                append_scan_log(self.failure_log_path, clean_line)
            except OSError:
                LOGGER.exception("Could not write scan failure log scan_id=%s", self.id)
        self.publish(
            "log",
            {"line": clean_line, "failure": failure, "sequence": sequence},
        )

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
                self.listeners = [
                    listener
                    for listener in self.listeners
                    if id(listener) not in stale_ids
                ]

    def add_listener(self) -> queue.Queue[dict[str, Any] | None]:
        listener: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=250)
        with self.lock:
            self.listeners.append(listener)
        return listener

    def remove_listener(self, listener: queue.Queue[dict[str, Any] | None]) -> None:
        with self.lock:
            self.listeners = [
                candidate for candidate in self.listeners if candidate is not listener
            ]

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
            if self._report_cache_at and (
                self.status in SCAN_STATUSES_DONE or now - self._report_cache_at < 2.0
            ):
                return list(self._report_cache)
        reports: list[dict[str, Any]] = []
        if self.reports_dir.exists():
            for path in sorted(self.reports_dir.iterdir()):
                if (
                    path.name.startswith(".")
                    or not path.is_file()
                    or path.suffix.lower() not in REPORT_EXTENSIONS
                ):
                    continue
                stat = path.stat()
                reports.append(
                    {
                        "name": path.name,
                        "size": stat.st_size,
                        "updatedAt": datetime.fromtimestamp(
                            stat.st_mtime, timezone.utc
                        ).isoformat(),
                        "url": f"/api/scans/{self.id}/reports/{path.name}",
                    }
                )
        with self.lock:
            self._report_cache = reports
            self._report_cache_at = now
        return list(reports)

    def active_seconds(self) -> int:
        with self.lock:
            if self.started_monotonic:
                end = (
                    time.monotonic()
                    if self.status not in SCAN_STATUSES_DONE
                    else self.started_monotonic + self._elapsed_seconds()
                )
                paused = self.paused_seconds
                if self.paused_monotonic:
                    paused += time.monotonic() - self.paused_monotonic
                return max(0, round(end - self.started_monotonic - paused))
            if not self.started_at:
                return 0
            try:
                started = datetime.fromisoformat(self.started_at.replace("Z", "+00:00"))
                ended = (
                    datetime.fromisoformat(self.ended_at.replace("Z", "+00:00"))
                    if self.ended_at
                    else datetime.now(timezone.utc)
                )
            except ValueError:
                return 0
            return max(
                0, round((ended - started).total_seconds() - self.paused_seconds)
            )

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
                "postgresSchema": str(
                    self.config.get("postgresSchema", DEFAULT_POSTGRES_SCHEMA)
                ),
                "postgresTable": str(
                    self.config.get("postgresTable", DEFAULT_POSTGRES_TABLE)
                ),
                "startedAt": self.started_at,
                "endedAt": self.ended_at,
                "exitCode": self.exit_code,
                "detectedCount": self.detected_count,
                "failureCount": self.failure_count,
                "logSequence": self._log_sequence,
                "progress": dict(self.progress),
                "activeSeconds": self.active_seconds(),
                "reportsDir": str(self.reports_dir),
                "command": " ".join(self.display_command),
                "persistent": True,
                "recovered": self.recovered,
                "reports": reports,
                "logsTail": list(self.log_tail),
                "failuresTail": list(self.failure_tail),
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
        state_dir: Path | None = None,
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
        self.state_store = ScanStateStore(
            state_dir or self.reports_root / ".application_inventory_service"
        )
        self._restore_scans()

    def list_scans(self, owner_user_id: str = "") -> list[dict[str, Any]]:
        with self.lock:
            runs = tuple(self.scans.values())
        if owner_user_id:
            runs = tuple(run for run in runs if run_owner_id(run) == owner_user_id)
        return [
            run.summary()
            for run in sorted(runs, key=lambda item: item.id, reverse=True)
        ]

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
            log_path=reports_dir / ".scan.log",
            failure_log_path=reports_dir / "failures.log",
        )
        self.state_store.remove_completion(scan_id)
        with self.lock:
            self.scans[scan_id] = run
        self._persist_scans()
        LOGGER.info(
            "Scan queued scan_id=%s provider=%s",
            scan_id,
            normalized.get("provider", ""),
            extra=scan_log_extra(run, "scan.queued"),
        )
        if normalized.get("provider") in {"github-enterprise", "mixed"}:
            log_github_app_context(
                normalized.get("githubAppId") or configured_github_app_id(),
                normalized.get("githubAppInstallationId")
                or configured_github_installation_id(),
                scan_id=scan_id,
                owner_user_id=normalized.get("ownerUserId", ""),
                owner_user_login=normalized.get("ownerUserLogin", ""),
            )
        self._start_thread(run, self._run_scan)
        return run

    def pause_scan(self, scan_id: str) -> ScanRun | None:
        run = self.get_scan(scan_id)
        if not run:
            return None
        with run.lock:
            process = run.process or run.process_pid
            process_group_id = run.process_group_id
            status = run.status
        if status != "running" or not process_is_running(process, process_group_id):
            raise ValueError("Only a running scan can be paused.")
        try:
            pause_process(process, process_group_id)
        except ProcessLookupError as exc:
            raise ValueError("The scan ended before it could be paused.") from exc
        run.append_log("Scan paused from UI.")
        run.set_status("paused")
        self._persist_scans()
        LOGGER.info(
            "Scan paused scan_id=%s",
            run.id,
            extra=scan_log_extra(run, "scan.paused", status="paused"),
        )
        return run

    def resume_scan(self, scan_id: str) -> ScanRun | None:
        run = self.get_scan(scan_id)
        if not run:
            return None
        with run.lock:
            process = run.process or run.process_pid
            process_group_id = run.process_group_id
            status = run.status
        if status != "paused" or not process_is_running(process, process_group_id):
            raise ValueError("Only a paused scan can be resumed.")
        try:
            resume_process(process, process_group_id)
        except ProcessLookupError as exc:
            raise ValueError("The scan ended before it could be resumed.") from exc
        run.append_log("Scan resumed from UI.")
        run.set_status("running")
        self._persist_scans()
        LOGGER.info(
            "Scan resumed scan_id=%s",
            run.id,
            extra=scan_log_extra(run, "scan.resumed", status="running"),
        )
        return run

    def stop_scan(self, scan_id: str) -> ScanRun | None:
        run = self.get_scan(scan_id)
        if not run:
            return None
        with run.lock:
            process = run.process or run.process_pid
            process_group_id = run.process_group_id
            status = run.status
            run.stop_requested = True
        if status == "queued":
            run.append_log("Queued scan cancelled from UI.")
        elif (
            process
            and status in {"running", "paused"}
            and process_is_running(process, process_group_id)
        ):
            run.append_log("Stop requested from UI.")
            try:
                terminate_process(
                    process,
                    process_group_id,
                    resume_first=status == "paused",
                )
            except ProcessLookupError:
                return run
        self._persist_scans()
        return run

    def close(self) -> None:
        with self.lock:
            self._closing = True
            runs = tuple(self.scans.values())
            threads = tuple(self._threads)
        self._persist_scans()
        for run in runs:
            run.close_listeners()
        deadline = time.monotonic() + 2
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

    def _start_thread(
        self,
        run: ScanRun,
        target: Callable[..., None],
        *args: Any,
    ) -> None:
        thread = threading.Thread(
            target=target,
            args=(run, *args),
            name=f"scan-{run.id}",
            daemon=True,
        )
        with self.lock:
            self._threads.add(thread)
        thread.start()

    def _run_scan(self, run: ScanRun) -> None:
        acquired = False
        try:
            while not acquired:
                if self._closing:
                    self._persist_scans()
                    return
                if run.stop_requested:
                    run.set_status("stopped", 0)
                    self._persist_scans()
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
            command_line = f"Command: {' '.join(run.display_command)}"
            append_scan_log(run.log_path, command_line)
            run.append_log(command_line)
            log_offset = scan_log_size(run.log_path)
            completion_path = self.state_store.completion_path(run.id)
            self.state_store.remove_completion(run.id)
            worker_command = durable_worker_command(run.command, completion_path)
            LOGGER.info(
                "Scan started scan_id=%s",
                run.id,
                extra=scan_log_extra(run, "scan.started", status="running"),
            )
            try:
                with open_scan_log(run.log_path) as log_file:
                    process = subprocess.Popen(
                        worker_command,
                        stdin=subprocess.DEVNULL,
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                        env=environment,
                        close_fds=True,
                        start_new_session=os.name == "posix",
                    )
                with run.lock:
                    run.process = process
                    run.process_pid = process.pid
                    run.process_group_id = process.pid if os.name == "posix" else None
                self._persist_scans()
                self._monitor_scan(run, process, log_offset)
            except FileNotFoundError as exc:
                run.append_log(str(exc))
                run.set_status("failed", 127)
                self._persist_scans()
                LOGGER.error(
                    "Scan failed scan_id=%s",
                    run.id,
                    extra=scan_log_extra(run, "scan.failed", status="failed"),
                )
                run.close_listeners()
                return
            except Exception as exc:
                run.append_log(str(exc))
                run.set_status("failed", 1)
                self._persist_scans()
                LOGGER.exception(
                    "Scan failed scan_id=%s",
                    run.id,
                    extra=scan_log_extra(run, "scan.failed", status="failed"),
                )
                run.close_listeners()
                return
        finally:
            if acquired:
                self._slots.release()
            with self.lock:
                self._threads.discard(threading.current_thread())

    def _monitor_recovered_scan(self, run: ScanRun, acquired: bool) -> None:
        try:
            self._monitor_scan(run, None, run._log_offset)
        finally:
            if acquired:
                self._slots.release()
            with self.lock:
                self._threads.discard(threading.current_thread())

    def _monitor_scan(
        self,
        run: ScanRun,
        process: subprocess.Popen[str] | None,
        log_offset: int,
    ) -> None:
        while True:
            log_offset = self._publish_scan_log(run, log_offset)
            completion = self.state_store.read_completion(run.id)
            exit_code = completion_exit_code(completion)
            if exit_code is None and process is not None:
                exit_code = process.poll()
            if exit_code is not None:
                self._publish_scan_log(run, log_offset, include_partial=True)
                self._complete_scan(run, exit_code, completion)
                return
            if process is None and not process_is_running(
                run.process_pid, run.process_group_id
            ):
                self._publish_scan_log(run, log_offset, include_partial=True)
                self._complete_scan(run, None, completion)
                return
            if self._closing:
                self._persist_scans()
                return
            time.sleep(0.25)

    def _publish_scan_log(
        self,
        run: ScanRun,
        offset: int,
        include_partial: bool = False,
    ) -> int:
        next_offset, lines = read_scan_log(run.log_path, offset, include_partial)
        for line in lines:
            run.append_log(line)
        return next_offset

    def _complete_scan(
        self,
        run: ScanRun,
        exit_code: int | None,
        completion: dict[str, Any] | None,
    ) -> None:
        if completion and completion.get("endedAt"):
            run.ended_at = str(completion["endedAt"])
        if run.stop_requested:
            status = "stopped"
        elif exit_code == 0:
            status = "succeeded"
        else:
            status = "failed"
        run.set_status(status, exit_code)
        with run.lock:
            run.process = None
        self._persist_scans()
        LOGGER.info(
            "Scan completed scan_id=%s status=%s exit_code=%s",
            run.id,
            run.status,
            exit_code,
            extra=scan_log_extra(run, "scan.completed", status=run.status),
        )
        run.close_listeners()

    def _restore_scans(self) -> None:
        queued: list[ScanRun] = []
        recovered: list[ScanRun] = []
        for record in self.state_store.records():
            run = self._restore_run(record)
            if run is None:
                continue
            self.scans[run.id] = run
            if run.status == "queued":
                queued.append(run)
            elif run.status in {"running", "paused"}:
                completion = self.state_store.read_completion(run.id)
                exit_code = completion_exit_code(completion)
                if exit_code is not None:
                    self._complete_scan(run, exit_code, completion)
                elif process_is_running(run.process_pid, run.process_group_id):
                    recovered.append(run)
                else:
                    run.append_log(
                        "Scan process ended while the service was offline; exit status is unavailable."
                    )
                    self._complete_scan(run, None, None)
        self._persist_scans()
        for run in queued:
            self._start_thread(run, self._run_scan)
        for run in recovered:
            acquired = self._slots.acquire(blocking=False)
            self._start_thread(run, self._monitor_recovered_scan, acquired)

    def _restore_run(self, record: dict[str, Any]) -> ScanRun | None:
        try:
            scan_id = valid_scan_id(record.get("id"))
            config = dict(record.get("config") or {})
            status = str(record.get("status") or "failed")
            if status not in SCAN_STATUSES_ACTIVE | SCAN_STATUSES_DONE:
                return None
            reports_dir = self.reports_root / scan_id
            reports_dir.mkdir(parents=True, exist_ok=True)
            command = (
                tuple(self.build_command(config, reports_dir))
                if status == "queued"
                else ()
            )
            display_command = tuple(record.get("displayCommand") or ())
            if status == "queued" and not display_command:
                display_command = tuple(self.redact_command(command))
        except (OSError, TypeError, ValueError):
            return None
        run = ScanRun(
            id=scan_id,
            config=config,
            command=command,
            display_command=display_command,
            reports_dir=reports_dir,
            status=status,
            started_at=str(record.get("startedAt") or ""),
            ended_at=str(record.get("endedAt") or ""),
            exit_code=optional_int(record.get("exitCode")),
            stop_requested=bool(record.get("stopRequested")),
            process_pid=positive_optional_int(record.get("processPid")),
            process_group_id=positive_optional_int(record.get("processGroupId")),
            recovered=status in {"running", "paused"},
            log_path=reports_dir / ".scan.log",
            failure_log_path=reports_dir / "failures.log",
            paused_seconds=non_negative_float(record.get("pausedSeconds")),
        )
        snapshot_size = scan_log_size(run.log_path)
        for offset, line in scan_log_entries(run.log_path, snapshot_size):
            run._log_offset = offset
            run.append_log(line, persist_failure=False)
        try:
            rebuild_failure_log(
                run.log_path,
                run.failure_log_path,
                byte_limit=run._log_offset,
            )
        except OSError:
            LOGGER.exception("Could not rebuild scan failure log scan_id=%s", run.id)
        return run

    def _persist_scans(self) -> None:
        with self.lock:
            runs = sorted(self.scans.values(), key=lambda item: item.id, reverse=True)
        active = [run for run in runs if run.status in SCAN_STATUSES_ACTIVE]
        completed = [run for run in runs if run.status not in SCAN_STATUSES_ACTIVE]
        retained = active + completed[: max(0, MAX_PERSISTED_SCANS - len(active))]
        self.state_store.write(run_state_record(run) for run in retained)


def durable_worker_command(
    command: tuple[str, ...], completion_path: Path
) -> tuple[str, ...]:
    return (
        sys.executable,
        "-m",
        "appsec_scan_router.scan_worker",
        "--completion-file",
        str(completion_path),
        "--",
        *command,
    )


def open_scan_log(path: Path | None) -> Any:
    if path is None:
        raise ValueError("Scan log path is required.")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    return os.fdopen(descriptor, "ab", buffering=0)


def append_scan_log(path: Path | None, line: str) -> None:
    with open_scan_log(path) as log_file:
        log_file.write(f"{line.rstrip()}\n".encode("utf-8", errors="replace"))


def scan_log_size(path: Path | None) -> int:
    if path is None:
        return 0
    try:
        return path.stat().st_size
    except OSError:
        return 0


def read_scan_log(
    path: Path | None,
    offset: int,
    include_partial: bool = False,
) -> tuple[int, list[str]]:
    if path is None or not path.exists():
        return offset, []
    try:
        with path.open("rb") as log_file:
            log_file.seek(max(0, offset))
            data = log_file.read()
    except OSError:
        return offset, []
    if not data:
        return offset, []
    consumed = len(data)
    if not include_partial and not data.endswith(b"\n"):
        newline = data.rfind(b"\n")
        if newline < 0:
            return offset, []
        consumed = newline + 1
        data = data[:consumed]
    lines = data.decode("utf-8", errors="replace").splitlines()
    return offset + consumed, lines


def scan_log_entries(
    path: Path | None,
    byte_limit: int | None = None,
) -> Iterable[tuple[int, str]]:
    if path is None or not path.exists():
        return ()

    def entries() -> Iterable[tuple[int, str]]:
        try:
            with path.open("rb") as log_file:
                while True:
                    if byte_limit is None:
                        line = log_file.readline()
                    else:
                        remaining = max(0, byte_limit - log_file.tell())
                        if not remaining:
                            return
                        line = log_file.readline(remaining)
                    if not line or not line.endswith(b"\n"):
                        return
                    yield (
                        log_file.tell(),
                        line.decode("utf-8", errors="replace").rstrip("\r\n"),
                    )
        except OSError:
            return

    return entries()


def scan_log_lines(
    path: Path | None,
    byte_limit: int | None = None,
) -> Iterable[str]:
    return (line for _, line in scan_log_entries(path, byte_limit))


def is_failure_log_line(line: str) -> bool:
    value = str(line or "").strip()
    if not value or CONFIRMED_FINDING_PATTERN.search(value):
        return False
    return bool(FAILURE_LOG_PATTERN.search(NEGATED_FAILURE_PATTERN.sub("", value)))


def rebuild_failure_log(
    source_path: Path | None,
    failure_path: Path | None,
    byte_limit: int | None = None,
) -> int:
    return write_failure_log(
        failure_path,
        scan_log_lines(source_path, byte_limit),
    )


def write_failure_log(failure_path: Path | None, lines: Iterable[str]) -> int:
    if failure_path is None:
        return 0
    failure_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = failure_path.with_name(
        f".{failure_path.name}.{uuid.uuid4().hex}.tmp"
    )
    descriptor = os.open(
        temporary_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    count = 0
    try:
        with os.fdopen(descriptor, "wb") as failure_file:
            for line in lines:
                if not is_failure_log_line(line):
                    continue
                failure_file.write(
                    f"{line.rstrip()}\n".encode("utf-8", errors="replace")
                )
                count += 1
        if count:
            os.replace(temporary_path, failure_path)
        else:
            temporary_path.unlink(missing_ok=True)
            failure_path.unlink(missing_ok=True)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    return count


def run_state_record(run: ScanRun) -> dict[str, Any]:
    with run.lock:
        return {
            "id": run.id,
            "config": json_safe(run.config),
            "displayCommand": list(run.display_command),
            "status": run.status,
            "startedAt": run.started_at,
            "endedAt": run.ended_at,
            "exitCode": run.exit_code,
            "stopRequested": run.stop_requested,
            "processPid": run.process_pid,
            "processGroupId": run.process_group_id,
            "pausedSeconds": run.paused_seconds,
        }


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    return str(value)


def completion_exit_code(completion: dict[str, Any] | None) -> int | None:
    if not completion:
        return None
    return optional_int(completion.get("exitCode"))


def optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def positive_optional_int(value: Any) -> int | None:
    resolved = optional_int(value)
    return resolved if resolved is not None and resolved > 0 else None


def non_negative_float(value: Any) -> float:
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return 0.0


def process_id(process: subprocess.Popen[Any] | int) -> int:
    return process if isinstance(process, int) else process.pid


def process_is_running(
    process: subprocess.Popen[Any] | int | None,
    process_group_id: int | None = None,
) -> bool:
    if process is None:
        return False
    if not isinstance(process, int):
        return process.poll() is None
    try:
        os.kill(process, 0)
        if (
            os.name == "posix"
            and process_group_id is not None
            and os.getpgid(process) != process_group_id
        ):
            return False
        return True
    except PermissionError:
        return True
    except (ProcessLookupError, OSError):
        return False


def process_group(process: subprocess.Popen[Any] | int, fallback: int | None) -> int:
    if fallback is not None:
        return fallback
    return os.getpgid(process_id(process))


def pause_process(
    process: subprocess.Popen[Any] | int,
    process_group_id: int | None = None,
) -> None:
    if os.name != "posix" or not hasattr(signal, "SIGSTOP"):
        raise ValueError(
            "Pause and resume require a POSIX host such as Linux or macOS."
        )
    os.killpg(process_group(process, process_group_id), signal.SIGSTOP)


def resume_process(
    process: subprocess.Popen[Any] | int,
    process_group_id: int | None = None,
) -> None:
    if os.name != "posix" or not hasattr(signal, "SIGCONT"):
        raise ValueError(
            "Pause and resume require a POSIX host such as Linux or macOS."
        )
    os.killpg(process_group(process, process_group_id), signal.SIGCONT)


def terminate_process(
    process: subprocess.Popen[Any] | int,
    process_group_id: int | None = None,
    resume_first: bool = False,
) -> None:
    if os.name == "posix":
        group_id = process_group(process, process_group_id)
        if resume_first and hasattr(signal, "SIGCONT"):
            os.killpg(group_id, signal.SIGCONT)
        os.killpg(group_id, signal.SIGTERM)
        return
    if isinstance(process, int):
        os.kill(process, signal.SIGTERM)
    else:
        process.terminate()


def kill_process(
    process: subprocess.Popen[Any] | int,
    process_group_id: int | None = None,
) -> None:
    if os.name == "posix" and hasattr(signal, "SIGKILL"):
        os.killpg(process_group(process, process_group_id), signal.SIGKILL)
        return
    if isinstance(process, int):
        os.kill(process, signal.SIGTERM)
    else:
        process.kill()


def scan_target_summary(config: dict[str, Any]) -> str:
    target_filters = (
        config.get("targetFilters")
        if isinstance(config.get("targetFilters"), list)
        else []
    )
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
