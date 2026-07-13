from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .runtime import ScanManager, scan_target_summary
from .secure_store import EncryptedJsonStore


LOGGER = logging.getLogger("appsec_scan_router")
SCHEDULE_FREQUENCIES = frozenset({"once", "daily", "weekly"})


@dataclass
class ScanSchedule:
    id: str
    name: str
    frequency: str
    next_run_at: str
    owner_user_id: str
    owner_user_login: str
    config: dict[str, Any]
    enabled: bool = True
    created_at: str = ""
    last_run_at: str = ""
    last_scan_id: str = ""
    last_error: str = ""

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> ScanSchedule | None:
        try:
            schedule_id = str(record["id"])
            name = str(record["name"])
            frequency = normalize_frequency(record["frequency"])
            next_run_at = normalize_timestamp(record["nextRunAt"])
            config = dict(record["config"])
        except (KeyError, TypeError, ValueError):
            return None
        return cls(
            id=schedule_id,
            name=name,
            frequency=frequency,
            next_run_at=next_run_at,
            owner_user_id=str(record.get("ownerUserId") or "anonymous"),
            owner_user_login=str(record.get("ownerUserLogin") or "anonymous"),
            config=config,
            enabled=bool(record.get("enabled", True)),
            created_at=str(record.get("createdAt") or ""),
            last_run_at=str(record.get("lastRunAt") or ""),
            last_scan_id=str(record.get("lastScanId") or ""),
            last_error=str(record.get("lastError") or ""),
        )

    def record(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "frequency": self.frequency,
            "nextRunAt": self.next_run_at,
            "ownerUserId": self.owner_user_id,
            "ownerUserLogin": self.owner_user_login,
            "config": self.config,
            "enabled": self.enabled,
            "createdAt": self.created_at,
            "lastRunAt": self.last_run_at,
            "lastScanId": self.last_scan_id,
            "lastError": self.last_error,
        }

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "frequency": self.frequency,
            "nextRunAt": self.next_run_at,
            "enabled": self.enabled,
            "createdAt": self.created_at,
            "lastRunAt": self.last_run_at,
            "lastScanId": self.last_scan_id,
            "lastError": self.last_error,
            "provider": str(self.config.get("provider") or "azure-devops"),
            "org": str(self.config.get("orgDisplay") or self.config.get("org") or ""),
            "target": scan_target_summary(self.config),
            "applicationTypes": list(self.config.get("applicationTypes") or []),
        }


class ScanScheduler:
    def __init__(self, manager: ScanManager, state_dir: Path) -> None:
        self.manager = manager
        self.store = EncryptedJsonStore(state_dir, "schedules.json.enc", self.default_data)
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.schedules = self._load()
        self.closed = False
        self.started = False
        self.thread = threading.Thread(target=self._run, name="scan-scheduler", daemon=True)

    def start(self) -> None:
        with self.condition:
            if self.started:
                return
            if self.closed:
                raise RuntimeError("The scan scheduler is closed.")
            self.started = True
        self.thread.start()

    def close(self) -> None:
        with self.condition:
            if self.closed:
                return
            self.closed = True
            self.condition.notify_all()
            started = self.started
        if started:
            self.thread.join(timeout=5)

    def list_schedules(self, owner_user_id: str) -> list[dict[str, Any]]:
        with self.lock:
            schedules = [
                schedule
                for schedule in self.schedules.values()
                if schedule.owner_user_id == owner_user_id
            ]
        return [
            schedule.summary()
            for schedule in sorted(schedules, key=lambda item: (not item.enabled, item.next_run_at, item.name.lower()))
        ]

    def create_schedule(
        self,
        name: str,
        frequency: str,
        run_at: str,
        config: dict[str, Any],
        owner_user_id: str,
        owner_user_login: str,
    ) -> ScanSchedule:
        clean_name = str(name or "").strip()
        if not clean_name:
            raise ValueError("Schedule name is required.")
        if len(clean_name) > 120:
            raise ValueError("Schedule name cannot exceed 120 characters.")
        clean_frequency = normalize_frequency(frequency)
        next_run_at = normalize_timestamp(run_at)
        normalized_config = self.manager.normalize_config(config)
        normalized_config["ownerUserId"] = owner_user_id
        normalized_config["ownerUserLogin"] = owner_user_login
        now = utc_now()
        schedule = ScanSchedule(
            id=uuid.uuid4().hex,
            name=clean_name,
            frequency=clean_frequency,
            next_run_at=next_run_at,
            owner_user_id=owner_user_id,
            owner_user_login=owner_user_login,
            config=normalized_config,
            created_at=now,
        )
        with self.condition:
            self.schedules[schedule.id] = schedule
            self._save()
            self.condition.notify_all()
        LOGGER.info(
            "Scan schedule created schedule_id=%s frequency=%s next_run_at=%s",
            schedule.id,
            schedule.frequency,
            schedule.next_run_at,
            extra={
                "event_type": "schedule.created",
                "owner_user_id": owner_user_id,
                "owner_user_login": owner_user_login,
                "provider": str(normalized_config.get("provider") or ""),
            },
        )
        return schedule

    def set_enabled(self, schedule_id: str, owner_user_id: str, enabled: bool) -> ScanSchedule | None:
        with self.condition:
            schedule = self._owned_schedule(schedule_id, owner_user_id)
            if not schedule:
                return None
            schedule.enabled = enabled
            if enabled and parse_timestamp(schedule.next_run_at) <= datetime.now(timezone.utc):
                schedule.next_run_at = next_future_run(schedule.frequency, schedule.next_run_at)
            self._save()
            self.condition.notify_all()
            return schedule

    def run_now(self, schedule_id: str, owner_user_id: str) -> ScanSchedule | None:
        with self.lock:
            schedule = self._owned_schedule(schedule_id, owner_user_id)
            if not schedule:
                return None
            config = dict(schedule.config)
        self._launch(schedule, config)
        return schedule

    def delete_schedule(self, schedule_id: str, owner_user_id: str) -> bool:
        with self.condition:
            schedule = self._owned_schedule(schedule_id, owner_user_id)
            if not schedule:
                return False
            self.schedules.pop(schedule.id, None)
            self._save()
            self.condition.notify_all()
        LOGGER.info(
            "Scan schedule deleted schedule_id=%s",
            schedule_id,
            extra={"event_type": "schedule.deleted", "owner_user_id": owner_user_id},
        )
        return True

    def metrics(self) -> dict[str, int]:
        with self.lock:
            schedules = tuple(self.schedules.values())
        return {
            "schedulesTotal": len(schedules),
            "schedulesEnabled": sum(schedule.enabled for schedule in schedules),
        }

    def _run(self) -> None:
        while True:
            with self.condition:
                if self.closed:
                    return
                now = datetime.now(timezone.utc)
                due = [
                    schedule
                    for schedule in self.schedules.values()
                    if schedule.enabled and parse_timestamp(schedule.next_run_at) <= now
                ]
                if not due:
                    self.condition.wait(timeout=self._wait_seconds(now))
                    continue
                launches: list[tuple[ScanSchedule, dict[str, Any]]] = []
                for schedule in due:
                    schedule.last_run_at = utc_now()
                    schedule.last_error = ""
                    if schedule.frequency == "once":
                        schedule.enabled = False
                    else:
                        schedule.next_run_at = next_future_run(schedule.frequency, schedule.next_run_at)
                    launches.append((schedule, dict(schedule.config)))
                self._save()
            for schedule, config in launches:
                self._launch(schedule, config)

    def _launch(self, schedule: ScanSchedule, config: dict[str, Any]) -> None:
        with self.condition:
            schedule.last_run_at = utc_now()
            schedule.last_error = ""
            self._save()
        try:
            run = self.manager.start_scan(config)
        except Exception as exc:
            with self.condition:
                schedule.last_error = str(exc)
                self._save()
            LOGGER.exception(
                "Scheduled scan failed to start schedule_id=%s",
                schedule.id,
                extra={"event_type": "schedule.failed", "owner_user_id": schedule.owner_user_id},
            )
            return
        with self.condition:
            schedule.last_scan_id = run.id
            schedule.last_error = ""
            self._save()
        LOGGER.info(
            "Scheduled scan queued schedule_id=%s scan_id=%s",
            schedule.id,
            run.id,
            extra={
                "event_type": "schedule.started",
                "scan_id": run.id,
                "owner_user_id": schedule.owner_user_id,
                "provider": str(config.get("provider") or ""),
            },
        )

    def _wait_seconds(self, now: datetime) -> float:
        upcoming = [
            parse_timestamp(schedule.next_run_at)
            for schedule in self.schedules.values()
            if schedule.enabled
        ]
        if not upcoming:
            return 60.0
        return max(0.1, min(60.0, (min(upcoming) - now).total_seconds()))

    def _owned_schedule(self, schedule_id: str, owner_user_id: str) -> ScanSchedule | None:
        schedule = self.schedules.get(str(schedule_id or "").strip())
        if not schedule or schedule.owner_user_id != owner_user_id:
            return None
        return schedule

    def _load(self) -> dict[str, ScanSchedule]:
        data = self.store.read()
        records = data.get("schedules") if isinstance(data.get("schedules"), list) else []
        schedules = (ScanSchedule.from_record(record) for record in records if isinstance(record, dict))
        return {schedule.id: schedule for schedule in schedules if schedule is not None}

    def _save(self) -> None:
        self.store.write(
            {
                "version": 1,
                "schedules": [schedule.record() for schedule in self.schedules.values()],
            }
        )

    @staticmethod
    def default_data() -> dict[str, Any]:
        return {"version": 1, "schedules": []}


def normalize_frequency(value: Any) -> str:
    frequency = str(value or "").strip().lower()
    if frequency not in SCHEDULE_FREQUENCIES:
        raise ValueError("Schedule frequency must be once, daily, or weekly.")
    return frequency


def normalize_timestamp(value: Any) -> str:
    timestamp = parse_timestamp(str(value or ""))
    if timestamp < datetime.now(timezone.utc) - timedelta(seconds=5):
        raise ValueError("Scheduled time must be in the future.")
    return timestamp.isoformat()


def parse_timestamp(value: str) -> datetime:
    if not value:
        return datetime.max.replace(tzinfo=timezone.utc)
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Scheduled time must be a valid ISO 8601 timestamp.") from exc
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def next_future_run(frequency: str, current_run_at: str) -> str:
    if frequency == "once":
        return (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    current = parse_timestamp(current_run_at)
    interval = timedelta(days=1 if frequency == "daily" else 7)
    now = datetime.now(timezone.utc)
    while current <= now:
        current += interval
    return current.isoformat()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
