from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Iterable

from .secure_store import EncryptedJsonStore, chmod_private


SCAN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
STATE_VERSION = 1


class ScanStateStore:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.worker_dir = state_dir / "scan-workers"
        self.store = EncryptedJsonStore(
            state_dir,
            "scan-runs.json.enc",
            lambda: {"version": STATE_VERSION, "runs": []},
        )
        self.lock = threading.RLock()

    def records(self) -> list[dict[str, Any]]:
        with self.lock:
            payload = self.store.read()
        records = payload.get("runs")
        if not isinstance(records, list):
            return []
        return [dict(record) for record in records if isinstance(record, dict)]

    def write(self, records: Iterable[dict[str, Any]]) -> None:
        payload = {"version": STATE_VERSION, "runs": list(records)}
        with self.lock:
            self.store.write(payload)

    def completion_path(self, scan_id: str) -> Path:
        return self.worker_dir / f"{valid_scan_id(scan_id)}.json"

    def read_completion(self, scan_id: str) -> dict[str, Any] | None:
        path = self.completion_path(scan_id)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def remove_completion(self, scan_id: str) -> None:
        self.completion_path(scan_id).unlink(missing_ok=True)


def write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    chmod_private(path.parent, 0o700)
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            json.dump(payload, temporary, sort_keys=True, separators=(",", ":"))
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        chmod_private(temporary_path, 0o600)
        temporary_path.replace(path)
        chmod_private(path, 0o600)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink(missing_ok=True)


def valid_scan_id(value: Any) -> str:
    scan_id = str(value or "").strip()
    if not SCAN_ID_RE.fullmatch(scan_id):
        raise ValueError("Invalid scan identifier.")
    return scan_id
