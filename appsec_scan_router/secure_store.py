from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .constants import MISSING_CRYPTOGRAPHY_MESSAGE

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    Fernet = None
    InvalidToken = Exception


class EncryptedJsonStore:
    def __init__(
        self,
        state_dir: Path,
        filename: str,
        default_factory: Callable[[], dict[str, Any]],
    ) -> None:
        if Fernet is None:
            raise SystemExit(MISSING_CRYPTOGRAPHY_MESSAGE)
        self.state_dir = state_dir
        self.path = state_dir / filename
        self.key_path = state_dir / "vault.key"
        self.default_factory = default_factory
        self.lock = threading.RLock()
        self.fernet = Fernet(self._encryption_key())

    def read(self) -> dict[str, Any]:
        with self.lock:
            if not self.path.exists():
                return self.default_factory()
            try:
                plaintext = self.fernet.decrypt(self.path.read_bytes())
                data = json.loads(plaintext.decode("utf-8"))
            except (InvalidToken, OSError, ValueError):
                return self.default_factory()
            return data if isinstance(data, dict) else self.default_factory()

    def write(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encrypted = self.fernet.encrypt(payload)
        with self.lock:
            self._prepare_state_dir()
            temporary_path: Path | None = None
            try:
                with NamedTemporaryFile(dir=self.state_dir, prefix=f".{self.path.name}.", delete=False) as temporary:
                    temporary.write(encrypted)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    temporary_path = Path(temporary.name)
                chmod_private(temporary_path, 0o600)
                temporary_path.replace(self.path)
                chmod_private(self.path, 0o600)
            finally:
                if temporary_path and temporary_path.exists():
                    temporary_path.unlink(missing_ok=True)

    def _encryption_key(self) -> bytes:
        configured = first_environment_value(
            "APPLICATION_INVENTORY_SERVICE_SECRET_KEY",
            "APPSEC_INVENTORY_SERVICE_SECRET_KEY",
        )
        if configured:
            return configured.encode("utf-8")
        self._prepare_state_dir()
        try:
            descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key()
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(key)
            key_file.flush()
            os.fsync(key_file.fileno())
        chmod_private(self.key_path, 0o600)
        return key

    def _prepare_state_dir(self) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        chmod_private(self.state_dir, 0o700)


def first_environment_value(*names: str) -> str:
    for name in names:
        value = str(os.getenv(name) or "").strip()
        if value:
            return value
    return ""


def chmod_private(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        return
