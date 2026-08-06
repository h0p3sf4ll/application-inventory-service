from __future__ import annotations

import os
import re
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path


ENVIRONMENT_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_project_environment() -> Path | None:
    configured = environment_file_setting()
    path = Path(configured).expanduser() if configured else Path.cwd() / ".env"
    return load_environment_file(path)


@contextmanager
def project_environment(path: Path | None = None) -> Iterator[Path | None]:
    resolved_path = path or project_environment_path()
    loaded: dict[str, str] = {}
    loaded_path = load_environment_file_values(resolved_path, loaded)
    try:
        yield loaded_path
    finally:
        for key, value in loaded.items():
            if os.environ.get(key) == value:
                os.environ.pop(key, None)


def load_environment_file(path: Path) -> Path | None:
    return load_environment_file_values(path, None)


def project_environment_path() -> Path:
    configured = environment_file_setting()
    return Path(configured).expanduser() if configured else Path.cwd() / ".env"


def environment_file_setting() -> str:
    return (
        os.getenv("APPSEC_ATLAS_ENV_FILE", "").strip()
        or os.getenv("APPLICATION_INVENTORY_ENV_FILE", "").strip()
    )


def load_environment_file_values(
    path: Path, loaded: dict[str, str] | None
) -> Path | None:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in content.splitlines():
        key, value = environment_assignment(line)
        if key and key not in os.environ:
            os.environ[key] = value
            if loaded is not None:
                loaded[key] = value
    return path


def environment_assignment(line: str) -> tuple[str, str]:
    value = line.strip()
    if not value or value.startswith("#"):
        return "", ""
    if value.startswith("export "):
        value = value[7:].lstrip()
    key, separator, raw_value = value.partition("=")
    key = key.strip()
    if not separator or not ENVIRONMENT_KEY_RE.fullmatch(key):
        return "", ""
    return key, environment_value(raw_value.strip())


def environment_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value