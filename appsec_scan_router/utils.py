from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from typing import Any

from .constants import CONTENT_FILE_SUFFIXES


def should_fetch_content(path: str) -> bool:
    return path.lower().endswith(CONTENT_FILE_SUFFIXES)


def normalize_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def first_present(values: Iterable[str]) -> str:
    for value in values:
        cleaned = clean_value(value)
        if cleaned:
            return cleaned
    return ""


def clean_value(value: Any) -> str:
    if value is None:
        return ""
    cleaned = str(value).strip().strip('"').strip("'")
    if not cleaned:
        return ""
    unresolved_markers = ("$(", "${", "@string/")
    if any(marker in cleaned for marker in unresolved_markers):
        return ""
    return cleaned


def clean_value_without_resource_filter(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().strip('"').strip("'")


def clean_version(value: Any) -> str:
    cleaned = clean_value(value)
    if not cleaned:
        return ""
    placeholder_patterns = (r"^9{2,}(?:\.9{2,})+$",)
    if any(re.match(pattern, cleaned) for pattern in placeholder_patterns):
        return ""
    if cleaned.lower() in {"todo", "tbd", "placeholder", "local", "dev"}:
        return ""
    return cleaned


def load_json_object(content: str) -> dict[str, Any]:
    try:
        data = json.loads(content)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def merged_package_dependencies(data: dict[str, Any]) -> set[str]:
    dependency_names: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        dependencies = data.get(key)
        if isinstance(dependencies, dict):
            dependency_names.update(str(name) for name in dependencies)
    return dependency_names


def yaml_has_flutter_dependency(content: str) -> bool:
    return bool(
        re.search(r"^\s*flutter\s*:\s*$", content, re.MULTILINE)
        or re.search(r"^\s*sdk\s*:\s*flutter\s*$", content, re.MULTILINE)
    )


def yaml_scalar(content: str, key: str) -> str:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:\s*(?P<value>.+?)\s*$", re.MULTILINE)
    match = pattern.search(content)
    if not match:
        return ""
    return clean_value(match.group("value").split("#", 1)[0])


def xml_text(content: str, tag_name: str) -> str:
    pattern = rf"<{re.escape(tag_name)}>\s*([^<]+?)\s*</{re.escape(tag_name)}>"
    return regex_value(content, pattern)


def regex_value(content: str, pattern: str | re.Pattern[str]) -> str:
    if isinstance(pattern, str):
        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
    else:
        match = pattern.search(content)
    if not match:
        return ""
    return clean_value(match.group(1))


def confidence_rank(confidence: str) -> int:
    ranks = {"none": 0, "low": 1, "medium": 2, "high": 3}
    try:
        return ranks[confidence]
    except KeyError as exc:
        valid = ", ".join(ranks)
        raise argparse.ArgumentTypeError(f"Invalid confidence {confidence!r}. Use: {valid}") from exc
