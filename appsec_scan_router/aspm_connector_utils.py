from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urlparse

from .aspm_models import SourceLocation, bounded_text


def mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def sequence(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def case_value(value: Mapping[str, Any], *keys: str) -> Any:
    folded = {str(key).casefold(): item for key, item in value.items()}
    for key in keys:
        if key.casefold() in folded:
            return folded[key.casefold()]
    return None


def repository_location(
    repository_url: Any,
    repository_name: Any = "",
    branch: Any = "",
    **extra: Any,
) -> SourceLocation:
    url = bounded_text(repository_url, 2000)
    name = bounded_text(repository_name, 500).removesuffix(".git")
    values: dict[str, Any] = {
        "repository": name.rsplit("/", 1)[-1],
        "branch": bounded_text(branch, 500).removeprefix("refs/heads/"),
        **extra,
    }
    parsed = urlparse(url)
    parts = [unquote(item) for item in parsed.path.strip("/").split("/") if item]
    host = (parsed.hostname or "").casefold()
    if host in {"github.com", "www.github.com"} and len(parts) >= 2:
        values.update(
            {
                "provider": "github-enterprise",
                "organization": parts[0],
                "repository": parts[1].removesuffix(".git"),
            }
        )
    elif host == "dev.azure.com" and "_git" in parts:
        index = parts.index("_git")
        if index >= 2 and len(parts) > index + 1:
            values.update(
                {
                    "provider": "azure-devops",
                    "organization": parts[0],
                    "project": parts[1],
                    "repository": parts[index + 1].removesuffix(".git"),
                }
            )
    elif host == "dev.azure.com" and "_apis" in parts and "repositories" in parts:
        project, repository = split_project_repository(name)
        if parts:
            values.update(
                {
                    "provider": "azure-devops",
                    "organization": parts[0],
                    "project": project or (parts[1] if len(parts) > 1 else ""),
                    "repository": repository or values["repository"],
                }
            )
    elif len(parts) >= 2 and not values["repository"]:
        values.update(
            {
                "organization": parts[-2],
                "repository": parts[-1].removesuffix(".git"),
            }
        )
    elif "/" in name:
        owner, repository = name.rsplit("/", 1)
        values.update({"organization": owner, "repository": repository})
    return SourceLocation.from_mapping(values)


def split_project_repository(value: str) -> tuple[str, str]:
    if "/" not in value:
        return "", value
    project, repository = value.rsplit("/", 1)
    return project, repository


def merge_location(location: SourceLocation, **values: Any) -> SourceLocation:
    current = {
        "provider": location.provider,
        "organization": location.organization,
        "project": location.project,
        "repository": location.repository,
        "branch": location.branch,
        "path": location.path,
        "start_line": location.start_line,
        "end_line": location.end_line,
        "application": location.application,
        "application_identifier": location.application_identifier,
        "web_url": location.web_url,
    }
    current.update(values)
    return SourceLocation.from_mapping(current)
