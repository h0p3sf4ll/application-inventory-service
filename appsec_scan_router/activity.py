from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from .models import RepoActivityMetadata
from .utils import clean_value


def extract_repo_activity(commits: Iterable[dict[str, Any]]) -> RepoActivityMetadata:
    developers_by_key: dict[str, str] = {}
    latest: datetime | None = None

    for commit in commits:
        author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
        committer = commit.get("committer") if isinstance(commit.get("committer"), dict) else {}
        developer = format_developer(author) or format_developer(committer)
        if developer:
            developers_by_key.setdefault(developer_identity_key(author, developer), developer)

        commit_datetime = parse_ado_datetime(committer.get("date") or author.get("date"))
        if commit_datetime and (latest is None or commit_datetime > latest):
            latest = commit_datetime

    return RepoActivityMetadata(
        contributing_developers=tuple(sorted(developers_by_key.values(), key=lambda value: value.lower())),
        last_updated=format_ado_datetime(latest),
    )


def format_developer(person: dict[str, Any]) -> str:
    name = clean_value(person.get("name"))
    email = clean_value(person.get("email"))
    if name and email:
        return f"{name} <{email}>"
    return name or email


def developer_identity_key(person: dict[str, Any], fallback: str) -> str:
    email = clean_value(person.get("email")).lower()
    if email:
        return email
    return fallback.lower()


def parse_ado_datetime(value: Any) -> datetime | None:
    text = clean_value(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_ado_datetime(value: datetime | None) -> str:
    if value is None:
        return ""
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")
