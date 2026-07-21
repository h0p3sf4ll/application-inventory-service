from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


SEVERITY_ORDER = {
    FindingSeverity.CRITICAL.value: 5,
    FindingSeverity.HIGH.value: 4,
    FindingSeverity.MEDIUM.value: 3,
    FindingSeverity.LOW.value: 2,
    FindingSeverity.INFO.value: 1,
}

ACTIVE_FINDING_STATUSES = {
    FindingStatus.OPEN.value,
    FindingStatus.TRIAGED.value,
    FindingStatus.IN_PROGRESS.value,
}

FINDING_TRANSITIONS = {
    FindingStatus.OPEN.value: {
        FindingStatus.TRIAGED.value,
        FindingStatus.IN_PROGRESS.value,
        FindingStatus.RESOLVED.value,
        FindingStatus.ACCEPTED.value,
        FindingStatus.FALSE_POSITIVE.value,
    },
    FindingStatus.TRIAGED.value: {
        FindingStatus.OPEN.value,
        FindingStatus.IN_PROGRESS.value,
        FindingStatus.RESOLVED.value,
        FindingStatus.ACCEPTED.value,
        FindingStatus.FALSE_POSITIVE.value,
    },
    FindingStatus.IN_PROGRESS.value: {
        FindingStatus.OPEN.value,
        FindingStatus.TRIAGED.value,
        FindingStatus.RESOLVED.value,
        FindingStatus.ACCEPTED.value,
        FindingStatus.FALSE_POSITIVE.value,
    },
    FindingStatus.RESOLVED.value: {FindingStatus.OPEN.value},
    FindingStatus.ACCEPTED.value: {FindingStatus.OPEN.value},
    FindingStatus.FALSE_POSITIVE.value: {FindingStatus.OPEN.value},
}


@dataclass(frozen=True, slots=True)
class SourceLocation:
    provider: str = ""
    organization: str = ""
    project: str = ""
    repository: str = ""
    branch: str = ""
    path: str = ""
    start_line: int | None = None
    end_line: int | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> SourceLocation:
        item = value or {}
        return cls(
            provider=bounded_text(item.get("provider"), 80),
            organization=bounded_text(
                item.get("organization") or item.get("org") or item.get("owner"),
                300,
            ),
            project=bounded_text(item.get("project"), 500),
            repository=bounded_text(
                item.get("repository") or item.get("repo") or item.get("repo_name"),
                500,
            ),
            branch=bounded_text(
                item.get("branch") or item.get("branch_name") or item.get("ref"),
                500,
            ),
            path=bounded_text(
                item.get("path") or item.get("file") or item.get("component"), 2000
            ),
            start_line=positive_int_or_none(
                item.get("start_line") or item.get("startLine") or item.get("line")
            ),
            end_line=positive_int_or_none(item.get("end_line") or item.get("endLine")),
        )

    def identity(self) -> str:
        return "/".join(
            clean_identity(value)
            for value in (
                self.provider,
                self.organization,
                self.project,
                self.repository,
                self.branch,
                self.path,
            )
        )

    def scope_key(self) -> str:
        return "/".join(
            clean_identity(value)
            for value in (
                self.provider,
                self.organization,
                self.project,
                self.repository,
                self.branch,
            )
        )


@dataclass(frozen=True, slots=True)
class FindingInput:
    external_id: str
    title: str
    severity: str
    status: str = "open"
    location: SourceLocation = field(default_factory=SourceLocation)
    fingerprint_hint: str = ""
    description: str = ""
    rule_id: str = ""
    category: str = ""
    confidence: str = ""
    scanner_url: str = ""
    remediation: str = ""
    cwes: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    package_name: str = ""
    package_version: str = ""
    fixed_version: str = ""
    cvss_score: float | None = None
    epss_score: float | None = None
    exploit_available: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw_data: Mapping[str, Any] = field(default_factory=dict)

    def fingerprint(self, tool_key: str) -> str:
        if self.fingerprint_hint:
            basis = (
                f"{clean_identity(tool_key)}:{clean_identity(self.fingerprint_hint)}"
            )
        elif self.external_id:
            basis = ":".join(
                (
                    clean_identity(tool_key),
                    clean_identity(self.external_id),
                    self.location.scope_key(),
                )
            )
        else:
            basis = ":".join(
                (
                    clean_identity(tool_key),
                    clean_identity(self.rule_id),
                    self.location.identity(),
                    clean_identity(self.package_name),
                    clean_identity(self.title),
                )
            )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def as_raw_json(self) -> dict[str, Any]:
        return json_safe_mapping(self.raw_data)


@dataclass(frozen=True, slots=True)
class FindingDocument:
    tool_key: str
    tool_name: str
    tool_type: str
    source_format: str
    findings: tuple[FindingInput, ...]
    scanned_targets: tuple[SourceLocation, ...] = ()
    complete_snapshot: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    band: str
    factors: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {"score": self.score, "band": self.band, "factors": list(self.factors)}


def normalize_severity(value: Any, default: str = "medium") -> str:
    text = clean_identity(value)
    aliases = {
        "blocker": "critical",
        "fatal": "critical",
        "error": "high",
        "important": "high",
        "major": "medium",
        "warning": "medium",
        "warn": "medium",
        "minor": "low",
        "note": "low",
        "informational": "info",
        "none": "info",
    }
    normalized = aliases.get(text, text)
    return normalized if normalized in SEVERITY_ORDER else default


def normalize_status(value: Any, default: str = "open") -> str:
    text = clean_identity(value)
    aliases = {
        "new": "open",
        "confirmed": "triaged",
        "reopened": "open",
        "in_progress": "in_progress",
        "inprogress": "in_progress",
        "closed": "resolved",
        "fixed": "resolved",
        "dismissed": "false_positive",
        "wont_fix": "accepted",
        "won_t_fix": "accepted",
        "risk_accepted": "accepted",
    }
    normalized = aliases.get(text, text)
    return (
        normalized if normalized in {item.value for item in FindingStatus} else default
    )


def validate_transition(current: str, target: str) -> None:
    normalized_current = normalize_status(current)
    normalized_target = normalize_status(target, "")
    if not normalized_target:
        raise ValueError("Finding status is invalid.")
    if normalized_target == normalized_current:
        return
    if normalized_target not in FINDING_TRANSITIONS.get(normalized_current, set()):
        raise ValueError(
            f"Finding status cannot transition from {normalized_current} to {normalized_target}."
        )


def bounded_text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    return text[:limit]


def clean_identity(value: Any) -> str:
    return re.sub(r"[^a-z0-9._/@+-]+", "_", bounded_text(value, 2000).lower()).strip(
        "_"
    )


def positive_int_or_none(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def float_or_none(
    value: Any, minimum: float = 0.0, maximum: float = 100.0
) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed < minimum or parsed > maximum:
        return None
    return parsed


def utc_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif value:
        try:
            parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def string_tuple(value: Any, limit: int = 50) -> tuple[str, ...]:
    if isinstance(value, str):
        items = re.split(r"[,;]", value)
    elif isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = ()
    return tuple(
        sorted({bounded_text(item, 200) for item in items if bounded_text(item, 200)})[
            :limit
        ]
    )


def json_safe_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        serialized = json.dumps(dict(value), default=str, ensure_ascii=True)
        parsed = json.loads(serialized)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}
