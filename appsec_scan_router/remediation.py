from __future__ import annotations

from collections.abc import Mapping
from typing import Any


REMEDIATION_SEVERITIES = ("critical", "high", "medium", "low", "info")
DEFAULT_REMEDIATION_POLICY = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": 365,
}
MIN_REMEDIATION_DAYS = 1
MAX_REMEDIATION_DAYS = 3_650


def default_remediation_policy() -> dict[str, int]:
    return dict(DEFAULT_REMEDIATION_POLICY)


def normalize_remediation_policy(value: Mapping[str, Any] | None) -> dict[str, int]:
    source = value or {}
    policy: dict[str, int] = {}
    for severity in REMEDIATION_SEVERITIES:
        raw = source.get(severity, DEFAULT_REMEDIATION_POLICY[severity])
        try:
            days = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Remediation timeline for {severity} must be a whole number of days.") from exc
        if not MIN_REMEDIATION_DAYS <= days <= MAX_REMEDIATION_DAYS:
            raise ValueError(
                f"Remediation timeline for {severity} must be between "
                f"{MIN_REMEDIATION_DAYS} and {MAX_REMEDIATION_DAYS} days."
            )
        policy[severity] = days
    return policy


def remediation_days(policy: Mapping[str, Any], severity: str) -> int:
    normalized = normalize_remediation_policy(policy)
    return normalized.get(str(severity or "").casefold(), normalized["medium"])