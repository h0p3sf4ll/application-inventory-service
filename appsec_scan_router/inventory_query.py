from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from .constants import APPLICATION_TYPE_LABELS, KNOWN_INVENTORY_TYPES


PROVIDERS = frozenset({"azure-devops", "github-enterprise"})
CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})
DOMAIN_STATUSES = frozenset({"confirmed", "configured", "inferred", "not_detected"})
SORT_FIELDS = frozenset(
    {
        "application",
        "branch",
        "confidence",
        "domain",
        "repository",
        "source",
        "types",
        "updated",
    }
)
SORT_DIRECTIONS = frozenset({"asc", "desc"})
EXPORT_FORMATS = frozenset({"csv", "json", "xlsx"})
QUERY_FIELDS = frozenset(
    {
        "text",
        "application_search",
        "repository_search",
        "branch_search",
        "domain_search",
        "providers",
        "organizations",
        "projects",
        "repositories",
        "application_types",
        "languages",
        "confidences",
        "domain_statuses",
        "updated_within_days",
        "older_than_days",
        "has_domain",
        "has_mobile_identifier",
        "store_validation_passed",
        "sort_by",
        "sort_direction",
    }
)


def repository_browse_url(record: Mapping[str, Any]) -> str:
    for field in ("web_url", "source_url"):
        url = canonical_repository_url(record.get(field))
        if url:
            return url
    return ""


def canonical_repository_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw or "\\" in raw or any(ord(character) < 32 for character in raw):
        return ""
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not hostname:
        return ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port is not None else host
    path = parsed.path[:-4] if parsed.path.lower().endswith(".git") else parsed.path
    return urlunsplit((scheme, netloc, path or "/", "", ""))


@dataclass(frozen=True, slots=True)
class InventorySearchCriteria:
    text: str = ""
    application_search: str = ""
    repository_search: str = ""
    branch_search: str = ""
    domain_search: str = ""
    providers: tuple[str, ...] = ()
    organizations: tuple[str, ...] = ()
    projects: tuple[str, ...] = ()
    repositories: tuple[str, ...] = ()
    application_types: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    confidences: tuple[str, ...] = ()
    domain_statuses: tuple[str, ...] = ()
    updated_within_days: int | None = None
    older_than_days: int | None = None
    has_domain: bool | None = None
    has_mobile_identifier: bool | None = None
    store_validation_passed: bool | None = None
    sort_by: str = "updated"
    sort_direction: str = "desc"

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any] | None = None,
        text: str = "",
    ) -> InventorySearchCriteria:
        source = value if isinstance(value, Mapping) else {}
        return cls(
            text=clean_query_text(text or source.get("text")),
            application_search=clean_filter_text(source.get("application_search")),
            repository_search=clean_filter_text(source.get("repository_search")),
            branch_search=clean_filter_text(source.get("branch_search")),
            domain_search=clean_filter_text(source.get("domain_search")),
            providers=choice_values(source.get("providers"), PROVIDERS),
            organizations=text_values(source.get("organizations")),
            projects=text_values(source.get("projects")),
            repositories=text_values(source.get("repositories")),
            application_types=choice_values(
                source.get("application_types"), frozenset(KNOWN_INVENTORY_TYPES)
            ),
            languages=text_values(source.get("languages")),
            confidences=choice_values(source.get("confidences"), CONFIDENCE_LEVELS),
            domain_statuses=choice_values(
                source.get("domain_statuses"), DOMAIN_STATUSES
            ),
            updated_within_days=bounded_days(source.get("updated_within_days")),
            older_than_days=bounded_days(source.get("older_than_days")),
            has_domain=optional_bool(source.get("has_domain")),
            has_mobile_identifier=optional_bool(source.get("has_mobile_identifier")),
            store_validation_passed=optional_bool(
                source.get("store_validation_passed")
            ),
            sort_by=choice(source.get("sort_by"), SORT_FIELDS, "updated"),
            sort_direction=choice(
                source.get("sort_direction"), SORT_DIRECTIONS, "desc"
            ),
        )

    def with_text(self, text: str) -> InventorySearchCriteria:
        return replace(self, text=clean_query_text(text))

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "application_search": self.application_search,
            "repository_search": self.repository_search,
            "branch_search": self.branch_search,
            "domain_search": self.domain_search,
            "providers": list(self.providers),
            "organizations": list(self.organizations),
            "projects": list(self.projects),
            "repositories": list(self.repositories),
            "application_types": list(self.application_types),
            "languages": list(self.languages),
            "confidences": list(self.confidences),
            "domain_statuses": list(self.domain_statuses),
            "updated_within_days": self.updated_within_days,
            "older_than_days": self.older_than_days,
            "has_domain": self.has_domain,
            "has_mobile_identifier": self.has_mobile_identifier,
            "store_validation_passed": self.store_validation_passed,
            "sort_by": self.sort_by,
            "sort_direction": self.sort_direction,
        }


@dataclass(frozen=True, slots=True)
class InventoryQueryPlan:
    criteria: InventorySearchCriteria
    action: str = "search"
    export_format: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> InventoryQueryPlan:
        action = choice(value.get("action"), frozenset({"search", "export"}), "search")
        export_format = (
            choice(value.get("export_format"), EXPORT_FORMATS, "xlsx")
            if action == "export"
            else ""
        )
        return cls(
            criteria=InventorySearchCriteria.from_mapping(value),
            action=action,
            export_format=export_format,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "filters": self.criteria.as_dict(),
            "action": self.action,
            "exportFormat": self.export_format,
            "summary": criteria_summary(self.criteria),
        }


def criteria_summary(criteria: InventorySearchCriteria) -> str:
    parts: list[str] = []
    if criteria.application_types:
        parts.append(
            ", ".join(
                APPLICATION_TYPE_LABELS.get(value, value.replace("_", " ").title())
                for value in criteria.application_types
            )
        )
    if criteria.providers:
        parts.append(
            ", ".join(value.replace("-", " ").title() for value in criteria.providers)
        )
    if criteria.organizations:
        parts.append(f"organizations: {', '.join(criteria.organizations)}")
    if criteria.repositories:
        parts.append(f"repositories: {', '.join(criteria.repositories)}")
    if criteria.languages:
        parts.append(f"languages: {', '.join(criteria.languages)}")
    if criteria.confidences:
        parts.append(f"confidence: {', '.join(criteria.confidences)}")
    if criteria.updated_within_days is not None:
        parts.append(f"updated within {criteria.updated_within_days} days")
    if criteria.older_than_days is not None:
        parts.append(f"older than {criteria.older_than_days} days")
    if criteria.has_domain is not None:
        parts.append(
            "with a web domain" if criteria.has_domain else "without a web domain"
        )
    if criteria.has_mobile_identifier is not None:
        parts.append(
            "with a mobile identifier"
            if criteria.has_mobile_identifier
            else "without a mobile identifier"
        )
    if criteria.store_validation_passed is not None:
        parts.append(
            "store validation passed"
            if criteria.store_validation_passed
            else "store validation not passed"
        )
    if criteria.text:
        parts.append(f'text: "{criteria.text}"')
    for label, value in (
        ("application", criteria.application_search),
        ("repository", criteria.repository_search),
        ("branch", criteria.branch_search),
        ("domain", criteria.domain_search),
    ):
        if value:
            parts.append(f'{label} contains "{value}"')
    return "; ".join(parts) if parts else "All inventory records"


def clean_query_text(value: Any) -> str:
    return " ".join(str(value or "").split())[:500]


def clean_filter_text(value: Any) -> str:
    return " ".join(str(value or "").split())[:120]


def text_values(value: Any, limit: int = 20) -> tuple[str, ...]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        return ()
    cleaned = {" ".join(str(item or "").split())[:120] for item in values}
    return tuple(sorted(item for item in cleaned if item)[:limit])


def choice_values(value: Any, allowed: frozenset[str]) -> tuple[str, ...]:
    return tuple(item for item in text_values(value) if item in allowed)


def choice(value: Any, allowed: frozenset[str], default: str) -> str:
    cleaned = str(value or "").strip().lower()
    return cleaned if cleaned in allowed else default


def bounded_days(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        days = int(value)
    except (TypeError, ValueError):
        return None
    return max(1, min(days, 3650))


def optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return None
    cleaned = str(value).strip().lower()
    if cleaned in {"1", "true", "yes", "on"}:
        return True
    if cleaned in {"0", "false", "no", "off"}:
        return False
    return None
