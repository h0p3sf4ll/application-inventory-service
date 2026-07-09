from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .constants import (
    DEFAULT_ACTIVITY_MODE,
    DEFAULT_BRANCH_AGE_DAYS,
    DEFAULT_BRANCH_WORKERS,
    DEFAULT_POSTGRES_SCHEMA,
    DEFAULT_POSTGRES_TABLE,
    DEFAULT_STORE_COUNTRY,
    DEFAULT_STORE_TIMEOUT_SECONDS,
)


class AzureDevOpsError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class AzureDevOpsOrgPat:
    org: str
    pat: str


@dataclass(frozen=True)
class SourceTargetFilter:
    org: str
    project: str


@dataclass(frozen=True)
class ScanConfig:
    org: str
    pat: str
    project: str | None
    out_dir: Path
    out_prefix: str
    max_workers: int
    content_workers: int
    max_commits_per_repo: int
    timeout_seconds: int
    min_confidence: str
    branch_workers: int = DEFAULT_BRANCH_WORKERS
    branch_age_days: int = DEFAULT_BRANCH_AGE_DAYS
    activity_mode: str = DEFAULT_ACTIVITY_MODE
    store_lookup: bool = False
    store_country: str = DEFAULT_STORE_COUNTRY
    store_timeout_seconds: int = DEFAULT_STORE_TIMEOUT_SECONDS
    provider: str = "azure-devops"
    base_url: str = ""
    application_types: tuple[str, ...] = ()
    postgres_dsn: str = ""
    postgres_schema: str = DEFAULT_POSTGRES_SCHEMA
    postgres_table: str = DEFAULT_POSTGRES_TABLE
    owner_user_id: str = "anonymous"
    owner_user_login: str = "anonymous"
    ado_org_pats: tuple[AzureDevOpsOrgPat, ...] = ()
    target_filters: tuple[SourceTargetFilter, ...] = ()
    github_app_id: str = ""
    github_app_installation_id: str = ""
    github_app_private_key: str = ""
    github_app_private_key_file: str = ""


@dataclass(frozen=True)
class RepoScanTarget:
    project_name: str
    repo: dict[str, Any]
    organization: str = ""
    provider: str = "azure-devops"


@dataclass(frozen=True)
class BranchScanTarget:
    project_name: str
    repo: dict[str, Any]
    branch_name: str
    organization: str = ""
    provider: str = "azure-devops"


@dataclass(frozen=True)
class MobileAppMetadata:
    name: str = ""
    version: str = ""
    identifier: str = ""
    identifier_source: str = ""


@dataclass(frozen=True)
class RepoActivityMetadata:
    contributing_developers: tuple[str, ...] = ()
    last_updated: str = ""


@dataclass(frozen=True)
class StoreListing:
    platform: str
    status: str
    name: str = ""
    identifier: str = ""
    url: str = ""
    version: str = ""
    last_updated: str = ""
    error: str = ""


@dataclass(frozen=True)
class DetectionEvidence:
    category: str
    source: str
    detail: str
    weight: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "source": self.source,
            "detail": self.detail,
            "weight": self.weight,
        }
