from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from .aspm_ingest import parse_finding_document
from .aspm_postgres import AspmRepository
from .models import ScanConfig
from .scanner import scan, scan_reports, scan_to_reports


class ApplicationInventoryService:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def scan(
        self, on_result: Callable[[dict[str, Any]], None] | None = None
    ) -> list[dict[str, Any]]:
        return scan(self.config, on_result=on_result)

    def scan_to_reports(self) -> tuple[list[dict[str, Any]], Path, Path, Path]:
        return scan_to_reports(self.config)

    def scan_reports(self) -> tuple[int, Path, Path, Path]:
        return scan_reports(self.config)


AppSecInventoryService = ApplicationInventoryService
AppSecScanRouter = ApplicationInventoryService


class ApplicationSecurityPostureManagementService:
    def __init__(
        self,
        postgres_dsn: str,
        postgres_schema: str,
        owner_user_id: str,
        owner_user_login: str = "",
    ) -> None:
        self.repository = AspmRepository(postgres_dsn, postgres_schema)
        self.owner_user_id = owner_user_id or "anonymous"
        self.owner_user_login = owner_user_login or self.owner_user_id

    def ingest(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.repository.ingest(
            self.owner_user_id,
            self.owner_user_login,
            parse_finding_document(payload),
        )

    def posture(self) -> dict[str, Any]:
        return self.repository.posture(self.owner_user_id)

    def findings(
        self,
        query: str = "",
        filters: dict[str, Any] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        return self.repository.search_findings(
            self.owner_user_id,
            query=query,
            filters=filters,
            limit=limit,
            offset=offset,
        )

    def update_finding(
        self,
        finding_id: str,
        status: str,
        assignee: str = "",
        due_at: Any = None,
        note: str = "",
    ) -> dict[str, Any]:
        return self.repository.update_finding(
            self.owner_user_id,
            self.owner_user_login,
            finding_id,
            status,
            assignee=assignee,
            due_at=due_at,
            note=note,
        )

    def finding(self, finding_id: str) -> dict[str, Any]:
        return self.repository.finding_detail(self.owner_user_id, finding_id)

    def export_findings(
        self,
        export_format: str,
        query: str = "",
        filters: dict[str, Any] | None = None,
    ) -> bytes:
        return self.repository.export_findings(
            self.owner_user_id,
            export_format,
            query=query,
            filters=filters,
        )

    def coverage(self, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        return self.repository.coverage(self.owner_user_id, limit=limit, offset=offset)

    def asset_profile(self, branch_inventory_id: int) -> dict[str, Any]:
        return self.repository.asset_profile(self.owner_user_id, branch_inventory_id)

    def update_asset_profile(
        self, branch_inventory_id: int, profile: dict[str, Any]
    ) -> dict[str, Any]:
        return self.repository.update_asset_profile(
            self.owner_user_id,
            self.owner_user_login,
            branch_inventory_id,
            profile,
        )


AspmService = ApplicationSecurityPostureManagementService
