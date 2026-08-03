from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .aspm_connector_models import ConnectorPullResult, ConnectorStatus


class ReportImportConnector:
    supports_streaming = False

    def __init__(
        self, key: str, name: str, configuration: Mapping[str, Any] | None = None
    ) -> None:
        self.key = key
        self.name = name
        self.report_path = str(dict(configuration or {}).get("reportPath") or "").strip()

    def status(self) -> ConnectorStatus:
        return ConnectorStatus(
            self.key,
            self.name,
            bool(self.report_path),
            self.report_path,
            "Configured for SARIF import. Upload the report from Findings."
            if self.report_path
            else "Configure a SARIF report path, then upload the report from Findings.",
        )

    def pull(self) -> ConnectorPullResult:
        raise ValueError("This scanner is imported from a report and cannot be synchronized remotely.")

    def close(self) -> None:
        return None