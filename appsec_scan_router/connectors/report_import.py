from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import (
    ConnectorDefinition,
    ConnectorField,
    ConnectorPullResult,
    ConnectorStatus,
)


class ReportImportConnector:
    supports_streaming = False

    def __init__(
        self,
        key: str,
        name: str,
        configuration: Mapping[str, Any] | None = None,
        report_format: str = "SARIF",
    ) -> None:
        self.key = key
        self.name = name
        self.report_path = str(dict(configuration or {}).get("reportPath") or "").strip()
        self.report_format = report_format

    def status(self) -> ConnectorStatus:
        return ConnectorStatus(
            self.key,
            self.name,
            bool(self.report_path),
            self.report_path,
            f"Configured for {self.report_format} import. Upload the report from Findings."
            if self.report_path
            else (
                f"Configure a {self.report_format} report path, then upload the report "
                "from Findings."
            ),
        )

    def pull(self) -> ConnectorPullResult:
        raise ValueError("This scanner is imported from a report and cannot be synchronized remotely.")

    def close(self) -> None:
        return None


def report_import_connector_definition(
    key: str,
    name: str,
    description: str,
    *,
    report_format: str = "SARIF",
    report_path_label: str = "SARIF report path",
    connector_type: str = "sarif_profile",
) -> ConnectorDefinition:
    def factory(
        _timeout_seconds: int, configuration: Mapping[str, Any] | None = None
    ) -> ReportImportConnector:
        return ReportImportConnector(key, name, configuration, report_format)

    return ConnectorDefinition(
        key=key,
        name=name,
        connector_type=connector_type,
        service_managed=False,
        description=description,
        fields=(ConnectorField("reportPath", report_path_label, required=True),),
        factory=factory,
        remote_sync=False,
        import_format=report_format,
    )