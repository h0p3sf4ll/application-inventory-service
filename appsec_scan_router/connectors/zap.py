from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from typing import Any
from urllib.parse import urlparse

from .http import JsonApiClient, positive_env_int
from .models import (
    ConnectorDefinition,
    ConnectorField,
    ConnectorPullResult,
    ConnectorStatus,
)
from .utils import mapping, sequence
from ..aspm_ingest import extract_identifiers
from ..aspm_models import FindingDocument, FindingInput, SourceLocation, bounded_text


DEFAULT_ZAP_PAGE_SIZE = 500
MAX_ZAP_ALERTS = 250_000


class ZapConnector:
    key = "zap"
    name = "OWASP ZAP"
    supports_streaming = True

    def __init__(
        self, timeout_seconds: int = 30, configuration: Mapping[str, Any] | None = None
    ) -> None:
        settings = dict(configuration or {})
        self.endpoint = text_value(settings.get("endpoint")) or os.getenv(
            "APPLICATION_INVENTORY_ZAP_API_URL", ""
        ).strip()
        self.api_key = text_value(settings.get("apiKey")) or os.getenv(
            "APPLICATION_INVENTORY_ZAP_API_KEY", ""
        ).strip()
        self.client = JsonApiClient(self.endpoint, timeout_seconds=timeout_seconds) if self.endpoint else None

    def status(self) -> ConnectorStatus:
        return ConnectorStatus(
            self.key,
            self.name,
            bool(self.endpoint),
            self.endpoint,
            "Ready" if self.endpoint else "Configure the ZAP API URL.",
        )

    def close(self) -> None:
        if self.client:
            self.client.close()

    def test_connection(self) -> dict[str, str]:
        if not self.client:
            raise ValueError(self.status().message)
        parameters = {"apikey": self.api_key} if self.api_key else {}
        response = self.client.get("JSON/core/view/version/", parameters)
        return {"version": text_value(response.get("version")) or "verified"}

    def pull(self) -> ConnectorPullResult:
        findings: list[FindingInput] = []
        targets: dict[str, SourceLocation] = {}
        for document in self.pull_batches():
            findings.extend(document.findings)
            for target in document.scanned_targets:
                targets[target.scope_key()] = target
        return ConnectorPullResult(
            self.key,
            self.name,
            FindingDocument(
                tool_key=self.key,
                tool_name=self.name,
                tool_type="dast",
                source_format="zap-api",
                findings=tuple(findings),
                scanned_targets=tuple(targets.values()),
                complete_snapshot=True,
                metadata={"api": self.endpoint},
            ),
            len(findings),
            {"targets": len(targets)},
        )

    def pull_batches(self) -> Iterator[FindingDocument]:
        if not self.client:
            raise ValueError(self.status().message)
        page_size = min(
            1000,
            positive_env_int("APPLICATION_INVENTORY_ZAP_PAGE_SIZE", DEFAULT_ZAP_PAGE_SIZE),
        )
        offset = 0
        total = 0
        while True:
            parameters: dict[str, Any] = {"start": offset, "count": page_size}
            if self.api_key:
                parameters["apikey"] = self.api_key
            response = self.client.get("JSON/core/view/alerts/", parameters)
            alerts = [mapping(item) for item in sequence(response.get("alerts"))]
            findings = tuple(zap_finding(item) for item in alerts)
            total += len(findings)
            if total > MAX_ZAP_ALERTS:
                raise ValueError(f"OWASP ZAP sync exceeds the {MAX_ZAP_ALERTS:,}-alert safety limit.")
            targets = {
                target.scope_key(): target
                for item in alerts
                if (target := zap_target(item)).has_asset_anchor()
            }
            if findings or targets:
                yield FindingDocument(
                    tool_key=self.key,
                    tool_name=self.name,
                    tool_type="dast",
                    source_format="zap-api",
                    findings=findings,
                    scanned_targets=tuple(targets.values()),
                    metadata={"api": self.endpoint, "offset": offset},
                )
            if len(alerts) < page_size:
                break
            offset += len(alerts)
        yield FindingDocument(
            tool_key=self.key,
            tool_name=self.name,
            tool_type="dast",
            source_format="zap-api",
            findings=(),
            complete_snapshot=True,
            metadata={"api": self.endpoint, "recordsRead": total},
        )


def zap_finding(alert: Mapping[str, Any]) -> FindingInput:
    location = zap_target(alert)
    risk = text_value(alert.get("risk") or alert.get("riskdesc") or alert.get("riskcode"))
    plugin_id = text_value(alert.get("pluginId"))
    alert_ref = text_value(alert.get("alertRef"))
    cwe_value = text_value(alert.get("cweid"))
    cwes = extract_identifiers(
        f"CWE-{cwe_value}" if cwe_value.isdigit() and cwe_value != "0" else cwe_value,
        "CWE",
    )
    return FindingInput(
        external_id=alert_ref or f"{plugin_id}:{location.web_url}",
        title=bounded_text(alert.get("alert") or "OWASP ZAP alert", 1000),
        severity=zap_severity(risk),
        status="open",
        location=location,
        rule_id=bounded_text(plugin_id, 500),
        category="dast",
        description=bounded_text(alert.get("description"), 20_000),
        remediation=bounded_text(alert.get("solution"), 20_000),
        cwes=cwes,
        scanner_url=location.web_url,
        raw_data=dict(alert),
    )


def zap_target(alert: Mapping[str, Any]) -> SourceLocation:
    url = text_value(alert.get("url"))
    parsed = urlparse(url)
    return SourceLocation(application=parsed.hostname or "", web_url=url)


def zap_severity(value: str) -> str:
    lowered = value.casefold()
    if "high" in lowered or lowered == "3":
        return "high"
    if "medium" in lowered or lowered == "2":
        return "medium"
    if "low" in lowered or lowered == "1":
        return "low"
    return "info"


def text_value(value: Any) -> str:
    return str(value or "").strip()


CONNECTOR_DEFINITION = ConnectorDefinition(
    key=ZapConnector.key,
    name=ZapConnector.name,
    connector_type="self_hosted_api",
    service_managed=False,
    description="OWASP ZAP alerts API for dynamic application security testing.",
    fields=(
        ConnectorField("endpoint", "ZAP API URL", required=True),
        ConnectorField("apiKey", "API key", secret=True),
    ),
    factory=ZapConnector,
)