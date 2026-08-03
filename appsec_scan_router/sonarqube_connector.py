from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from typing import Any

from .aspm_connector_http import JsonApiClient, positive_env_int
from .aspm_connector_models import ConnectorPullResult, ConnectorStatus
from .aspm_connector_utils import mapping, sequence
from .aspm_models import FindingDocument, FindingInput, SourceLocation, bounded_text


DEFAULT_SONARQUBE_PAGE_SIZE = 500
MAX_SONARQUBE_FINDINGS = 500_000


class SonarQubeConnector:
    key = "sonarqube"
    name = "SonarQube"
    supports_streaming = True

    def __init__(
        self, timeout_seconds: int = 30, configuration: Mapping[str, Any] | None = None
    ) -> None:
        settings = dict(configuration or {})
        self.endpoint = text_value(settings.get("endpoint")) or os.getenv(
            "APPLICATION_INVENTORY_SONARQUBE_URL", ""
        ).strip()
        self.token = text_value(settings.get("token")) or os.getenv(
            "APPLICATION_INVENTORY_SONARQUBE_TOKEN", ""
        ).strip()
        self.client = (
            JsonApiClient(
                self.endpoint,
                auth=(self.token, ""),
                timeout_seconds=timeout_seconds,
            )
            if self.endpoint and self.token
            else None
        )

    def status(self) -> ConnectorStatus:
        missing = []
        if not self.endpoint:
            missing.append("server URL")
        if not self.token:
            missing.append("token")
        return ConnectorStatus(
            self.key,
            self.name,
            not missing,
            self.endpoint,
            "Ready" if not missing else f"Configure {' and '.join(missing)}.",
        )

    def close(self) -> None:
        if self.client:
            self.client.close()

    def test_connection(self) -> dict[str, str]:
        if not self.client:
            raise ValueError(self.status().message)
        response = self.client.get("api/system/status")
        return {"status": text_value(response.get("status")) or "verified"}

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
                tool_type="sast",
                source_format="sonarqube-api",
                findings=tuple(findings),
                scanned_targets=tuple(targets.values()),
                complete_snapshot=True,
                metadata={"api": self.endpoint},
            ),
            len(findings),
            {"projects": len(targets)},
        )

    def pull_batches(self) -> Iterator[FindingDocument]:
        if not self.client:
            raise ValueError(self.status().message)
        page_size = min(
            500,
            positive_env_int(
                "APPLICATION_INVENTORY_SONARQUBE_PAGE_SIZE", DEFAULT_SONARQUBE_PAGE_SIZE
            ),
        )
        page = 1
        total = 0
        while True:
            response = self.client.get(
                "api/issues/search",
                {
                    "p": page,
                    "ps": page_size,
                    "resolved": "false",
                    "additionalFields": "_all",
                },
            )
            issues = [mapping(item) for item in sequence(response.get("issues"))]
            findings = tuple(sonarqube_finding(item, self.endpoint) for item in issues)
            total += len(findings)
            if total > MAX_SONARQUBE_FINDINGS:
                raise ValueError(
                    f"SonarQube sync exceeds the {MAX_SONARQUBE_FINDINGS:,}-finding safety limit."
                )
            targets = {
                target.scope_key(): target
                for item in issues
                if (target := sonarqube_target(item)).has_asset_anchor()
            }
            if findings or targets:
                yield FindingDocument(
                    tool_key=self.key,
                    tool_name=self.name,
                    tool_type="sast",
                    source_format="sonarqube-api",
                    findings=findings,
                    scanned_targets=tuple(targets.values()),
                    metadata={"api": self.endpoint, "page": page},
                )
            reported_total = integer_value(response.get("total"))
            if not issues or len(issues) < page_size or (reported_total and page * page_size >= reported_total):
                break
            page += 1
        yield FindingDocument(
            tool_key=self.key,
            tool_name=self.name,
            tool_type="sast",
            source_format="sonarqube-api",
            findings=(),
            complete_snapshot=True,
            metadata={"api": self.endpoint, "recordsRead": total},
        )


def sonarqube_finding(issue: Mapping[str, Any], endpoint: str = "") -> FindingInput:
    component = text_value(issue.get("component"))
    project, path = component_parts(component)
    location = SourceLocation(
        application=project,
        repository=project,
        path=path,
        start_line=integer_value(issue.get("line")) or None,
    )
    rule = text_value(issue.get("rule"))
    return FindingInput(
        external_id=text_value(issue.get("key")) or rule,
        title=bounded_text(issue.get("message") or rule or "SonarQube issue", 1000),
        severity=sonarqube_severity(issue.get("severity")),
        status="open",
        location=location,
        rule_id=bounded_text(rule, 500),
        category=bounded_text(issue.get("type"), 300),
        scanner_url=issue_url(endpoint, issue.get("key")),
        remediation=bounded_text(issue.get("message"), 20_000),
        raw_data=dict(issue),
    )


def sonarqube_target(issue: Mapping[str, Any]) -> SourceLocation:
    project, _ = component_parts(text_value(issue.get("component")))
    return SourceLocation(application=project, repository=project)


def sonarqube_severity(value: Any) -> str:
    return {
        "BLOCKER": "critical",
        "CRITICAL": "critical",
        "MAJOR": "high",
        "MINOR": "medium",
        "INFO": "info",
    }.get(text_value(value).upper(), "medium")


def component_parts(value: str) -> tuple[str, str]:
    project, separator, path = value.partition(":")
    return project, path if separator else ""


def issue_url(endpoint: str, issue_key: Any) -> str:
    key = text_value(issue_key)
    return f"{endpoint.rstrip('/')}/project/issues?id={key}" if endpoint and key else ""


def integer_value(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def text_value(value: Any) -> str:
    return str(value or "").strip()