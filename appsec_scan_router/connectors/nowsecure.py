from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from typing import Any

from .http import ConnectorError, JsonApiClient, positive_env_int
from .models import (
    ConnectorDefinition,
    ConnectorField,
    ConnectorPullResult,
    ConnectorStatus,
)
from .utils import mapping, sequence
from ..aspm_data import explicit_data_interactions
from ..aspm_ingest import extract_identifiers
from ..aspm_models import (
    FindingDocument,
    FindingInput,
    SourceLocation,
    bounded_text,
    float_or_none,
    normalize_severity,
    string_tuple,
    utc_datetime,
)


DEFAULT_NOWSECURE_API_URL = "https://api.nowsecure.com/graphql"
DEFAULT_NOWSECURE_PAGE_SIZE = 25
MAX_NOWSECURE_APPLICATIONS = 100_000

NOWSECURE_QUERY = """
query InventoryFindings($limit: Int!, $offset: Int!) {
  auto {
    applications(limit: $limit, offset: $offset) {
      ref
      title
      packageKey
      platformType
      group { ref name }
      latestCompleteAssessment {
        ref
        taskId
        createdAt
        score
        releaseVersion
        packageVersion
        platformType
        networkConnectionCountries { alpha2 name }
        report {
          findings {
            key
            title
            description
            summary
            recommendation
            shortRemediation
            impactType
            cvss
            cvssVector
            severity
            status
            findingStatus
            decision
            affected
            uniqueVulnerabilityId
            regulations { type label links { title url } }
            check {
              id
              title
              displayName
              description
              analysisType
              categories
              privacyCategory
              platformType
              issue {
                title
                description
                category
                cve
                cvss
                cvssVector
                severity
                recommendation
                impactSummary
              }
            }
          }
        }
      }
    }
  }
}
""".strip()

NOWSECURE_CONNECTION_QUERY = """
query ConnectionCheck {
    auto {
        applications(limit: 1, offset: 0) { ref }
    }
}
""".strip()


class NowSecureConnector:
    key = "nowsecure"
    name = "NowSecure"
    supports_streaming = True

    def __init__(
        self, timeout_seconds: int = 30, configuration: Mapping[str, Any] | None = None
    ) -> None:
        settings = dict(configuration or {})
        self.token = str(settings.get("token") or "").strip() or os.getenv(
            "APPLICATION_INVENTORY_NOWSECURE_TOKEN", ""
        ).strip() or os.getenv("NOWSECURE_TOKEN", "").strip()
        self.endpoint = str(settings.get("endpoint") or "").strip() or os.getenv(
            "APPLICATION_INVENTORY_NOWSECURE_API_URL", DEFAULT_NOWSECURE_API_URL
        ).strip()
        self.client = (
            JsonApiClient(
                self.endpoint,
                headers={"Authorization": f"Bearer {self.token}"},
                timeout_seconds=timeout_seconds,
            )
            if self.token
            else None
        )

    def status(self) -> ConnectorStatus:
        configured = bool(self.token)
        return ConnectorStatus(
            self.key,
            self.name,
            configured,
            self.endpoint,
            "Ready"
            if configured
            else "APPLICATION_INVENTORY_NOWSECURE_TOKEN is not configured.",
        )

    def close(self) -> None:
        if self.client:
            self.client.close()

    def test_connection(self) -> dict[str, str]:
        if not self.client:
            raise ValueError(self.status().message)
        response = self.client.post("", {"query": NOWSECURE_CONNECTION_QUERY, "variables": {}})
        errors = sequence(response.get("errors"))
        if errors:
            message = bounded_text(mapping(errors[0]).get("message"), 1000)
            raise ConnectorError(f"NowSecure connection check failed: {message}")
        return {"account": "verified"}

    def pull(self) -> ConnectorPullResult:
        findings: list[FindingInput] = []
        targets: dict[str, SourceLocation] = {}
        metadata: dict[str, Any] = {}
        for batch in self.pull_batches():
            findings.extend(batch.findings)
            for target in batch.scanned_targets:
                targets[target.scope_key()] = target
            metadata.update(batch.metadata)
        document = FindingDocument(
            tool_key=self.key,
            tool_name=self.name,
            tool_type="mobile_security",
            source_format="nowsecure-api",
            findings=tuple(findings),
            scanned_targets=tuple(targets.values()),
            complete_snapshot=True,
            metadata=metadata,
        )
        return ConnectorPullResult(
            self.key,
            self.name,
            document,
            len(findings),
            {
                "applications": int(metadata.get("applicationCount", len(targets))),
                "assessments": int(metadata.get("assessmentCount", 0)),
                "targets": len(targets),
            },
        )

    def pull_batches(self) -> Iterator[FindingDocument]:
        if not self.client:
            raise ValueError(self.status().message)
        page_size = min(
            100,
            positive_env_int(
                "APPLICATION_INVENTORY_NOWSECURE_PAGE_SIZE",
                DEFAULT_NOWSECURE_PAGE_SIZE,
            ),
        )
        offset = 0
        application_count = 0
        assessment_count = 0
        finding_count = 0
        targets_seen: set[str] = set()
        while True:
            response = self.client.post(
                "",
                {
                    "query": NOWSECURE_QUERY,
                    "variables": {"limit": page_size, "offset": offset},
                },
            )
            errors = sequence(response.get("errors"))
            if errors:
                message = bounded_text(mapping(errors[0]).get("message"), 1000)
                raise ConnectorError(f"NowSecure GraphQL request failed: {message}")
            raw_batch = sequence(
                mapping(mapping(response.get("data")).get("auto")).get(
                    "applications"
                )
            )
            applications = [mapping(item) for item in raw_batch]
            application_count += len(applications)
            if application_count > MAX_NOWSECURE_APPLICATIONS:
                raise ValueError(
                    "NowSecure sync exceeds the "
                    f"{MAX_NOWSECURE_APPLICATIONS:,}-application safety limit."
                )
            findings: list[FindingInput] = []
            targets: dict[str, SourceLocation] = {}
            for application in applications:
                target = nowsecure_target(application)
                if target.has_asset_anchor():
                    targets[target.scope_key()] = target
                    targets_seen.add(target.scope_key())
                assessment = mapping(application.get("latestCompleteAssessment"))
                if not assessment:
                    continue
                assessment_count += 1
                report = mapping(assessment.get("report"))
                for raw_item in sequence(report.get("findings")):
                    raw = mapping(raw_item)
                    if nowsecure_finding_is_active(raw):
                        findings.append(
                            nowsecure_finding(application, assessment, raw)
                        )
            finding_count += len(findings)
            if findings or targets:
                yield FindingDocument(
                    tool_key=self.key,
                    tool_name=self.name,
                    tool_type="mobile_security",
                    source_format="nowsecure-api",
                    findings=tuple(findings),
                    scanned_targets=tuple(targets.values()),
                    metadata={"api": self.endpoint, "offset": offset},
                )
            if len(applications) < page_size:
                break
            offset += len(applications)
        yield FindingDocument(
            tool_key=self.key,
            tool_name=self.name,
            tool_type="mobile_security",
            source_format="nowsecure-api",
            findings=(),
            complete_snapshot=True,
            metadata={
                "api": self.endpoint,
                "recordsRead": finding_count,
                "applicationCount": application_count,
                "assessmentCount": assessment_count,
                "targetCount": len(targets_seen),
            },
        )


def nowsecure_target(application: dict[str, Any]) -> SourceLocation:
    return SourceLocation.from_mapping(
        {
            "application": application.get("title"),
            "application_identifier": application.get("packageKey"),
        }
    )


def nowsecure_finding_is_active(raw: dict[str, Any]) -> bool:
    if raw.get("affected") is True:
        return True
    values = {
        bounded_text(raw.get("findingStatus"), 100).casefold(),
        bounded_text(raw.get("status"), 100).casefold(),
    }
    return bool(values & {"affected", "detected", "fail", "failed", "warn"})


def nowsecure_finding(
    application: dict[str, Any], assessment: dict[str, Any], raw: dict[str, Any]
) -> FindingInput:
    check = mapping(raw.get("check"))
    issue = mapping(check.get("issue"))
    app_ref = bounded_text(application.get("ref"), 500)
    finding_key = bounded_text(
        raw.get("key") or raw.get("uniqueVulnerabilityId") or check.get("id"), 500
    )
    privacy_labels = [
        check.get("privacyCategory"),
        *string_tuple(check.get("categories")),
        *(mapping(item).get("label") for item in sequence(raw.get("regulations"))),
    ]
    cve_values = (
        issue.get("cve"),
        raw.get("uniqueVulnerabilityId"),
    )
    title = bounded_text(
        raw.get("title")
        or check.get("displayName")
        or check.get("title")
        or issue.get("title")
        or "NowSecure finding",
        1000,
    )
    return FindingInput(
        external_id=f"{app_ref}:{finding_key}" if app_ref else finding_key,
        fingerprint_hint=f"{app_ref}:{finding_key}" if app_ref else finding_key,
        title=title,
        description=bounded_text(
            raw.get("description")
            or raw.get("summary")
            or check.get("description")
            or issue.get("description"),
            20_000,
        ),
        rule_id=bounded_text(check.get("id") or finding_key, 500),
        category=bounded_text(
            issue.get("category") or check.get("analysisType"), 300
        ),
        severity=nowsecure_severity(raw, issue),
        status="open",
        confidence="high" if raw.get("affected") is True else "medium",
        location=nowsecure_target(application),
        remediation=bounded_text(
            raw.get("shortRemediation")
            or raw.get("recommendation")
            or issue.get("recommendation"),
            20_000,
        ),
        cves=extract_identifiers(cve_values, "CVE"),
        package_name=bounded_text(application.get("packageKey"), 500),
        package_version=bounded_text(
            assessment.get("packageVersion") or assessment.get("releaseVersion"), 200
        ),
        cvss_score=float_or_none(raw.get("cvss") or issue.get("cvss"), maximum=10),
        first_seen=utc_datetime(assessment.get("createdAt")),
        last_seen=utc_datetime(assessment.get("createdAt")),
        data_interactions=explicit_data_interactions(
            privacy_labels, "nowsecure_metadata"
        ),
        raw_data={
            **raw,
            "application": {
                "ref": application.get("ref"),
                "title": application.get("title"),
                "packageKey": application.get("packageKey"),
                "platformType": application.get("platformType"),
                "group": application.get("group"),
            },
            "assessment": {
                key: assessment.get(key)
                for key in (
                    "ref",
                    "taskId",
                    "createdAt",
                    "score",
                    "releaseVersion",
                    "packageVersion",
                    "platformType",
                    "networkConnectionCountries",
                )
            },
        },
    )


def nowsecure_severity(raw: dict[str, Any], issue: dict[str, Any]) -> str:
    impact = bounded_text(raw.get("impactType"), 100).casefold()
    if impact == "artifact":
        return "info"
    if impact == "warn":
        return "medium"
    return normalize_severity(
        raw.get("severity") or impact or issue.get("severity") or "medium"
    )


CONNECTOR_DEFINITION = ConnectorDefinition(
    key=NowSecureConnector.key,
    name=NowSecureConnector.name,
    connector_type="hosted_api",
    service_managed=True,
    description="NowSecure mobile application security findings API.",
    fields=(
        ConnectorField("endpoint", "API URL"),
        ConnectorField("token", "API token", required=True, secret=True),
    ),
    factory=NowSecureConnector,
)
