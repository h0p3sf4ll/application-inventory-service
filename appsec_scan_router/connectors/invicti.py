from __future__ import annotations

import os
from collections import deque
from collections.abc import Iterator, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock, local
from typing import Any

from .http import JsonApiClient, positive_env_int
from .models import (
    ConnectorDefinition,
    ConnectorField,
    ConnectorPullResult,
    ConnectorStatus,
)
from .utils import case_value, mapping, sequence
from ..aspm_ingest import extract_identifiers
from ..aspm_models import (
    FindingDocument,
    FindingInput,
    SourceLocation,
    bounded_text,
    float_or_none,
    normalize_severity,
    normalize_status,
    string_tuple,
    utc_datetime,
)


MAX_INVICTI_FINDINGS = 250_000
DEFAULT_INVICTI_API_URL = "https://www.netsparkercloud.com/api/1.0"
DEFAULT_INVICTI_WORKERS = 2
DEFAULT_INVICTI_BATCH_PAGES = 10
DEFAULT_INVICTI_TIMEOUT_SECONDS = 120
MAX_INVICTI_WORKERS = 16
MAX_INVICTI_BATCH_PAGES = 25
INVICTI_PAGE_SIZE = 200


class InvictiConnector:
    key = "invicti"
    name = "Invicti"
    supports_streaming = True

    def __init__(
        self, timeout_seconds: int = 30, configuration: Mapping[str, Any] | None = None
    ) -> None:
        settings = dict(configuration or {})
        self.user_id = str(settings.get("userId") or "").strip() or os.getenv(
            "APPLICATION_INVENTORY_INVICTI_USER_ID", ""
        ).strip() or os.getenv("INVICTI_USER_ID", "").strip()
        self.token = str(settings.get("token") or "").strip() or os.getenv("APPLICATION_INVENTORY_INVICTI_TOKEN", "").strip() or os.getenv(
            "INVICTI_TOKEN", ""
        ).strip()
        self.endpoint = str(settings.get("endpoint") or "").strip() or os.getenv(
            "APPLICATION_INVENTORY_INVICTI_API_URL", ""
        ).strip() or os.getenv(
            "INVICTI_API_URL", ""
        ).strip() or DEFAULT_INVICTI_API_URL
        self.worker_count = min(
            MAX_INVICTI_WORKERS,
            positive_env_int(
                "APPLICATION_INVENTORY_INVICTI_WORKERS",
                DEFAULT_INVICTI_WORKERS,
            ),
        )
        self._worker_local = local()
        self._worker_clients: list[JsonApiClient] = []
        self._worker_clients_lock = Lock()
        request_timeout = max(
            int(timeout_seconds),
            positive_env_int(
                "APPLICATION_INVENTORY_INVICTI_TIMEOUT_SECONDS",
                DEFAULT_INVICTI_TIMEOUT_SECONDS,
            ),
        )
        self.client = (
            JsonApiClient(
                self.endpoint,
                auth=(self.user_id, self.token),
                timeout_seconds=request_timeout,
            )
            if self.endpoint and self.user_id and self.token
            else None
        )

    def status(self) -> ConnectorStatus:
        missing = []
        if not self.endpoint:
            missing.append("APPLICATION_INVENTORY_INVICTI_API_URL")
        if not self.user_id:
            missing.append("APPLICATION_INVENTORY_INVICTI_USER_ID")
        if not self.token:
            missing.append("APPLICATION_INVENTORY_INVICTI_TOKEN")
        return ConnectorStatus(
            self.key,
            self.name,
            not missing,
            self.endpoint,
            "Ready" if not missing else f"Configure {', '.join(missing)}.",
        )

    def close(self) -> None:
        if self.client:
            self.client.close()
        self._close_worker_clients()

    def test_connection(self) -> dict[str, str]:
        if not self.client:
            raise ValueError(self.status().message)
        self.client.get("account/license")
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
            tool_type="dast",
            source_format="invicti-api",
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
            {"targets": int(metadata.get("targetCount", len(targets)))},
        )

    def pull_batches(self) -> Iterator[FindingDocument]:
        if not self.client:
            raise ValueError(self.status().message)
        self.client.get("account/license")
        total = 0
        targets_seen: set[str] = set()
        batch_pages = min(
            MAX_INVICTI_BATCH_PAGES,
            positive_env_int(
                "APPLICATION_INVENTORY_INVICTI_BATCH_PAGES",
                DEFAULT_INVICTI_BATCH_PAGES,
            ),
        )
        first_response = self._fetch_page(1, self.client)
        total_count = integer_value(case_value(first_response, "TotalItemCount"))
        if total_count > MAX_INVICTI_FINDINGS:
            raise ValueError(
                f"Invicti sync exceeds the {MAX_INVICTI_FINDINGS:,}-finding safety limit."
            )
        page_count = integer_value(case_value(first_response, "PageCount"))
        if page_count:
            pages = self._prefetched_pages(first_response, page_count)
        else:
            pages = self._sequential_pages(first_response)
        pending_findings: list[FindingInput] = []
        pending_targets: dict[str, SourceLocation] = {}
        first_pending_page = 1
        pages_pending = 0
        for page, response in pages:
            raw_batch = [mapping(item) for item in sequence(case_value(response, "List"))]
            findings = tuple(invicti_finding(raw) for raw in raw_batch)
            targets: dict[str, SourceLocation] = {}
            for raw in raw_batch:
                target = SourceLocation.from_mapping(
                    {
                        "application": case_value(raw, "WebsiteName"),
                        "web_url": case_value(raw, "WebsiteRootUrl"),
                    }
                )
                if target.has_asset_anchor():
                    targets[target.scope_key()] = target
                    targets_seen.add(target.scope_key())
            total += len(findings)
            if total > MAX_INVICTI_FINDINGS:
                raise ValueError(
                    f"Invicti sync exceeds the {MAX_INVICTI_FINDINGS:,}-finding safety limit."
                )
            pending_findings.extend(findings)
            pending_targets.update(targets)
            pages_pending += 1
            if pages_pending >= batch_pages:
                yield FindingDocument(
                    tool_key=self.key,
                    tool_name=self.name,
                    tool_type="dast",
                    source_format="invicti-api",
                    findings=tuple(pending_findings),
                    scanned_targets=tuple(pending_targets.values()),
                    metadata={
                        "api": self.endpoint,
                        "pageStart": first_pending_page,
                        "pageEnd": page,
                    },
                )
                pending_findings.clear()
                pending_targets.clear()
                pages_pending = 0
                first_pending_page = page + 1
        if pending_findings or pending_targets:
            yield FindingDocument(
                tool_key=self.key,
                tool_name=self.name,
                tool_type="dast",
                source_format="invicti-api",
                findings=tuple(pending_findings),
                scanned_targets=tuple(pending_targets.values()),
                metadata={
                    "api": self.endpoint,
                    "pageStart": first_pending_page,
                    "pageEnd": page,
                },
            )
        yield FindingDocument(
            tool_key=self.key,
            tool_name=self.name,
            tool_type="dast",
            source_format="invicti-api",
            findings=(),
            complete_snapshot=True,
            metadata={
                "api": self.endpoint,
                "recordsRead": total,
                "targetCount": len(targets_seen),
            },
        )

    def _fetch_page(
        self, page: int, client: JsonApiClient | None = None
    ) -> dict[str, Any]:
        api_client = client or self._worker_client()
        return api_client.get(
            "issues/allissues",
            {
                "page": page,
                "pageSize": INVICTI_PAGE_SIZE,
                "sortType": "Descending",
                "rawDetails": "false",
            },
        )

    def _prefetched_pages(
        self, first_response: dict[str, Any], page_count: int
    ) -> Iterator[tuple[int, dict[str, Any]]]:
        yield 1, first_response
        if page_count <= 1:
            return
        executor = ThreadPoolExecutor(
            max_workers=self.worker_count,
            thread_name_prefix="invicti",
        )
        pending: deque[tuple[int, Future[dict[str, Any]]]] = deque()
        next_page = 2
        window = self.worker_count * 2
        try:
            while next_page <= page_count and len(pending) < window:
                pending.append((next_page, executor.submit(self._fetch_page, next_page)))
                next_page += 1
            while pending:
                page, future = pending.popleft()
                yield page, future.result()
                if next_page <= page_count:
                    pending.append(
                        (next_page, executor.submit(self._fetch_page, next_page))
                    )
                    next_page += 1
        finally:
            for _, future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            self._close_worker_clients()

    def _sequential_pages(
        self, first_response: dict[str, Any]
    ) -> Iterator[tuple[int, dict[str, Any]]]:
        page = 1
        response = first_response
        while True:
            yield page, response
            if (
                not sequence(case_value(response, "List"))
                or case_value(response, "IsLastPage") is True
            ):
                return
            page += 1
            response = self._fetch_page(page, self.client)

    def _worker_client(self) -> JsonApiClient:
        client = getattr(self._worker_local, "client", None)
        if client is None:
            client = JsonApiClient(
                self.endpoint,
                auth=(self.user_id, self.token),
                timeout_seconds=self.client.timeout_seconds,
            )
            self._worker_local.client = client
            with self._worker_clients_lock:
                self._worker_clients.append(client)
        return client

    def _close_worker_clients(self) -> None:
        with self._worker_clients_lock:
            clients = tuple(self._worker_clients)
            self._worker_clients.clear()
        for client in clients:
            client.close()


def integer_value(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def invicti_finding(raw: dict[str, Any]) -> FindingInput:
    state = bounded_text(case_value(raw, "State"), 100)
    is_present = case_value(raw, "IsPresent")
    is_addressed = case_value(raw, "IsAddressed")
    status = "resolved" if is_present is False else normalize_status(state or "open")
    if status == "open" and is_addressed is True:
        status = "triaged"
    classification_links = string_tuple(case_value(raw, "ClassificationLinks"))
    cwe_values = (
        case_value(raw, "Classification"),
        case_value(raw, "Type"),
        case_value(raw, "VulnerabilityDetail"),
        classification_links,
    )
    cve_values = (
        case_value(raw, "VulnerabilityDetail"),
        case_value(raw, "ExternalReferences"),
        classification_links,
    )
    title = bounded_text(case_value(raw, "Title") or "Invicti finding", 1000)
    return FindingInput(
        external_id=bounded_text(case_value(raw, "Id"), 500),
        title=title,
        description=bounded_text(case_value(raw, "VulnerabilityDetail"), 20_000),
        rule_id=bounded_text(case_value(raw, "Type"), 500),
        category=bounded_text(case_value(raw, "Classification"), 300),
        severity=normalize_severity(case_value(raw, "Severity") or "medium"),
        status=status,
        confidence=invicti_confidence(case_value(raw, "Certainty")),
        location=SourceLocation.from_mapping(
            {
                "application": case_value(raw, "WebsiteName"),
                "web_url": case_value(raw, "WebsiteRootUrl"),
                "path": case_value(raw, "Url"),
            }
        ),
        scanner_url=bounded_text(case_value(raw, "Url"), 2000),
        remediation=bounded_text(case_value(raw, "Remedy"), 20_000),
        cwes=extract_identifiers(cwe_values, "CWE"),
        cves=extract_identifiers(cve_values, "CVE"),
        cvss_score=invicti_cvss(raw),
        first_seen=utc_datetime(case_value(raw, "FirstSeenDate")),
        last_seen=utc_datetime(
            case_value(raw, "LastSeenDate") or case_value(raw, "UpdatedDate")
        ),
        raw_data=raw,
    )


def invicti_confidence(value: Any) -> str:
    try:
        certainty = int(value)
    except (TypeError, ValueError):
        return ""
    if certainty >= 90:
        return "high"
    if certainty >= 60:
        return "medium"
    return "low"


def invicti_cvss(raw: dict[str, Any]) -> float | None:
    for key in ("Cvss40Vector", "Cvss31Vector", "CvssVector"):
        vector = mapping(case_value(raw, key))
        for score_key in ("Score", "BaseScore", "score", "baseScore"):
            score = float_or_none(vector.get(score_key), maximum=10)
            if score is not None:
                return score
    return None


CONNECTOR_DEFINITION = ConnectorDefinition(
    key=InvictiConnector.key,
    name=InvictiConnector.name,
    connector_type="hosted_api",
    service_managed=True,
    description="Invicti or Netsparker vulnerability management API.",
    fields=(
        ConnectorField("endpoint", "API URL", required=True),
        ConnectorField("userId", "User ID", required=True),
        ConnectorField("token", "API token", required=True, secret=True),
    ),
    factory=InvictiConnector,
)
