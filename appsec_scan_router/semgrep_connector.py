from __future__ import annotations

import os
from collections import deque
from collections.abc import Iterator, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock, local
from typing import Any

from .aspm_connector_http import JsonApiClient, positive_env_int
from .aspm_connector_models import ConnectorPullResult, ConnectorStatus
from .aspm_connector_utils import mapping, merge_location, repository_location, sequence
from .aspm_ingest import extract_identifiers
from .aspm_models import (
    FindingDocument,
    FindingInput,
    SourceLocation,
    bounded_text,
    normalize_severity,
    normalize_status,
    string_tuple,
    utc_datetime,
)


DEFAULT_SEMGREP_API_URL = "https://semgrep.dev/api/v1"
DEFAULT_SEMGREP_PAGE_SIZE = 3000
DEFAULT_SEMGREP_PROJECT_PAGE_SIZE = 3000
DEFAULT_SEMGREP_ISSUE_TYPES = ("sast", "sca", "ai_sast")
DEFAULT_SEMGREP_STATUSES = ("open", "reviewing", "fixing", "provisionally_ignored")
DEFAULT_SEMGREP_MAX_FINDINGS = 5_000_000
DEFAULT_SEMGREP_WORKERS = 4
MAX_SEMGREP_WORKERS = 16


class SemgrepConnector:
    key = "semgrep"
    name = "Semgrep"
    supports_streaming = True

    def __init__(
        self, timeout_seconds: int = 30, configuration: Mapping[str, Any] | None = None
    ) -> None:
        settings = dict(configuration or {})
        self.token = str(settings.get("token") or "").strip() or os.getenv("SEMGREP_APP_TOKEN", "").strip() or os.getenv(
            "APPLICATION_INVENTORY_SEMGREP_APP_TOKEN", ""
        ).strip()
        self.endpoint = str(settings.get("endpoint") or "").strip() or os.getenv(
            "APPLICATION_INVENTORY_SEMGREP_API_URL", DEFAULT_SEMGREP_API_URL
        ).strip()
        self.worker_count = min(
            MAX_SEMGREP_WORKERS,
            positive_env_int(
                "APPLICATION_INVENTORY_SEMGREP_WORKERS",
                DEFAULT_SEMGREP_WORKERS,
            ),
        )
        self._worker_local = local()
        self._worker_clients: list[JsonApiClient] = []
        self._worker_clients_lock = Lock()
        self.timeout_seconds = timeout_seconds
        self.client = (
            self._new_client()
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
            "Ready" if configured else "SEMGREP_APP_TOKEN is not configured.",
        )

    def close(self) -> None:
        if self.client:
            self.client.close()
        self._close_worker_clients()

    def test_connection(self) -> dict[str, int]:
        if not self.client:
            raise ValueError(self.status().message)
        response = self.client.get("deployments")
        return {"deployments": len(sequence(response.get("deployments")))}

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
            tool_type="sast",
            source_format="semgrep-api",
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
                "deployments": int(metadata.get("deploymentCount", 0)),
                "targets": len(targets),
            },
        )

    def pull_batches(self) -> Iterator[FindingDocument]:
        if not self.client:
            raise ValueError("SEMGREP_APP_TOKEN is not configured.")
        max_findings = positive_env_int(
            "APPLICATION_INVENTORY_SEMGREP_MAX_FINDINGS",
            DEFAULT_SEMGREP_MAX_FINDINGS,
        )
        deployments = sequence(self.client.get("deployments").get("deployments"))
        deployment_names = [
            bounded_text(mapping(item).get("name") or mapping(item).get("slug"), 300)
            for item in deployments
            if bounded_text(mapping(item).get("slug"), 300)
        ]
        metadata = {
            "deploymentCount": len(deployment_names),
            "deployments": deployment_names[:100],
            "api": self.endpoint,
        }
        seen: set[str] = set()
        total = 0
        for item in deployments:
            slug = bounded_text(mapping(item).get("slug"), 300)
            if not slug:
                continue
            yield from self._project_batches(slug, metadata)
            for issue_type in semgrep_issue_types():
                for status in semgrep_statuses():
                    for findings in self._finding_pages(slug, issue_type, status):
                        unique: list[FindingInput] = []
                        for finding in findings:
                            identity = finding.external_id or finding.fingerprint_hint
                            if identity and identity in seen:
                                continue
                            if identity:
                                seen.add(identity)
                            unique.append(finding)
                        total += len(unique)
                        if total > max_findings:
                            raise ValueError(
                                "Semgrep sync exceeds the "
                                f"{max_findings:,}-finding safety limit."
                            )
                        if unique:
                            yield FindingDocument(
                                tool_key=self.key,
                                tool_name=self.name,
                                tool_type="sast",
                                source_format="semgrep-api",
                                findings=tuple(unique),
                                metadata={
                                    **metadata,
                                    "issueType": issue_type,
                                    "status": status,
                                },
                            )
        yield FindingDocument(
            tool_key=self.key,
            tool_name=self.name,
            tool_type="sast",
            source_format="semgrep-api",
            findings=(),
            complete_snapshot=True,
            metadata={**metadata, "recordsRead": total},
        )

    def _project_batches(
        self, slug: str, metadata: dict[str, Any]
    ) -> Iterator[FindingDocument]:
        page_size = positive_env_int(
            "APPLICATION_INVENTORY_SEMGREP_PROJECT_PAGE_SIZE",
            DEFAULT_SEMGREP_PROJECT_PAGE_SIZE,
        )
        page = 0
        while True:
            response = self.client.get(
                f"deployments/{slug}/projects",
                {"page": page, "page_size": page_size},
            )
            batch = sequence(response.get("projects"))
            targets = tuple(
                target
                for item in batch
                if (target := semgrep_project_target(mapping(item))).has_asset_anchor()
            )
            if targets:
                yield FindingDocument(
                    tool_key=self.key,
                    tool_name=self.name,
                    tool_type="sast",
                    source_format="semgrep-api",
                    findings=(),
                    scanned_targets=targets,
                    metadata=metadata,
                )
            if len(batch) < page_size:
                break
            page += 1

    def _finding_pages(
        self, slug: str, issue_type: str, status: str
    ) -> Iterator[list[FindingInput]]:
        page_size = min(
            3000,
            positive_env_int(
                "APPLICATION_INVENTORY_SEMGREP_PAGE_SIZE", DEFAULT_SEMGREP_PAGE_SIZE
            ),
        )
        if self.worker_count == 1:
            page = 0
            while True:
                batch = self._fetch_finding_page(
                    slug,
                    issue_type,
                    status,
                    page,
                    page_size,
                    self.client,
                )
                if not batch:
                    return
                yield batch
                if len(batch) < page_size:
                    return
                page += 1
        else:
            yield from self._prefetched_finding_pages(
                slug,
                issue_type,
                status,
                page_size,
            )

    def _prefetched_finding_pages(
        self,
        slug: str,
        issue_type: str,
        status: str,
        page_size: int,
    ) -> Iterator[list[FindingInput]]:
        executor = ThreadPoolExecutor(
            max_workers=self.worker_count,
            thread_name_prefix="semgrep",
        )
        pending: deque[tuple[int, Future[list[FindingInput]]]] = deque()
        next_page = 0
        try:
            while len(pending) < self.worker_count:
                pending.append(
                    (
                        next_page,
                        executor.submit(
                            self._fetch_finding_page,
                            slug,
                            issue_type,
                            status,
                            next_page,
                            page_size,
                        ),
                    )
                )
                next_page += 1
            while pending:
                _, future = pending.popleft()
                batch = future.result()
                if not batch:
                    return
                yield batch
                if len(batch) < page_size:
                    return
                pending.append(
                    (
                        next_page,
                        executor.submit(
                            self._fetch_finding_page,
                            slug,
                            issue_type,
                            status,
                            next_page,
                            page_size,
                        ),
                    )
                )
                next_page += 1
        finally:
            for _, future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            self._close_worker_clients()

    def _fetch_finding_page(
        self,
        slug: str,
        issue_type: str,
        status: str,
        page: int,
        page_size: int,
        client: JsonApiClient | None = None,
    ) -> list[FindingInput]:
        api_client = client or self._worker_client()
        response = api_client.get(
            f"deployments/{slug}/findings",
            {
                "issue_type": issue_type,
                "status": status,
                "page": page,
                "page_size": page_size,
                "dedup": "true",
            },
        )
        return [
            semgrep_finding(mapping(item), slug)
            for item in sequence(response.get("findings"))
        ]

    def _new_client(self) -> JsonApiClient:
        return JsonApiClient(
            self.endpoint,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout_seconds=self.timeout_seconds,
        )

    def _worker_client(self) -> JsonApiClient:
        client = getattr(self._worker_local, "client", None)
        if client is None:
            client = self._new_client()
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


def semgrep_project_target(project: dict[str, Any]) -> SourceLocation:
    return repository_location(
        project.get("url"),
        project.get("name"),
        project.get("primary_branch") or project.get("default_branch"),
        application=project.get("name"),
    )


def semgrep_finding(raw: dict[str, Any], deployment: str) -> FindingInput:
    repository = mapping(raw.get("repository"))
    location_data = mapping(raw.get("location"))
    rule = mapping(raw.get("rule"))
    categories = string_tuple(raw.get("categories"))
    location = repository_location(
        repository.get("url"),
        repository.get("name"),
        raw.get("ref"),
    )
    location = merge_location(
        location,
        path=location_data.get("file_path"),
        start_line=location_data.get("line"),
        end_line=location_data.get("end_line"),
    )
    external_id = bounded_text(
        raw.get("id") or raw.get("match_based_id") or raw.get("syntactic_id"), 500
    )
    status_value = raw.get("status") or raw.get("triage_state") or raw.get("state")
    dependency = mapping(raw.get("found_dependency"))
    fixes = [mapping(item) for item in sequence(raw.get("fix_recommendations"))]
    epss = mapping(raw.get("epss_score"))
    vulnerability_identifier = raw.get("vulnerability_identifier")
    return FindingInput(
        external_id=external_id,
        fingerprint_hint=bounded_text(
            raw.get("match_based_id") or raw.get("syntactic_id") or external_id,
            1000,
        ),
        title=bounded_text(
            raw.get("rule_message")
            or rule.get("message")
            or raw.get("rule_name")
            or rule.get("name")
            or "Semgrep finding",
            1000,
        ),
        description=bounded_text(rule.get("message") or raw.get("rule_message"), 20_000),
        rule_id=bounded_text(raw.get("rule_name") or rule.get("name"), 500),
        category=bounded_text("; ".join(categories) or rule.get("category"), 300),
        severity=normalize_severity(raw.get("severity") or "medium"),
        status=normalize_status(status_value or "open"),
        confidence=bounded_text(raw.get("confidence") or rule.get("confidence"), 50),
        location=location,
        scanner_url=bounded_text(raw.get("line_of_code_url"), 2000),
        cwes=extract_identifiers(rule.get("cwe_names"), "CWE"),
        cves=extract_identifiers(vulnerability_identifier, "CVE"),
        package_name=bounded_text(dependency.get("package"), 500),
        package_version=bounded_text(dependency.get("version"), 200),
        fixed_version=bounded_text(
            fixes[0].get("version") if fixes else "", 200
        ),
        epss_score=float(epss["score"])
        if isinstance(epss.get("score"), (int, float))
        else None,
        first_seen=utc_datetime(raw.get("created_at")),
        last_seen=utc_datetime(
            raw.get("state_updated_at") or raw.get("relevant_since")
        ),
        raw_data={**raw, "deployment": deployment},
    )


def semgrep_issue_types() -> tuple[str, ...]:
    configured = os.getenv("APPLICATION_INVENTORY_SEMGREP_ISSUE_TYPES", "")
    values = tuple(item.strip().casefold() for item in configured.split(",") if item.strip())
    valid = tuple(item for item in values if item in DEFAULT_SEMGREP_ISSUE_TYPES)
    return valid or DEFAULT_SEMGREP_ISSUE_TYPES


def semgrep_statuses() -> tuple[str, ...]:
    configured = os.getenv("APPLICATION_INVENTORY_SEMGREP_STATUSES", "")
    allowed = {
        "open",
        "fixed",
        "ignored",
        "reviewing",
        "fixing",
        "provisionally_ignored",
    }
    values = tuple(item.strip().casefold() for item in configured.split(",") if item.strip())
    valid = tuple(item for item in values if item in allowed)
    return valid or DEFAULT_SEMGREP_STATUSES
