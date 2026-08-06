from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, Mock, patch

from requests import exceptions as requests_exceptions

from appsec_scan_router.aspm_asset_risk import (
    AssetFindingSummary,
    AssetRiskProfileEngine,
)
from appsec_scan_router.connectors.http import (
    ConnectorConfigurationError,
    ConnectorError,
    JsonApiClient,
    bounded_response_body,
    network_error_reason,
    normalize_api_url,
)
from appsec_scan_router.connectors.models import (
    ConnectorDefinition,
    ConnectorField,
    ConnectorPullResult,
    ConnectorStatus,
)
from appsec_scan_router.connectors.registry import ConnectorRegistry
from appsec_scan_router.connectors.service import ConnectorService, connector_status
from appsec_scan_router.aspm_connectors import ConnectorService as CompatibilityConnectorService
from appsec_scan_router.aspm_data import (
    AssetDataInteraction,
    DataInteractionClassifier,
)
from appsec_scan_router.aspm_models import (
    DataInteraction,
    FindingDocument,
    FindingInput,
    SourceLocation,
)
from appsec_scan_router.aspm_postgres import repository_asset_candidate
from appsec_scan_router.aspm_risk import AssetRiskContext
from appsec_scan_router.connectors.invicti import InvictiConnector, invicti_finding
from appsec_scan_router.connectors.nowsecure import NowSecureConnector, nowsecure_finding
from appsec_scan_router.connectors.semgrep_enterprise import SemgrepConnector, semgrep_finding
from appsec_scan_router.connectors.semgrep_community import (
    CONNECTOR_DEFINITION as SEMGREP_COMMUNITY_CONNECTOR,
)
from appsec_scan_router.connectors.report_import import ReportImportConnector
from appsec_scan_router.connectors.sonarqube import SonarQubeConnector
from appsec_scan_router.connectors.zap import ZapConnector


class ConnectorNormalizationTests(unittest.TestCase):
    def test_semgrep_enterprise_api_and_community_profile_are_distinct(self) -> None:
        enterprise = SemgrepConnector(configuration={"token": "enterprise-token"})
        community = SEMGREP_COMMUNITY_CONNECTOR.create(
            30, {"reportPath": "reports/semgrep.json"}
        )

        self.assertEqual(enterprise.key, "semgrep")
        self.assertEqual(enterprise.name, "Semgrep Enterprise")
        self.assertTrue(enterprise.status().configured)
        self.assertEqual(community.key, "semgrep_community")
        self.assertEqual(community.name, "Semgrep Community")
        self.assertTrue(community.status().configured)
        self.assertIn("Semgrep JSON", community.status().message)

    def test_configured_service_scanner_stays_checked_and_sync_ready(self) -> None:
        connector = Mock()
        connector.key = "semgrep"
        connector.status.return_value = ConnectorStatus(
            "semgrep", "Semgrep", True, "https://semgrep.dev/api/v1", "Ready"
        )

        status = connector_status(connector)

        self.assertTrue(status["configured"])
        self.assertTrue(status["syncReady"])
        self.assertEqual(status["configurationSource"], "service")

    def test_configured_sarif_profile_is_not_remotely_synced(self) -> None:
        connector = ReportImportConnector(
            "trivy", "Trivy", {"reportPath": "reports/trivy.sarif"}
        )

        status = connector_status(connector, "account")

        self.assertTrue(status["configured"])
        self.assertFalse(status["syncReady"])
        self.assertEqual(status["configurationSource"], "account")
        self.assertIn("SARIF", status["message"])

    def test_sonarqube_connector_uses_user_configuration_and_normalizes_issues(self) -> None:
        client = Mock()
        client.get.return_value = {
            "total": 1,
            "issues": [
                {
                    "key": "issue-1",
                    "message": "Use parameterized SQL queries",
                    "severity": "CRITICAL",
                    "type": "VULNERABILITY",
                    "rule": "python:S3649",
                    "component": "payments-api:src/db.py",
                    "line": 42,
                }
            ],
        }
        with patch(
            "appsec_scan_router.connectors.sonarqube.JsonApiClient", return_value=client
        ) as client_class:
            connector = SonarQubeConnector(
                configuration={
                    "endpoint": "https://sonar.example.test",
                    "token": "user-token",
                }
            )
            result = connector.pull()

        finding = result.document.findings[0]
        self.assertTrue(connector.status().configured)
        self.assertEqual(client_class.call_args.kwargs["auth"], ("user-token", ""))
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.location.repository, "payments-api")
        self.assertEqual(finding.location.path, "src/db.py")
        self.assertEqual(finding.location.start_line, 42)

    def test_zap_connector_uses_api_key_and_normalizes_alerts(self) -> None:
        client = Mock()
        client.get.return_value = {
            "alerts": [
                {
                    "alertRef": "alert-1",
                    "alert": "SQL Injection",
                    "risk": "High",
                    "pluginId": "40018",
                    "cweid": "89",
                    "url": "https://payments.example.test/search",
                    "description": "A database error was returned.",
                    "solution": "Use parameterized queries.",
                }
            ]
        }
        with patch(
            "appsec_scan_router.connectors.zap.JsonApiClient", return_value=client
        ):
            connector = ZapConnector(
                configuration={
                    "endpoint": "http://127.0.0.1:8080",
                    "apiKey": "zap-key",
                }
            )
            result = connector.pull()

        finding = result.document.findings[0]
        parameters = client.get.call_args.args[1]
        self.assertTrue(connector.status().configured)
        self.assertEqual(parameters["apikey"], "zap-key")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.location.web_url, "https://payments.example.test/search")
        self.assertEqual(finding.cwes, ("CWE-89",))

    def test_semgrep_api_finding_preserves_repository_context(self) -> None:
        finding = semgrep_finding(
            {
                "id": 42,
                "match_based_id": "stable-match",
                "severity": "high",
                "ref": "main",
                "repository": {
                    "name": "ExampleEngineering/payments-api",
                    "url": "https://github.com/ExampleEngineering/payments-api",
                },
                "location": {"file_path": "src/payments.py", "line": 17},
                "rule": {
                    "name": "python.security.hardcoded-secret",
                    "message": "Hardcoded API key",
                    "cwe_names": ["CWE-798"],
                },
            },
            "example",
        )

        self.assertEqual(finding.location.organization, "ExampleEngineering")
        self.assertEqual(finding.location.repository, "payments-api")
        self.assertEqual(finding.location.path, "src/payments.py")
        self.assertEqual(finding.cwes, ("CWE-798",))

    def test_invicti_finding_uses_web_target_as_asset_anchor(self) -> None:
        finding = invicti_finding(
            {
                "Id": "issue-1",
                "Title": "Sensitive data exposure",
                "Severity": "Critical",
                "IsPresent": True,
                "WebsiteName": "Payments",
                "WebsiteRootUrl": "https://payments.example.test",
                "Url": "https://payments.example.test/account",
                "ClassificationLinks": [
                    "https://cwe.mitre.org/data/definitions/200.html"
                ],
                "VulnerabilityDetail": "CWE-200 exposes personal data",
            }
        )

        self.assertEqual(finding.location.web_url, "https://payments.example.test")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.cwes, ("CWE-200",))

    def test_nowsecure_finding_uses_package_identifier_and_privacy_metadata(
        self,
    ) -> None:
        finding = nowsecure_finding(
            {"ref": "app-1", "title": "Pay", "packageKey": "com.example.pay"},
            {"createdAt": "2026-07-20T12:00:00Z", "packageVersion": "3.2.1"},
            {
                "key": "finding-1",
                "title": "Advertising identifier collected",
                "impactType": "medium",
                "affected": True,
                "check": {
                    "id": "privacy-1",
                    "privacyCategory": "User Tracking",
                    "categories": ["Device Identifiers"],
                },
            },
        )

        self.assertEqual(finding.location.application_identifier, "com.example.pay")
        self.assertEqual(finding.package_version, "3.2.1")
        self.assertEqual(
            {item.data_type for item in finding.data_interactions},
            {"device_identifiers", "tracking_data"},
        )


class ConnectorRegistryTests(unittest.TestCase):
    def test_registry_creates_connectors_from_individual_definitions(self) -> None:
        connector = Mock()
        factory = Mock(return_value=connector)
        registry = ConnectorRegistry(
            (
                ConnectorDefinition(
                    key="example",
                    name="Example",
                    connector_type="cloud_api",
                    service_managed=False,
                    description="Example connector.",
                    fields=(ConnectorField("token", "API token", required=True, secret=True),),
                    factory=factory,
                ),
            )
        )

        connectors = registry.create_all(45, {"example": {"token": "secret"}})

        self.assertEqual(connectors, (connector,))
        factory.assert_called_once_with(45, {"token": "secret"})
        self.assertEqual(registry.keys, ("example",))
        self.assertEqual(registry.remote_keys, ("example",))
        self.assertEqual(
            registry.setup("example")["fields"],
            [{"key": "token", "label": "API token", "required": True, "secret": True}],
        )

    def test_service_uses_registry_extensions_without_concrete_wiring(self) -> None:
        connector = Mock()
        connector.key = "example"
        connector.name = "Example"
        connector.status.return_value = ConnectorStatus(
            "example", "Example", True, "https://example.test", "Ready"
        )
        connector.test_connection.return_value = {"account": "verified"}
        factory = Mock(return_value=connector)
        registry = ConnectorRegistry(
            (
                ConnectorDefinition(
                    key="example",
                    name="Example",
                    connector_type="cloud_api",
                    service_managed=False,
                    description="Example connector.",
                    fields=(ConnectorField("token", "API token", required=True, secret=True),),
                    factory=factory,
                ),
            )
        )
        service = ConnectorService(
            None,
            "user-a",
            "alice",
            timeout_seconds=45,
            connector_configurations={"example": {"token": "secret"}},
            registry=registry,
        )

        status = service.status()
        result = service.test_connections(["example"])

        factory.assert_called_once_with(45, {"token": "secret"})
        self.assertEqual(status[0]["configurationSource"], "account")
        self.assertTrue(status[0]["syncReady"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["results"][0]["metadata"], {"account": "verified"})

    def test_compatibility_facade_reexports_connector_service(self) -> None:
        self.assertIs(CompatibilityConnectorService, ConnectorService)


class DataRiskTests(unittest.TestCase):
    def test_classifier_combines_explicit_scanner_data_and_cwe_evidence(self) -> None:
        interactions = DataInteractionClassifier().classify(
            FindingInput(
                external_id="finding-1",
                title="Hardcoded credential",
                severity="high",
                cwes=("CWE-798",),
                data_interactions=(
                    DataInteraction("payment", 0.99, "scanner", "PCI data"),
                ),
            )
        )

        by_type = {item.data_type: item for item in interactions}
        self.assertIn("credentials", by_type)
        self.assertIn("secrets", by_type)
        self.assertIn("payment_card_data", by_type)
        self.assertEqual(by_type["payment_card_data"].confidence, 0.99)

    def test_sensitive_data_and_exposure_raise_asset_risk(self) -> None:
        engine = AssetRiskProfileEngine()
        baseline = engine.assess(
            [(60, "high")],
            (),
            AssetRiskContext(
                criticality="medium",
                internet_exposed=False,
                data_classification="internal",
            ),
        )
        sensitive = engine.assess(
            [(60, "high")],
            (
                AssetDataInteraction(
                    "payment_card_data", 0.99, 2, ({"source": "scanner"},)
                ),
            ),
            AssetRiskContext(
                criticality="mission_critical",
                internet_exposed=True,
                data_classification="restricted",
            ),
        )

        self.assertGreater(sensitive.score, baseline.score)
        self.assertEqual(sensitive.data_types, ("payment_card_data",))

    def test_aggregated_finding_summary_matches_full_finding_assessment(self) -> None:
        engine = AssetRiskProfileEngine()
        findings = [
            (91, "critical"),
            (82, "high"),
            (68, "high"),
            (55, "medium"),
            (44, "medium"),
            (31, "low"),
        ]
        context = AssetRiskContext(
            criticality="high",
            internet_exposed=True,
            data_classification="confidential",
        )

        full = engine.assess(findings, (), context)
        aggregated = engine.assess_summary(
            AssetFindingSummary.from_findings(findings), (), context
        )

        self.assertEqual(aggregated, full)


class ConnectorServiceTests(unittest.TestCase):
    def test_repository_asset_candidate_uses_strong_scope_and_branch(self) -> None:
        candidates = (
            {
                "branch_inventory_id": 1,
                "provider": "github-enterprise",
                "organization": "example",
                "project": "",
                "repo_name": "payments",
                "branch_name": "main",
            },
            {
                "branch_inventory_id": 2,
                "provider": "github-enterprise",
                "organization": "another-owner",
                "project": "",
                "repo_name": "payments",
                "branch_name": "main",
            },
        )

        result = repository_asset_candidate(
            SourceLocation(
                provider="github-enterprise",
                organization="Example",
                repository="Payments",
                branch="refs/heads/main",
            ),
            candidates,
        )

        self.assertEqual(result["branch_inventory_id"], 1)
        self.assertEqual(result["correlation_method"], "repository")

    def test_repository_asset_candidate_uses_single_branch_fallback(self) -> None:
        result = repository_asset_candidate(
            SourceLocation(repository="payments", branch="release"),
            (
                {
                    "branch_inventory_id": 1,
                    "provider": "azure-devops",
                    "organization": "example",
                    "project": "payments",
                    "repo_name": "payments",
                    "branch_name": "main",
                },
            ),
        )

        self.assertEqual(result["branch_inventory_id"], 1)
        self.assertEqual(result["correlation_method"], "repository_default_branch")

    def test_repository_asset_candidate_rejects_ambiguous_matches(self) -> None:
        candidates = tuple(
            {
                "branch_inventory_id": value,
                "provider": "azure-devops",
                "organization": "example",
                "project": f"project-{value}",
                "repo_name": "shared",
                "branch_name": "main",
            }
            for value in (1, 2)
        )

        result = repository_asset_candidate(
            SourceLocation(repository="shared", branch="main"), candidates
        )

        self.assertIsNone(result)

    def test_invicti_uses_public_cloud_api_by_default(self) -> None:
        with (
            patch.dict(
                os.environ,
                {
                    "APPLICATION_INVENTORY_INVICTI_USER_ID": "test-user",
                    "APPLICATION_INVENTORY_INVICTI_TOKEN": "test-token",
                },
                clear=True,
            ),
            patch("appsec_scan_router.connectors.invicti.JsonApiClient") as client_class,
        ):
            connector = InvictiConnector()

        self.assertEqual(connector.endpoint, "https://www.netsparkercloud.com/api/1.0")
        self.assertTrue(connector.status().configured)
        self.assertEqual(client_class.call_args.kwargs["timeout_seconds"], 120)

    def test_invicti_groups_api_pages_into_bounded_database_batches(self) -> None:
        client = Mock()
        client.get.side_effect = (
            {},
            {
                "List": [{"Id": "finding-1", "Title": "One"}],
                "IsLastPage": False,
            },
            {
                "List": [{"Id": "finding-2", "Title": "Two"}],
                "IsLastPage": False,
            },
            {
                "List": [{"Id": "finding-3", "Title": "Three"}],
                "IsLastPage": True,
            },
        )
        with (
            patch.dict(
                os.environ,
                {
                    "INVICTI_USER_ID": "test-user",
                    "INVICTI_TOKEN": "test-token",
                    "APPLICATION_INVENTORY_INVICTI_BATCH_PAGES": "2",
                },
                clear=False,
            ),
            patch(
                "appsec_scan_router.connectors.invicti.JsonApiClient",
                return_value=client,
            ),
        ):
            batches = list(InvictiConnector().pull_batches())

        finding_batches = [batch for batch in batches if batch.findings]
        self.assertEqual([len(batch.findings) for batch in finding_batches], [2, 1])
        self.assertEqual(finding_batches[0].metadata["pageStart"], 1)
        self.assertEqual(finding_batches[0].metadata["pageEnd"], 2)
        self.assertTrue(batches[-1].complete_snapshot)

    def test_sync_audits_and_ingests_normalized_document(self) -> None:
        document = FindingDocument(
            tool_key="semgrep",
            tool_name="Semgrep",
            tool_type="sast",
            source_format="semgrep-api",
            findings=(FindingInput("1", "Finding", "high"),),
        )
        connector = Mock()
        connector.key = "semgrep"
        connector.name = "Semgrep"
        connector.status.return_value = ConnectorStatus(
            "semgrep", "Semgrep", True, "https://semgrep.dev/api/v1", "Ready"
        )
        connector.pull.return_value = ConnectorPullResult(
            "semgrep", "Semgrep", document, 1
        )
        repository = Mock()
        repository.start_connector_sync.return_value = "sync-1"
        repository.ingest.return_value = {
            "findings": 1,
            "inserted": 1,
            "updated": 0,
            "resolved": 0,
            "assetsCovered": 1,
            "linkedFindings": 1,
            "unlinkedFindings": 0,
        }
        service = ConnectorService(
            repository, "user-a", "alice", connectors=(connector,)
        )

        result = service.sync(["semgrep"])

        self.assertEqual(result["status"], "completed")
        repository.ingest.assert_called_once_with("user-a", "alice", document)
        repository.finish_connector_sync.assert_called_once()

    def test_sync_streams_connector_batches_and_preserves_metadata(self) -> None:
        document = FindingDocument(
            tool_key="semgrep",
            tool_name="Semgrep",
            tool_type="sast",
            source_format="semgrep-api",
            findings=(FindingInput("1", "Finding", "high"),),
            complete_snapshot=True,
        )
        connector = Mock()
        connector.key = "semgrep"
        connector.name = "Semgrep"
        connector.supports_streaming = True
        connector.status.return_value = ConnectorStatus(
            "semgrep", "Semgrep", True, "https://semgrep.dev/api/v1", "Ready"
        )
        connector.pull_batches.return_value = iter((document,))
        repository = Mock()
        repository.start_connector_sync.return_value = "sync-1"
        repository.ingest_batches.return_value = {
            "findings": 1,
            "inserted": 1,
            "updated": 0,
            "resolved": 0,
            "assetsCovered": 1,
            "linkedFindings": 1,
            "unlinkedFindings": 0,
            "metadata": {"deploymentCount": 2},
        }
        service = ConnectorService(
            repository, "user-a", "alice", connectors=(connector,)
        )

        result = service.sync(["semgrep"])

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["results"][0]["metadata"]["deploymentCount"], 2)
        repository.ingest_batches.assert_called_once()
        connector.pull.assert_not_called()

    def test_test_connections_reports_current_connector_reachability(self) -> None:
        connector = Mock()
        connector.key = "semgrep"
        connector.name = "Semgrep"
        connector.status.return_value = ConnectorStatus(
            "semgrep", "Semgrep", True, "https://semgrep.dev/api/v1", "Ready"
        )
        connector.test_connection.return_value = {"deployments": 1}
        service = ConnectorService(
            Mock(), "user-a", "alice", connectors=(connector,)
        )

        result = service.test_connections(["semgrep"])

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["results"][0]["connector"], "semgrep")
        self.assertEqual(result["results"][0]["metadata"], {"deployments": 1})
        connector.test_connection.assert_called_once_with()

    def test_semgrep_pages_start_at_zero_and_are_requested_in_order(self) -> None:
        client = Mock()
        client.get.side_effect = (
            {
                "findings": [
                    {"id": "finding-1", "title": "One"},
                    {"id": "finding-2", "title": "Two"},
                ]
            },
            {"findings": [{"id": "finding-3", "title": "Three"}]},
        )
        with (
            patch.dict(
                os.environ,
                {
                    "SEMGREP_APP_TOKEN": "test-token",
                    "APPLICATION_INVENTORY_SEMGREP_PAGE_SIZE": "2",
                    "APPLICATION_INVENTORY_SEMGREP_WORKERS": "1",
                },
                clear=False,
            ),
            patch(
                "appsec_scan_router.connectors.semgrep_enterprise.JsonApiClient",
                return_value=client,
            ),
        ):
            connector = SemgrepConnector()
            pages = list(connector._finding_pages("example", "sast", "open"))

        self.assertEqual([len(page) for page in pages], [2, 1])
        first_parameters = connector.client.get.call_args_list[0].args[1]
        second_parameters = connector.client.get.call_args_list[1].args[1]
        self.assertEqual(first_parameters["page"], 0)
        self.assertEqual(second_parameters["page"], 1)
        self.assertEqual(first_parameters["dedup"], "true")

    def test_semgrep_finding_limit_is_configurable(self) -> None:
        client = Mock()
        client.get.side_effect = (
            {"deployments": [{"slug": "example", "name": "Example"}]},
            {"projects": []},
            {
                "findings": [
                    {"id": "finding-1", "title": "One"},
                    {"id": "finding-2", "title": "Two"},
                ]
            },
        )
        with (
            patch.dict(
                os.environ,
                {
                    "SEMGREP_APP_TOKEN": "test-token",
                    "APPLICATION_INVENTORY_SEMGREP_ISSUE_TYPES": "sast",
                    "APPLICATION_INVENTORY_SEMGREP_STATUSES": "open",
                    "APPLICATION_INVENTORY_SEMGREP_PAGE_SIZE": "2",
                    "APPLICATION_INVENTORY_SEMGREP_MAX_FINDINGS": "1",
                    "APPLICATION_INVENTORY_SEMGREP_WORKERS": "1",
                },
                clear=False,
            ),
            patch(
                "appsec_scan_router.connectors.semgrep_enterprise.JsonApiClient",
                return_value=client,
            ),
        ):
            connector = SemgrepConnector()
            with self.assertRaisesRegex(ValueError, "1-finding safety limit"):
                list(connector.pull_batches())

    def test_semgrep_prefetches_bounded_pages_and_preserves_order(self) -> None:
        client = Mock()

        def get(_path: str, parameters: dict[str, object]) -> dict[str, object]:
            page = int(parameters["page"])
            findings = (
                [{"id": f"finding-{page}", "title": str(page)}] if page < 3 else []
            )
            return {"findings": findings}

        client.get.side_effect = get
        with (
            patch.dict(
                os.environ,
                {
                    "SEMGREP_APP_TOKEN": "test-token",
                    "APPLICATION_INVENTORY_SEMGREP_PAGE_SIZE": "1",
                    "APPLICATION_INVENTORY_SEMGREP_WORKERS": "2",
                },
                clear=False,
            ),
            patch(
                "appsec_scan_router.connectors.semgrep_enterprise.JsonApiClient",
                return_value=client,
            ),
        ):
            connector = SemgrepConnector()
            pages = list(connector._finding_pages("example", "sast", "open"))
            connector.close()

        self.assertEqual(
            [page[0].external_id for page in pages],
            ["finding-0", "finding-1", "finding-2"],
        )
        requested_pages = sorted(
            int(call.args[1]["page"]) for call in client.get.call_args_list
        )
        self.assertEqual(requested_pages[:4], [0, 1, 2, 3])
        self.assertLessEqual(len(requested_pages), 5)

    def test_api_url_requires_https_outside_loopback(self) -> None:
        with self.assertRaises(ConnectorConfigurationError):
            normalize_api_url("http://scanner.example.test/api")
        self.assertEqual(
            normalize_api_url("http://127.0.0.1:8080/api"),
            "http://127.0.0.1:8080/api",
        )

    def test_connector_response_body_enforces_decoded_size_limit(self) -> None:
        response = Mock()
        response.headers = {}
        response.iter_content.return_value = (b"1234", b"5678")

        with self.assertRaisesRegex(ConnectorError, "6-byte limit"):
            bounded_response_body(response, 6)

    def test_json_client_retries_transient_dns_failures(self) -> None:
        response = MagicMock()
        response.status_code = 200
        response.url = "https://scanner.example.test/api/findings"
        response.headers = {}
        response.iter_content.return_value = (b'{"findings": []}',)
        response.__enter__.return_value = response
        client = object.__new__(JsonApiClient)
        client.base_url = "https://scanner.example.test/api"
        client.timeout_seconds = 30
        client.verify = True
        client.session = Mock()
        client.session.request.side_effect = (
            requests_exceptions.ConnectionError("Failed to resolve host"),
            response,
        )

        with (
            patch.dict(
                os.environ,
                {
                    "APPLICATION_INVENTORY_CONNECTOR_NETWORK_ATTEMPTS": "2",
                    "APPLICATION_INVENTORY_CONNECTOR_NETWORK_BACKOFF_SECONDS": "1",
                },
            ),
            patch("appsec_scan_router.connectors.http.time.sleep") as sleep,
        ):
            document = client.get("findings")

        self.assertEqual(document, {"findings": []})
        self.assertEqual(client.session.request.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_json_client_reports_exhausted_dns_retries(self) -> None:
        client = object.__new__(JsonApiClient)
        client.base_url = "https://scanner.example.test/api"
        client.timeout_seconds = 30
        client.verify = True
        client.session = Mock()
        client.session.request.side_effect = requests_exceptions.ConnectionError(
            "Failed to resolve host"
        )

        with (
            patch.dict(
                os.environ,
                {"APPLICATION_INVENTORY_CONNECTOR_NETWORK_ATTEMPTS": "2"},
            ),
            patch("appsec_scan_router.connectors.http.time.sleep"),
            self.assertRaisesRegex(
                ConnectorError,
                "failed after 2 network attempts: DNS resolution failed",
            ),
        ):
            client.get("findings")

        self.assertEqual(client.session.request.call_count, 2)

    def test_network_error_reason_distinguishes_rate_limits(self) -> None:
        error = requests_exceptions.RetryError("too many 429 error responses")

        self.assertEqual(
            network_error_reason(error),
            "rate limits exhausted their retries",
        )

    def test_invicti_and_nowsecure_emit_terminal_complete_snapshots(self) -> None:
        invicti = object.__new__(InvictiConnector)
        invicti.endpoint = "https://invicti.example/api/1.0"
        invicti.client = Mock()
        invicti.client.get.side_effect = (
            {},
            {
                "List": [
                    {
                        "Id": "web-1",
                        "Title": "Web finding",
                        "Severity": "High",
                        "WebsiteRootUrl": "https://app.example.test",
                    }
                ],
                "IsLastPage": True,
            },
        )
        nowsecure = object.__new__(NowSecureConnector)
        nowsecure.endpoint = "https://api.nowsecure.com/graphql"
        nowsecure.client = Mock()
        nowsecure.client.post.return_value = {
            "data": {
                "auto": {
                    "applications": [
                        {
                            "ref": "app-1",
                            "title": "Mobile App",
                            "packageKey": "com.example.mobile",
                        }
                    ]
                }
            }
        }

        invicti_batches = list(invicti.pull_batches())
        nowsecure_batches = list(nowsecure.pull_batches())

        self.assertFalse(invicti_batches[0].complete_snapshot)
        self.assertTrue(invicti_batches[-1].complete_snapshot)
        self.assertEqual(invicti_batches[-1].metadata["recordsRead"], 1)
        self.assertFalse(nowsecure_batches[0].complete_snapshot)
        self.assertTrue(nowsecure_batches[-1].complete_snapshot)
        self.assertEqual(nowsecure_batches[-1].metadata["applicationCount"], 1)


if __name__ == "__main__":
    unittest.main()
