from __future__ import annotations

import os
import unittest
from unittest.mock import Mock, patch

from appsec_scan_router.aspm_asset_risk import AssetRiskProfileEngine
from appsec_scan_router.aspm_connector_http import (
    ConnectorConfigurationError,
    ConnectorError,
    bounded_response_body,
    normalize_api_url,
)
from appsec_scan_router.aspm_connector_models import (
    ConnectorPullResult,
    ConnectorStatus,
)
from appsec_scan_router.aspm_connectors import ConnectorService
from appsec_scan_router.aspm_data import (
    AssetDataInteraction,
    DataInteractionClassifier,
)
from appsec_scan_router.aspm_models import (
    DataInteraction,
    FindingDocument,
    FindingInput,
)
from appsec_scan_router.aspm_risk import AssetRiskContext
from appsec_scan_router.invicti_connector import InvictiConnector, invicti_finding
from appsec_scan_router.nowsecure_connector import NowSecureConnector, nowsecure_finding
from appsec_scan_router.semgrep_connector import SemgrepConnector, semgrep_finding


class ConnectorNormalizationTests(unittest.TestCase):
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
                "ClassificationLinks": ["https://cwe.mitre.org/data/definitions/200.html"],
                "VulnerabilityDetail": "CWE-200 exposes personal data",
            }
        )

        self.assertEqual(finding.location.web_url, "https://payments.example.test")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.cwes, ("CWE-200",))

    def test_nowsecure_finding_uses_package_identifier_and_privacy_metadata(self) -> None:
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


class ConnectorServiceTests(unittest.TestCase):
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
            patch("appsec_scan_router.invicti_connector.JsonApiClient"),
        ):
            connector = InvictiConnector()

        self.assertEqual(
            connector.endpoint, "https://www.netsparkercloud.com/api/1.0"
        )
        self.assertTrue(connector.status().configured)

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
                },
                clear=False,
            ),
            patch(
                "appsec_scan_router.semgrep_connector.JsonApiClient",
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
