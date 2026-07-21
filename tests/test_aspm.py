from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from appsec_scan_router.aspm_ingest import parse_finding_document
from appsec_scan_router.aspm_models import (
    FindingInput,
    SourceLocation,
    validate_transition,
)
from appsec_scan_router.aspm_risk import AssetRiskContext, RiskEngine


class FindingIngestionTests(unittest.TestCase):
    def test_generic_findings_are_normalized_and_fingerprinted(self) -> None:
        document = parse_finding_document(
            {
                "format": "generic",
                "tool": {"key": "custom-sca", "name": "Custom SCA", "type": "sca"},
                "context": {
                    "provider": "github-enterprise",
                    "organization": "ExampleEngineering",
                    "repository": "payments-api",
                    "branch": "main",
                },
                "findings": [
                    {
                        "id": "CVE-2026-1000",
                        "title": "Vulnerable dependency",
                        "severity": "CRITICAL",
                        "cwe": ["CWE-1104"],
                        "cve": "CVE-2026-1000",
                        "package_name": "example-lib",
                        "package_version": "1.0.0",
                        "fixed_version": "1.0.1",
                    }
                ],
            }
        )

        self.assertEqual(document.tool_key, "custom-sca")
        self.assertEqual(document.tool_type, "sca")
        self.assertEqual(document.findings[0].severity, "critical")
        self.assertEqual(document.findings[0].location.repository, "payments-api")
        self.assertEqual(document.findings[0].cves, ("CVE-2026-1000",))
        self.assertEqual(
            document.findings[0].fingerprint("custom-sca"),
            document.findings[0].fingerprint("custom-sca"),
        )

    def test_sarif_source_control_context_and_security_metadata_are_parsed(
        self,
    ) -> None:
        document = parse_finding_document(
            {
                "format": "auto",
                "document": {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "name": "CodeQL",
                                    "rules": [
                                        {
                                            "id": "py/sql-injection",
                                            "shortDescription": {
                                                "text": "SQL injection"
                                            },
                                            "properties": {
                                                "security-severity": "9.3",
                                                "tags": ["external/cwe/cwe-089"],
                                            },
                                        }
                                    ],
                                }
                            },
                            "versionControlProvenance": [
                                {
                                    "repositoryUri": "https://github.com/ExampleEngineering/payments-api.git",
                                    "branch": "refs/heads/main",
                                }
                            ],
                            "results": [
                                {
                                    "ruleId": "py/sql-injection",
                                    "message": {"text": "Unsanitized SQL query"},
                                    "partialFingerprints": {
                                        "primaryLocationLineHash": "abc123"
                                    },
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": "src/db.py"
                                                },
                                                "region": {"startLine": 42},
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
            }
        )

        finding = document.findings[0]
        self.assertEqual(document.source_format, "sarif")
        self.assertEqual(document.tool_name, "CodeQL")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.location.organization, "ExampleEngineering")
        self.assertEqual(finding.location.repository, "payments-api")
        self.assertEqual(finding.location.branch, "main")
        self.assertEqual(finding.location.path, "src/db.py")
        self.assertEqual(finding.location.start_line, 42)

    def test_semgrep_and_sonarqube_formats_are_detected(self) -> None:
        semgrep = parse_finding_document(
            {
                "document": {
                    "results": [
                        {
                            "check_id": "python.lang.security.audit.exec-used",
                            "path": "worker.py",
                            "start": {"line": 10},
                            "end": {"line": 10},
                            "extra": {
                                "message": "Use of exec",
                                "severity": "ERROR",
                                "metadata": {"cwe": ["CWE-95"]},
                            },
                        }
                    ]
                }
            }
        )
        sonarqube = parse_finding_document(
            {
                "document": {
                    "issues": [
                        {
                            "key": "issue-1",
                            "rule": "python:S3649",
                            "severity": "BLOCKER",
                            "message": "Database query uses untrusted input",
                            "component": "payments:src/db.py",
                            "line": 8,
                        }
                    ]
                }
            }
        )

        self.assertEqual(semgrep.source_format, "semgrep")
        self.assertEqual(semgrep.findings[0].cwes, ("CWE-95",))
        self.assertEqual(sonarqube.source_format, "sonarqube")
        self.assertEqual(sonarqube.findings[0].severity, "critical")

    def test_empty_complete_snapshot_requires_a_scanned_target(self) -> None:
        document = parse_finding_document(
            {
                "format": "generic",
                "findings": [],
                "scannedTargets": [{"repository": "payments-api", "branch": "main"}],
                "completeSnapshot": True,
            }
        )
        self.assertEqual(document.findings, ())
        self.assertTrue(document.complete_snapshot)
        self.assertEqual(document.scanned_targets[0].repository, "payments-api")


class RiskEngineTests(unittest.TestCase):
    def test_risk_score_combines_finding_and_asset_context(self) -> None:
        finding = FindingInput(
            external_id="finding-1",
            title="Remote code execution",
            severity="critical",
            location=SourceLocation(repository="payments-api"),
            cvss_score=9.8,
            epss_score=0.94,
            exploit_available=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=180),
        )
        assessment = RiskEngine().assess(
            finding,
            AssetRiskContext(
                criticality="mission_critical",
                internet_exposed=True,
                data_classification="restricted",
            ),
        )

        self.assertEqual(assessment.score, 100)
        self.assertEqual(assessment.band, "critical")
        self.assertIn(
            "known_exploit", {factor["factor"] for factor in assessment.factors}
        )

    def test_finding_workflow_rejects_invalid_terminal_transition(self) -> None:
        validate_transition("open", "triaged")
        with self.assertRaisesRegex(ValueError, "cannot transition"):
            validate_transition("resolved", "accepted")


if __name__ == "__main__":
    unittest.main()
