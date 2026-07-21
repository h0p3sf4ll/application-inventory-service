from __future__ import annotations

import os
import unittest
import uuid
from io import BytesIO
from unittest.mock import patch

from openpyxl import load_workbook

from appsec_scan_router.aspm_ingest import parse_finding_document
from appsec_scan_router.aspm_postgres import AspmRepository
from appsec_scan_router.postgres import create_database_schema

try:
    import psycopg
    from psycopg import sql
except ImportError:
    psycopg = None
    sql = None


POSTGRES_TEST_DSN = os.getenv("APPLICATION_INVENTORY_TEST_POSTGRES_DSN", "")


@unittest.skipUnless(
    POSTGRES_TEST_DSN and psycopg and sql,
    "PostgreSQL integration DSN is not configured",
)
class AspmPostgresIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = f"aspm_test_{uuid.uuid4().hex[:12]}"
        with psycopg.connect(POSTGRES_TEST_DSN, autocommit=True) as connection:
            create_database_schema(
                connection, self.schema, "application_inventory_assets"
            )
            connection.execute(
                sql.SQL(
                    "INSERT INTO {runs} (scan_id, provider, organization, owner_user_id, owner_user_login, started_at) VALUES ('scan-1', 'github-enterprise', 'ExampleEngineering', 'user-a', 'alice', now())"
                ).format(runs=sql.Identifier(self.schema, "scan_runs"))
            )
            repository_id = connection.execute(
                sql.SQL(
                    "INSERT INTO {repositories} (owner_user_id, owner_user_login, provider, organization, project, repo_name, web_url) VALUES ('user-a', 'alice', 'github-enterprise', 'ExampleEngineering', '', 'payments-api', 'https://github.com/ExampleEngineering/payments-api') RETURNING repository_id"
                ).format(repositories=sql.Identifier(self.schema, "repositories"))
            ).fetchone()[0]
            self.branch_inventory_id = connection.execute(
                sql.SQL(
                    """
                    INSERT INTO {branches} (
                        repository_id, scan_id, owner_user_id, owner_user_login,
                        branch_name, inventory_name, primary_language, last_updated,
                        confidence, score, row_data, detection_evidence, scan_started_at
                    ) VALUES (%s, 'scan-1', 'user-a', 'alice', 'main', 'Payments API',
                              'Python', now(), 'high', 95, '{{}}'::jsonb, '{{}}'::jsonb, now())
                    RETURNING branch_inventory_id
                    """
                ).format(branches=sql.Identifier(self.schema, "branch_inventory")),
                (repository_id,),
            ).fetchone()[0]
            connection.execute(
                sql.SQL(
                    "INSERT INTO {types} (branch_inventory_id, inventory_type) VALUES (%s, 'api_service')"
                ).format(types=sql.Identifier(self.schema, "inventory_types")),
                (self.branch_inventory_id,),
            )
            connection.execute(
                sql.SQL(
                    "INSERT INTO {domains} (branch_inventory_id, domain, url, confidence, is_primary) VALUES (%s, 'payments.example.test', 'https://payments.example.test', 'confirmed', true)"
                ).format(domains=sql.Identifier(self.schema, "web_domains")),
                (self.branch_inventory_id,),
            )
        self.repository = AspmRepository(POSTGRES_TEST_DSN, self.schema)

    def tearDown(self) -> None:
        with psycopg.connect(POSTGRES_TEST_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {schema} CASCADE").format(
                    schema=sql.Identifier(self.schema)
                )
            )

    def test_findings_are_linked_deduplicated_scored_and_reconciled(self) -> None:
        payload = {
            "format": "generic",
            "tool": {"key": "codeql", "name": "CodeQL", "type": "sast"},
            "context": {
                "provider": "github-enterprise",
                "organization": "ExampleEngineering",
                "repository": "payments-api",
                "branch": "main",
            },
            "findings": [
                {
                    "id": "finding-1",
                    "title": "SQL injection",
                    "severity": "high",
                    "rule_id": "py/sql-injection",
                    "path": "src/db.py",
                    "line": 20,
                    "cwe": "CWE-89",
                    "cvss_score": 8.2,
                }
            ],
            "completeSnapshot": True,
            "scannedTargets": [
                {
                    "provider": "github-enterprise",
                    "organization": "ExampleEngineering",
                    "repository": "payments-api",
                    "branch": "main",
                }
            ],
        }

        first = self.repository.ingest(
            "user-a", "alice", parse_finding_document(payload)
        )
        second = self.repository.ingest(
            "user-a", "alice", parse_finding_document(payload)
        )

        self.assertEqual(first["inserted"], 1)
        self.assertEqual(first["assetsCovered"], 1)
        self.assertEqual(second["inserted"], 0)
        self.assertEqual(second["updated"], 1)
        search = self.repository.search_findings("user-a")
        self.assertEqual(search["total"], 1)
        finding = search["rows"][0]
        self.assertEqual(finding["branch_inventory_id"], self.branch_inventory_id)
        self.assertEqual(finding["primary_web_domain"], "payments.example.test")
        self.assertGreaterEqual(finding["risk_score"], 60)
        self.assertEqual(search["facets"]["tools"][0]["value"], "codeql")
        self.assertEqual(search["facets"]["tools"][0]["label"], "CodeQL")
        posture = self.repository.posture("user-a")
        self.assertEqual(posture["summary"]["assets"], 1)
        self.assertEqual(posture["summary"]["active_findings"], 1)
        self.assertEqual(posture["coverage"]["coverage_percent"], 100.0)
        coverage = self.repository.coverage("user-a")
        self.assertEqual(coverage["rows"][0]["coverage_status"], "current")
        self.assertEqual(coverage["rows"][0]["tools"], "CodeQL")

        updated = self.repository.update_finding(
            "user-a",
            "alice",
            finding["finding_id"],
            "triaged",
            assignee="payments-team",
            note="Confirmed by AppSec.",
        )
        self.assertEqual(updated["status"], "triaged")
        detail = self.repository.finding_detail("user-a", finding["finding_id"])
        self.assertEqual(detail["finding"]["assignee"], "payments-team")
        self.assertEqual(detail["events"][0]["event_type"], "workflow_updated")

        empty_snapshot = parse_finding_document(
            {
                "format": "generic",
                "tool": {"key": "codeql", "name": "CodeQL", "type": "sast"},
                "findings": [],
                "completeSnapshot": True,
                "scannedTargets": payload["scannedTargets"],
            }
        )
        reconciled = self.repository.ingest("user-a", "alice", empty_snapshot)
        self.assertEqual(reconciled["resolved"], 1)
        resolved = self.repository.search_findings(
            "user-a", filters={"statuses": ["resolved"]}
        )
        self.assertEqual(resolved["total"], 1)

        workbook = load_workbook(
            BytesIO(self.repository.export_findings("user-a", "xlsx")),
            read_only=True,
        )
        self.assertIn("Security Findings", workbook.sheetnames)
        self.assertEqual(sum(1 for _ in workbook["Security Findings"].iter_rows()), 2)

    def test_asset_profile_changes_recalculate_risk_and_owner_scope_is_enforced(
        self,
    ) -> None:
        payload = {
            "format": "generic",
            "tool": {"key": "sca", "name": "Dependency Scanner", "type": "sca"},
            "context": {
                "organization": "ExampleEngineering",
                "repository": "payments-api",
                "branch": "main",
            },
            "findings": [
                {
                    "id": "dependency-1",
                    "title": "Outdated dependency",
                    "severity": "medium",
                }
            ],
        }
        self.repository.ingest("user-a", "alice", parse_finding_document(payload))
        before = self.repository.search_findings("user-a")["rows"][0]["risk_score"]
        profile = self.repository.update_asset_profile(
            "user-a",
            "alice",
            self.branch_inventory_id,
            {
                "criticality": "mission_critical",
                "internetExposed": True,
                "dataClassification": "restricted",
                "businessOwner": "Payments",
                "technicalOwner": "payments-team",
                "tags": ["pci", "tier-0"],
            },
        )
        after = self.repository.search_findings("user-a")["rows"][0]["risk_score"]

        self.assertEqual(profile["criticality"], "mission_critical")
        stored_profile = self.repository.asset_profile(
            "user-a", self.branch_inventory_id
        )
        self.assertEqual(stored_profile["technical_owner"], "payments-team")
        self.assertEqual(stored_profile["tags"], ["pci", "tier-0"])
        self.assertGreater(after, before)
        self.assertEqual(self.repository.search_findings("user-b")["total"], 0)
        with self.assertRaises(KeyError):
            self.repository.update_asset_profile(
                "user-b", "bob", self.branch_inventory_id, {}
            )

    def test_failed_import_is_auditable_and_atomic(self) -> None:
        document = parse_finding_document(
            {
                "format": "generic",
                "tool": {"key": "failing-tool", "name": "Failing Tool"},
                "findings": [
                    {
                        "id": "finding-1",
                        "title": "Finding that cannot be persisted",
                        "severity": "high",
                    }
                ],
            }
        )

        with patch.object(
            self.repository,
            "_upsert_finding",
            side_effect=RuntimeError("simulated persistence failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated persistence failure"):
                self.repository.ingest("user-a", "alice", document)

        with psycopg.connect(
            POSTGRES_TEST_DSN, row_factory=psycopg.rows.dict_row
        ) as connection:
            imported = connection.execute(
                sql.SQL(
                    "SELECT status, error_count, error_message FROM {imports} WHERE owner_user_id = 'user-a' ORDER BY started_at DESC LIMIT 1"
                ).format(imports=sql.Identifier(self.schema, "aspm_imports"))
            ).fetchone()
            finding_count = connection.execute(
                sql.SQL("SELECT count(*) AS finding_count FROM {findings}").format(
                    findings=sql.Identifier(self.schema, "aspm_findings")
                )
            ).fetchone()["finding_count"]

        self.assertEqual(imported["status"], "failed")
        self.assertEqual(imported["error_count"], 1)
        self.assertIn("simulated persistence failure", imported["error_message"])
        self.assertEqual(finding_count, 0)


if __name__ == "__main__":
    unittest.main()
