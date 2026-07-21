from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from appsec_scan_router.aspm_cli import (
    build_parser,
    execute,
    finding_filters,
    ingest_payload,
)


class AspmCliTests(unittest.TestCase):
    def test_ingest_wraps_sarif_and_builds_complete_snapshot_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "results.sarif"
            source.write_text(
                json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8"
            )
            args = SimpleNamespace(
                file=source,
                format="auto",
                tool_key="codeql",
                tool_name="CodeQL",
                tool_type="sast",
                provider="github-enterprise",
                organization="ExampleEngineering",
                project="",
                repository="payments-api",
                branch="main",
                complete_snapshot=True,
            )

            payload = ingest_payload(args)

        self.assertEqual(payload["document"]["version"], "2.1.0")
        self.assertEqual(payload["tool"]["key"], "codeql")
        self.assertEqual(payload["scannedTargets"][0]["repository"], "payments-api")

    def test_finding_filters_preserve_multi_value_arguments(self) -> None:
        args = SimpleNamespace(
            severity=["critical", "high"],
            status=["open", "triaged"],
            risk_band=["critical"],
            tool=["codeql", "semgrep"],
            repository="payments",
            assignee="appsec",
            overdue=True,
            unassigned=False,
            unlinked=True,
        )

        filters = finding_filters(args)

        self.assertEqual(filters["severities"], ["critical", "high"])
        self.assertEqual(filters["tools"], ["codeql", "semgrep"])
        self.assertTrue(filters["overdue"])
        self.assertFalse(filters["has_asset"])

    def test_profile_update_merges_existing_context(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["profile", "42", "--business-owner", "Payments"])
        service = Mock()
        service.asset_profile.return_value = {
            "criticality": "high",
            "internet_exposed": True,
            "data_classification": "restricted",
            "business_owner": "",
            "technical_owner": "payments-platform",
            "tags": ["pci"],
        }
        service.update_asset_profile.return_value = {"business_owner": "Payments"}

        result = execute(service, args, parser)

        profile = service.update_asset_profile.call_args.args[1]
        self.assertEqual(profile["criticality"], "high")
        self.assertTrue(profile["internetExposed"])
        self.assertEqual(profile["businessOwner"], "Payments")
        self.assertEqual(profile["tags"], ["pci"])
        self.assertEqual(result["business_owner"], "Payments")

    def test_findings_export_uses_private_file_permissions(self) -> None:
        parser = build_parser()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "findings.json"
            args = parser.parse_args(
                ["findings", "--export", "json", "--output", str(output)]
            )
            service = Mock()
            service.export_findings.return_value = b"[]"

            result = execute(service, args, parser)

            self.assertEqual(output.read_bytes(), b"[]")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result["bytes"], 2)


if __name__ == "__main__":
    unittest.main()
