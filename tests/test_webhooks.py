from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import appsec_scan_router.scanner as scanner_module
from appsec_scan_router.cli import parse_args
from appsec_scan_router.models import ScanConfig
from appsec_scan_router.webhooks import WebhookConfig, WebhookPublisher, configured_webhooks


class FakeResponse:
    status_code = 202
    text = "accepted"

    def close(self) -> None:
        return None


class FakeSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def post(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        return FakeResponse()

    def close(self) -> None:
        return None


class WebhookPublisherTests(unittest.TestCase):
    def test_batch_delivery_preserves_complete_records_and_signs_payload(self) -> None:
        session = FakeSession()
        config = WebhookConfig.from_values(
            "https://servicenow.example.test/api/now/import/app_inventory",
            bearer_token="service-token",
            signing_secret="webhook-secret",
            batch_size=2,
        )
        publisher = WebhookPublisher(
            config,
            "application_inventory.inventory.scan",
            session=session,
            sleep=lambda seconds: None,
        )
        first_row = {
            "repo_name": "payments-api",
            "score": 91,
            "store_validation_passed": True,
            "web_domain_evidence": [{"domain": "payments.example.test"}],
            "synced_at": datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
        }

        publisher.publish(first_row)
        publisher.publish({"repo_name": "checkout-web", "score": 75})
        result = publisher.finish()

        self.assertEqual(result.records, 2)
        self.assertEqual(result.batches, 1)
        self.assertEqual(len(session.calls), 1)
        call = session.calls[0]
        self.assertEqual(call["url"], config.url)
        payload = call["data"]
        self.assertIsInstance(payload, bytes)
        body = json.loads(payload)
        self.assertEqual(body["event"], "application_inventory.inventory.scan")
        self.assertEqual(body["records"][0]["score"], 91)
        self.assertTrue(body["records"][0]["store_validation_passed"])
        self.assertEqual(
            body["records"][0]["web_domain_evidence"],
            [{"domain": "payments.example.test"}],
        )
        self.assertEqual(body["records"][0]["synced_at"], "2026-08-01T12:00:00+00:00")
        headers = call["headers"]
        self.assertIsInstance(headers, dict)
        self.assertEqual(headers["Authorization"], "Bearer service-token")
        self.assertEqual(
            headers["X-Application-Inventory-Signature"],
            "sha256=" + hmac.new(b"webhook-secret", payload, hashlib.sha256).hexdigest(),
        )

    def test_scan_streams_complete_result_rows_to_configured_webhook(self) -> None:
        webhook = WebhookConfig.from_values("https://servicenow.example.test/api/import")
        row = {
            "repo_name": "payments-api",
            "score": 91,
            "web_domain_evidence": '[{"domain":"payments.example.test"}]',
        }
        publisher = Mock()

        def scan(config, on_result=None, retain_results=True):
            self.assertFalse(retain_results)
            self.assertIsNotNone(on_result)
            on_result(row)
            return []

        with tempfile.TemporaryDirectory() as directory:
            config = ScanConfig(
                org="example",
                pat="token",
                project=None,
                out_dir=Path(directory),
                out_prefix="inventory",
                max_workers=1,
                content_workers=1,
                max_commits_per_repo=1,
                timeout_seconds=1,
                min_confidence="low",
                webhook=webhook,
            )
            with (
                patch.object(scanner_module, "WebhookPublisher", return_value=publisher),
                patch.object(scanner_module, "validate_scan_source_access"),
                patch.object(scanner_module, "scan", side_effect=scan),
            ):
                result = scanner_module.write_scan_reports(config, retain_results=False)

        self.assertEqual(result[1], 1)
        publisher.publish.assert_called_once_with(row)
        publisher.finish.assert_called_once_with()
        publisher.close.assert_called_once_with()

    def test_scan_fans_out_complete_rows_to_every_configured_webhook(self) -> None:
        first_webhook = WebhookConfig.from_values("https://one.example.test/api/import")
        second_webhook = WebhookConfig.from_values("https://two.example.test/api/import")
        row = {"repo_name": "payments-api", "web_domain_evidence": "[]"}
        first_publisher = Mock()
        second_publisher = Mock()

        def scan(config, on_result=None, retain_results=True):
            on_result(row)
            return []

        with tempfile.TemporaryDirectory() as directory:
            config = ScanConfig(
                org="example",
                pat="token",
                project=None,
                out_dir=Path(directory),
                out_prefix="inventory",
                max_workers=1,
                content_workers=1,
                max_commits_per_repo=1,
                timeout_seconds=1,
                min_confidence="low",
                webhooks=(first_webhook, second_webhook),
            )
            with (
                patch.object(
                    scanner_module,
                    "WebhookPublisher",
                    side_effect=(first_publisher, second_publisher),
                ),
                patch.object(scanner_module, "validate_scan_source_access"),
                patch.object(scanner_module, "scan", side_effect=scan),
            ):
                scanner_module.write_scan_reports(config, retain_results=False)

        for publisher in (first_publisher, second_publisher):
            publisher.publish.assert_called_once_with(row)
            publisher.finish.assert_called_once_with()
            publisher.close.assert_called_once_with()

    def test_record_delivery_posts_each_complete_record(self) -> None:
        session = FakeSession()
        config = WebhookConfig.from_values(
            "https://servicenow.example.test/api/now/import/app_inventory",
            delivery_mode="record",
        )
        publisher = WebhookPublisher(
            config,
            "application_inventory.inventory.scan",
            session=session,
            sleep=lambda seconds: None,
        )

        publisher.publish({"repo_name": "payments-api", "score": 91})
        publisher.publish({"repo_name": "checkout-web", "score": 75})
        result = publisher.finish()

        self.assertEqual(result.records, 2)
        self.assertEqual(result.batches, 2)
        self.assertEqual(
            [json.loads(call["data"]) for call in session.calls],
            [
                {"repo_name": "payments-api", "score": 91},
                {"repo_name": "checkout-web", "score": 75},
            ],
        )
        self.assertTrue(
            all(
                call["headers"]["X-Application-Inventory-Event"]
                == "application_inventory.inventory.scan"
                for call in session.calls
            )
        )

    def test_scan_cli_builds_webhook_configuration(self) -> None:
        with patch.dict(os.environ, {"ADO_PAT": "token"}, clear=False):
            config = parse_args(
                [
                    "--org",
                    "example",
                    "--webhook-url",
                    "https://servicenow.example.test/api/now/import/app_inventory",
                    "--webhook-bearer-token",
                    "service-token",
                    "--webhook-header",
                    "X-ServiceNow-Table=cmdb_ci",
                    "--webhook-batch-size",
                    "25",
                    "--webhook-delivery-mode",
                    "record",
                ]
            )

        self.assertIsNotNone(config.webhook)
        self.assertEqual(config.webhook.url, "https://servicenow.example.test/api/now/import/app_inventory")
        self.assertEqual(config.webhook.bearer_token, "service-token")
        self.assertEqual(config.webhook.headers, (("X-ServiceNow-Table", "cmdb_ci"),))
        self.assertEqual(config.webhook.batch_size, 25)
        self.assertEqual(config.webhook.delivery_mode, "record")

    def test_child_environment_supports_multiple_webhook_configurations(self) -> None:
        values = [
            {
                "url": "https://one.example.test/api/import",
                "headers": {"X-Target": "one"},
                "bearerToken": "token-one",
                "deliveryMode": "record",
            },
            {
                "url": "https://two.example.test/api/import",
                "headers": {},
                "signingSecret": "secret-two",
                "batchSize": 25,
            },
        ]
        with patch.dict(
            os.environ,
            {"APPLICATION_INVENTORY_WEBHOOK_CONFIGURATIONS": json.dumps(values)},
            clear=False,
        ):
            configurations = configured_webhooks()

        self.assertEqual([item.url for item in configurations], [item["url"] for item in values])
        self.assertEqual(configurations[0].headers, (("X-Target", "one"),))
        self.assertEqual(configurations[0].delivery_mode, "record")
        self.assertEqual(configurations[1].signing_secret, "secret-two")
        self.assertEqual(configurations[1].batch_size, 25)


if __name__ == "__main__":
    unittest.main()