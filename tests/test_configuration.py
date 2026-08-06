from __future__ import annotations

import tempfile
import time
import unittest
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch

from appsec_scan_router.auth import AuthenticatedUser, CredentialStore, SessionRecord
from appsec_scan_router.connectors.registry import (
    CONNECTOR_KEYS,
    connector_setup,
    normalize_connector_keys,
)
from appsec_scan_router.github import github_app_public_config
from appsec_scan_router.integrations import (
    connector_configurations,
    default_integrations,
    public_connector_configuration,
    public_webhooks,
    webhook_environment_value,
    upsert_connector_configuration,
    upsert_webhook,
    webhook_configurations,
    remediation_policy,
    upsert_remediation_policy,
)
from appsec_scan_router.ui import ApplicationInventoryServiceHandler
from appsec_scan_router.ui import scan_environment_for_user


class UserIntegrationStoreTests(unittest.TestCase):
    def test_user_integrations_are_isolated_and_encrypted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = CredentialStore(Path(directory))
            user_a_integrations = {
                "webhooks": [
                    {
                        "id": "webhook-a",
                        "url": "https://servicenow.example.test/api/import",
                        "bearerToken": "user-a-webhook-token",
                    }
                ],
                "connectors": {
                    "sonarqube": {
                        "endpoint": "https://sonar.example.test",
                        "token": "user-a-scanner-token",
                    }
                },
            }
            store.save_integrations("user-a", user_a_integrations)
            store.save_integrations("user-b", {"webhooks": [], "connectors": {}})

            self.assertEqual(store.integrations("user-a"), user_a_integrations)
            self.assertEqual(store.integrations("user-b"), {"webhooks": [], "connectors": {}})
            encrypted = store.credentials_path.read_bytes()

        self.assertNotIn(b"user-a-webhook-token", encrypted)
        self.assertNotIn(b"user-a-scanner-token", encrypted)

    def test_webhook_management_hides_secrets_and_builds_enabled_publishers(self) -> None:
        integrations = upsert_webhook(
            default_integrations(),
            {
                "name": "ServiceNow CMDB",
                "url": "https://servicenow.example.test/api/now/import/cmdb_ci",
                "enabled": True,
                "bearerToken": "service-token",
                "signingSecret": "signing-secret",
                "headers": {"X-Instance": "cmdb"},
                "deliveryMode": "record",
            },
        )

        visible = public_webhooks(integrations)
        publishers = webhook_configurations(integrations)

        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]["name"], "ServiceNow CMDB")
        self.assertTrue(visible[0]["hasBearerToken"])
        self.assertTrue(visible[0]["hasSigningSecret"])
        self.assertEqual(visible[0]["headerNames"], ["X-Instance"])
        self.assertNotIn("bearerToken", visible[0])
        self.assertNotIn("signingSecret", visible[0])
        self.assertEqual(len(publishers), 1)
        self.assertEqual(publishers[0].delivery_mode, "record")
        self.assertEqual(publishers[0].headers, (("X-Instance", "cmdb"),))

    def test_open_source_scanners_have_self_hosted_api_setup_metadata(self) -> None:
        self.assertIn("sonarqube", CONNECTOR_KEYS)
        self.assertIn("zap", CONNECTOR_KEYS)
        self.assertEqual(connector_setup("sonarqube")["type"], "self_hosted_api")
        self.assertEqual(connector_setup("zap")["type"], "self_hosted_api")
        self.assertEqual(
            [field["key"] for field in connector_setup("sonarqube")["fields"]],
            ["endpoint", "token"],
        )
        self.assertEqual(
            [field["key"] for field in connector_setup("zap")["fields"]],
            ["endpoint", "apiKey"],
        )

    def test_semgrep_enterprise_and_community_use_distinct_connector_modes(self) -> None:
        enterprise = connector_setup("semgrep")
        community = connector_setup("semgrep_community")

        self.assertIn("semgrep", CONNECTOR_KEYS)
        self.assertIn("semgrep_community", CONNECTOR_KEYS)
        self.assertTrue(enterprise["serviceManaged"])
        self.assertEqual(enterprise["type"], "cloud_api")
        self.assertEqual(community["type"], "semgrep_json_profile")
        self.assertFalse(community["serviceManaged"])
        self.assertEqual(community["importFormat"], "Semgrep JSON")
        self.assertEqual(
            [field["key"] for field in community["fields"]], ["reportPath"]
        )

    def test_core_integrations_are_service_managed_and_popular_report_scanners_are_available(self) -> None:
        for connector in ("semgrep", "invicti", "nowsecure"):
            with self.subTest(connector=connector):
                self.assertTrue(connector_setup(connector)["serviceManaged"])
        self.assertNotIn("defectdojo", CONNECTOR_KEYS)
        for connector in ("trivy", "gitleaks", "nuclei", "dependency_check"):
            with self.subTest(connector=connector):
                self.assertIn(connector, CONNECTOR_KEYS)
                self.assertEqual(connector_setup(connector)["type"], "sarif_profile")

    def test_remote_sync_excludes_report_import_only_scanners(self) -> None:
        selected = normalize_connector_keys(None)

        self.assertNotIn("trivy", selected)
        self.assertNotIn("gitleaks", selected)
        self.assertNotIn("semgrep_community", selected)
        self.assertIn("semgrep", selected)
        self.assertIn("sonarqube", selected)
        with self.assertRaisesRegex(ValueError, "imported from a report"):
            normalize_connector_keys(["nuclei"])
        with self.assertRaisesRegex(ValueError, "imported from a report"):
            normalize_connector_keys(["semgrep_community"])

    def test_github_app_status_exposes_configuration_without_key_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pem_file = Path(directory) / "github-app.pem"
            pem_file.write_text(
                "-----BEGIN PRIVATE KEY-----\nprivate-key-material\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "APPLICATION_INVENTORY_GITHUB_APP_ID": "123",
                    "APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID": "456",
                    "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE": str(pem_file),
                },
                clear=True,
            ):
                status = github_app_public_config()

        self.assertTrue(status["configured"])
        self.assertEqual(status["appId"], "123")
        self.assertEqual(status["installationId"], "456")
        self.assertEqual(status["keySource"], "pem_file")
        self.assertNotIn("private-key-material", repr(status))
        self.assertNotIn("privateKeyFile", status)

    def test_user_remediation_policy_is_validated_and_persisted(self) -> None:
        integrations = upsert_remediation_policy(
            default_integrations(),
            {"critical": 2, "high": 14, "medium": 60, "low": 120, "info": 365},
        )

        self.assertEqual(
            remediation_policy(integrations),
            {"critical": 2, "high": 14, "medium": 60, "low": 120, "info": 365},
        )

    def test_connector_configuration_hides_secrets_and_preserves_existing_values(self) -> None:
        integrations = upsert_connector_configuration(
            default_integrations(),
            "sonarqube",
            {"endpoint": "https://sonar.example.test", "token": "first-token"},
        )
        integrations = upsert_connector_configuration(
            integrations,
            "sonarqube",
            {"endpoint": "https://sonar.example.test"},
        )

        public = public_connector_configuration(integrations, "sonarqube")
        configured = connector_configurations(integrations)

        self.assertEqual(public["endpoint"], "https://sonar.example.test")
        self.assertTrue(public["secrets"]["token"])
        self.assertNotIn("token", public)
        self.assertEqual(configured["sonarqube"]["token"], "first-token")

    def test_configuration_webhook_save_scopes_data_to_current_user(self) -> None:
        record = SessionRecord(
            "session-a",
            AuthenticatedUser("user-a", "user-a@example.test"),
            "csrf-token",
            time.time() + 60,
        )
        handler = object.__new__(ApplicationInventoryServiceHandler)
        handler.auth = Mock()
        handler.auth.integrations.return_value = default_integrations()
        handler.current_session = Mock(return_value=record)
        handler.valid_csrf = Mock(return_value=True)
        handler.read_json = Mock(
            return_value={
                "webhook": {
                    "name": "ServiceNow",
                    "url": "https://servicenow.example.test/api/import",
                    "bearerToken": "private-token",
                }
            }
        )
        handler.send_json = Mock()

        handler.handle_configuration_webhook_save()

        owner, saved = handler.auth.save_integrations.call_args.args
        response = handler.send_json.call_args.args[0]
        self.assertEqual(owner, "user-a")
        self.assertEqual(saved["webhooks"][0]["bearerToken"], "private-token")
        self.assertTrue(response["webhook"]["hasBearerToken"])
        self.assertNotIn("bearerToken", response["webhook"])

    def test_configuration_routes_are_registered_for_post_requests(self) -> None:
        routes = {
            "/api/configuration/connectors": "handle_configuration_connectors",
            "/api/configuration/webhooks": "handle_configuration_webhooks",
            "/api/configuration/remediation-policy": "handle_configuration_remediation_policy",
        }
        for path, method_name in routes.items():
            with self.subTest(path=path):
                handler = object.__new__(ApplicationInventoryServiceHandler)
                handler.path = path
                handler.send_error = Mock()
                endpoint = Mock()
                setattr(handler, method_name, endpoint)

                handler.do_POST()

                endpoint.assert_called_once_with()
                handler.send_error.assert_not_called()

    def test_configuration_remediation_policy_save_updates_user_policy(self) -> None:
        record = SessionRecord(
            "session-a",
            AuthenticatedUser("user-a", "user-a@example.test"),
            "csrf-token",
            time.time() + 60,
        )
        handler = object.__new__(ApplicationInventoryServiceHandler)
        handler.auth = Mock()
        handler.auth.integrations.return_value = default_integrations()
        handler.current_session = Mock(return_value=record)
        handler.valid_csrf = Mock(return_value=True)
        handler.read_json = Mock(
            return_value={
                "postgresEnabled": True,
                "postgresHost": "localhost",
                "postgresPort": 5432,
                "postgresDatabase": "postgres",
                "postgresUser": "postgres",
                "postgresPassword": "postgres",
                "postgresSchema": "application_inventory",
                "postgresTable": "application_inventory_assets",
                "policy": {"critical": 2, "high": 14, "medium": 60, "low": 120, "info": 365},
            }
        )
        handler.send_json = Mock()

        with patch("appsec_scan_router.ui.AspmRepository") as repository_class:
            repository_class.return_value.update_remediation_policy.return_value = {
                "policy": {"critical": 2, "high": 14, "medium": 60, "low": 120, "info": 365},
                "updatedFindings": 8,
            }
            handler.handle_configuration_remediation_policy_save()

        owner, integrations = handler.auth.save_integrations.call_args.args
        response, status = handler.send_json.call_args.args
        self.assertEqual(owner, "user-a")
        self.assertEqual(remediation_policy(integrations)["critical"], 2)
        repository_class.return_value.update_remediation_policy.assert_called_once()
        self.assertEqual(response["remediation"]["updatedFindings"], 8)
        self.assertEqual(status, 201)

    def test_enabled_webhooks_serialize_only_for_child_environment(self) -> None:
        integrations = upsert_webhook(
            default_integrations(),
            {
                "name": "Enabled webhook",
                "url": "https://servicenow.example.test/api/import",
                "enabled": True,
                "bearerToken": "delivery-token",
            },
        )
        integrations = upsert_webhook(
            integrations,
            {
                "name": "Disabled webhook",
                "url": "https://disabled.example.test/api/import",
                "enabled": False,
                "bearerToken": "disabled-token",
            },
        )

        serialized = webhook_environment_value(integrations)

        self.assertEqual(
            json.loads(serialized),
            [
                {
                    "url": "https://servicenow.example.test/api/import",
                    "headers": {},
                    "bearerToken": "delivery-token",
                    "signingSecret": "",
                    "timeoutSeconds": 30,
                    "batchSize": 100,
                    "retries": 3,
                    "deliveryMode": "batch",
                }
            ],
        )

    def test_scan_environment_injects_user_webhooks_without_mutating_scan_config(self) -> None:
        integrations = upsert_webhook(
            default_integrations(),
            {
                "name": "ServiceNow",
                "url": "https://servicenow.example.test/api/import",
                "bearerToken": "delivery-token",
            },
        )
        auth = Mock()
        auth.integrations.return_value = integrations
        config = {
            "provider": "azure-devops",
            "ownerUserId": "user-a",
            "ownerUserLogin": "user-a@example.test",
            "postgresEnabled": False,
        }

        environment = scan_environment_for_user(config, auth)

        self.assertEqual(
            json.loads(environment["APPLICATION_INVENTORY_WEBHOOK_CONFIGURATIONS"])[0]["bearerToken"],
            "delivery-token",
        )
        self.assertNotIn("webhookConfigurations", config)
        auth.integrations.assert_called_once_with("user-a")


if __name__ == "__main__":
    unittest.main()