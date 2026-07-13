from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import appsec_scan_router as scanner
import appsec_scan_router.github as github_module
import appsec_scan_router.scanner as scanner_module


class DomainAttributionTests(unittest.TestCase):
    def test_confirmed_deployment_domain_outranks_and_merges_configured_evidence(self):
        evidence = scanner.discover_web_domains(
            {
                "/deploy/ingress.yaml": "spec:\n  rules:\n    - host: app.acme.tested\n",
            },
            {"homepageUrl": "https://app.acme.tested/dashboard"},
            (
                {
                    "url": "https://app.acme.tested",
                    "source": "github:deployment_status",
                    "confidence": "confirmed",
                    "environment": "production",
                },
            ),
        )

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].domain, "app.acme.tested")
        self.assertEqual(evidence[0].confidence, "confirmed")
        self.assertEqual(evidence[0].environment, "production")
        self.assertEqual(
            evidence[0].sources,
            (
                "github:deployment_status",
                "repository:homepage",
                "source:/deploy/ingress.yaml:host:3",
            ),
        )

    def test_domain_configs_reject_credentials_dependencies_and_provider_hosts(self):
        evidence = scanner.discover_web_domains(
            {
                "/.github/workflows/deploy.yml": """
env:
  APP_URL: https://portal.acme.engineering
  DATABASE_HOST: db.acme.engineering
  OAUTH_ISSUER_URL: https://login.acme.engineering
  SOURCE_URL: https://github.com/acme/portal
""",
                "/deploy/values-production.yaml": """
ingress:
  hosts:
    - web.acme.engineering
""",
                "/Caddyfile": """
caddy.acme.engineering {
  reverse_proxy upstream.acme.engineering:8080
}
""",
            }
        )

        self.assertEqual(
            {item.domain for item in evidence},
            {"caddy.acme.engineering", "portal.acme.engineering", "web.acme.engineering"},
        )

    def test_cloud_service_names_are_labeled_as_inferred(self):
        evidence = scanner.discover_web_domains(
            {
                "/azure-pipelines.yml": "steps:\n  appName: inventory-web\n",
                "/deploy/fly.toml": 'app = "inventory-edge"\n',
            }
        )

        self.assertEqual(
            [(item.domain, item.confidence) for item in evidence],
            [
                ("inventory-edge.fly.dev", "inferred"),
                ("inventory-web.azurewebsites.net", "inferred"),
            ],
        )

    def test_reserved_placeholder_and_non_application_domains_are_rejected(self):
        rejected = (
            "http://localhost:8080",
            "https://example.com",
            "https://api.github.com/repos/acme/app",
            "https://service.invalid",
            "https://${APP_HOST}",
            "https://10.0.0.1",
        )

        for value in rejected:
            with self.subTest(value=value):
                self.assertIsNone(scanner.normalize_web_endpoint(value))

    def test_domain_columns_are_filter_friendly(self):
        evidence = scanner.discover_web_domains(
            {
                "/deploy/ingress.yml": "host: app.acme.engineering\nhost: api.acme.engineering\n",
            }
        )

        columns = scanner.web_domain_columns(evidence)

        self.assertEqual(columns["primary_web_domain"], "api.acme.engineering")
        self.assertEqual(columns["web_domains"], "api.acme.engineering; app.acme.engineering")
        self.assertEqual(columns["web_domain_status"], "configured")
        self.assertIn('"domain": "api.acme.engineering"', columns["web_domain_evidence"])

    def test_domain_deployment_files_are_selected_without_fetching_arbitrary_files(self):
        self.assertTrue(scanner.should_fetch_content("/.github/workflows/deploy.yml"))
        self.assertTrue(scanner.should_fetch_content("/deploy/values-production.yaml"))
        self.assertTrue(scanner.should_fetch_content("/infra/custom_domain.tf"))
        self.assertFalse(scanner.should_fetch_content("/infra/random_resource.tf"))
        self.assertFalse(scanner.should_fetch_content("/.env.production"))

    def test_web_scan_row_links_provider_domain_to_source_branch(self):
        class FakeClient:
            def list_repo_items(self, project_name, repo_id, branch_name):
                return [{"path": "/package.json"}, {"path": "/deploy/ingress.yaml"}]

            def fetch_file_content(self, project_name, repo_id, path, branch_name):
                if path == "/package.json":
                    return '{"name":"portal","version":"1.2.3","dependencies":{"react":"19.0.0"}}'
                return "host: configured.acme.engineering\n"

            def list_web_endpoints(self, project_name, repo_id, branch_name):
                return [
                    {
                        "url": "https://portal.acme.engineering",
                        "source": "github:deployment_status",
                        "confidence": "confirmed",
                        "environment": "production",
                    }
                ]

            def list_commits(self, **kwargs):
                return [
                    {
                        "author": {"name": "Alice", "email": "alice@acme.engineering"},
                        "committer": {"date": "2026-07-13T12:00:00Z"},
                    }
                ]

        target = scanner.RepoScanTarget(
            project_name="Acme",
            repo={
                "id": "Acme/portal",
                "name": "portal",
                "remoteUrl": "https://github.com/Acme/portal.git",
            },
            organization="Acme",
            provider="github-enterprise",
        )

        with ThreadPoolExecutor(max_workers=2) as executor:
            result = scanner.scan_branch(
                client=FakeClient(),
                target=target,
                branch_name="main",
                content_executor=scanner_module.BoundedExecutor(executor, 2),
                min_confidence_rank=1,
                max_commits_per_repo=1,
                branch_age_days=90,
                activity_mode="contributors",
                store_client=None,
            )

        self.assertIsNotNone(result)
        self.assertEqual(result["source_url"], "https://github.com/Acme/portal.git")
        self.assertEqual(result["branch_name"], "main")
        self.assertEqual(result["primary_web_domain"], "portal.acme.engineering")
        self.assertEqual(result["web_domain_status"], "confirmed")
        self.assertIn("configured.acme.engineering", result["web_domains"])


class GitHubDomainAttributionTests(unittest.TestCase):
    def test_github_pages_url_uses_repository_path(self):
        self.assertEqual(
            scanner.github_pages_url("Acme/portal"),
            "https://acme.github.io/portal",
        )
        self.assertEqual(
            scanner.github_pages_url("Acme/acme.github.io"),
            "https://acme.github.io",
        )

    def test_repository_metadata_retains_homepage_and_pages_url(self):
        client = object.__new__(github_module.GitHubEnterpriseClient)

        repo = client.repo_from_api(
            {
                "full_name": "Acme/portal",
                "name": "portal",
                "default_branch": "main",
                "homepage": "https://portal.acme.engineering",
                "has_pages": True,
            }
        )

        self.assertEqual(repo["homepageUrl"], "https://portal.acme.engineering")
        self.assertEqual(repo["pagesUrl"], "https://acme.github.io/portal")

    def test_successful_github_deployment_status_returns_environment_url(self):
        client = object.__new__(github_module.GitHubEnterpriseClient)

        def paginated(path, params=None, max_items=0):
            if path.endswith("/deployments"):
                return [
                    {"id": 100, "environment": "preview", "ref": "main"},
                    {"id": 101, "environment": "production", "ref": "main"},
                ]
            if path.endswith("/deployments/101/statuses"):
                return [
                    {
                        "state": "success",
                        "environment_url": "https://portal.acme.engineering",
                    }
                ]
            return []

        client._get_paginated = Mock(side_effect=paginated)

        with patch.dict("os.environ", {"APPLICATION_INVENTORY_GITHUB_DOMAIN_ENVIRONMENTS": "1"}):
            endpoints = client.list_web_endpoints("Acme", "Acme/portal", "main")

        self.assertEqual(
            endpoints,
            [
                {
                    "url": "https://portal.acme.engineering",
                    "source": "github:deployment_status",
                    "confidence": "confirmed",
                    "environment": "production",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
