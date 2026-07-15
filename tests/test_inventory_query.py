from __future__ import annotations

import unittest

from appsec_scan_router.inventory_query import (
    InventoryQueryPlan,
    InventorySearchCriteria,
    canonical_repository_url,
    criteria_summary,
    repository_browse_url,
)


class InventorySearchCriteriaTests(unittest.TestCase):
    def test_repository_browse_url_prefers_the_browser_url(self) -> None:
        self.assertEqual(
            repository_browse_url(
                {
                    "web_url": "https://dev.azure.com/Example/Payments/_git/api",
                    "source_url": "https://user@dev.azure.com/Example/Payments/_git/api",
                }
            ),
            "https://dev.azure.com/Example/Payments/_git/api",
        )

    def test_repository_browse_url_sanitizes_clone_url_fallback(self) -> None:
        self.assertEqual(
            repository_browse_url(
                {
                    "web_url": "javascript:alert(1)",
                    "source_url": "https://user:token@github.example/Team/service.git?token=secret#readme",
                }
            ),
            "https://github.example/Team/service",
        )

    def test_canonical_repository_url_rejects_non_browser_urls(self) -> None:
        for value in (
            "javascript:alert(1)",
            "data:text/html,unsafe",
            "ssh://git@github.example/Team/service.git",
            "https://example.com\\@untrusted.example/repo",
            "https://example.com/repo\nunsafe",
        ):
            with self.subTest(value=value):
                self.assertEqual(canonical_repository_url(value), "")

    def test_normalizes_allowlisted_filters(self) -> None:
        criteria = InventorySearchCriteria.from_mapping(
            {
                "providers": ["github-enterprise", "unsupported"],
                "application_types": [
                    "web_app",
                    "microservice",
                    "made_up",
                    "web_app",
                ],
                "updated_within_days": 90,
                "has_domain": False,
                "application_search": "Inventory Service",
                "repository_search": "inventory-service",
                "branch_search": "main",
                "domain_search": "example.engineering",
                "sort_by": "source",
                "sort_direction": "asc",
                "ignored": "value",
            },
            text="  payment   service  ",
        )

        self.assertEqual(criteria.text, "payment service")
        self.assertEqual(criteria.providers, ("github-enterprise",))
        self.assertEqual(criteria.application_types, ("microservice", "web_app"))
        self.assertEqual(criteria.updated_within_days, 90)
        self.assertFalse(criteria.has_domain)
        self.assertEqual(criteria.application_search, "Inventory Service")
        self.assertEqual(criteria.repository_search, "inventory-service")
        self.assertEqual(criteria.branch_search, "main")
        self.assertEqual(criteria.domain_search, "example.engineering")
        self.assertEqual(criteria.sort_by, "source")
        self.assertEqual(criteria.sort_direction, "asc")
        self.assertNotIn("ignored", criteria.as_dict())

    def test_rejects_unstructured_day_values_without_raising(self) -> None:
        criteria = InventorySearchCriteria.from_mapping({"older_than_days": [90]})

        self.assertIsNone(criteria.older_than_days)

    def test_language_filters_are_multi_select_and_sortable(self) -> None:
        criteria = InventorySearchCriteria.from_mapping(
            {
                "languages": ["Python", "Go", "Python", ""],
                "sort_by": "language",
                "sort_direction": "asc",
            }
        )

        self.assertEqual(criteria.languages, ("Go", "Python"))
        self.assertEqual(criteria.sort_by, "language")
        self.assertEqual(criteria.sort_direction, "asc")

    def test_query_plan_defaults_exports_to_xlsx(self) -> None:
        plan = InventoryQueryPlan.from_mapping(
            {
                "action": "export",
                "application_types": ["mobile_app"],
                "store_validation_passed": True,
            }
        )

        self.assertEqual(plan.action, "export")
        self.assertEqual(plan.export_format, "xlsx")
        self.assertIn("Mobile app", criteria_summary(plan.criteria))


if __name__ == "__main__":
    unittest.main()
