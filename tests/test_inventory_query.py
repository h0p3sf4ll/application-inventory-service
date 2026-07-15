from __future__ import annotations

import unittest

from appsec_scan_router.inventory_query import (
    InventoryQueryPlan,
    InventorySearchCriteria,
    criteria_summary,
)


class InventorySearchCriteriaTests(unittest.TestCase):
    def test_normalizes_allowlisted_filters(self) -> None:
        criteria = InventorySearchCriteria.from_mapping(
            {
                "providers": ["github-enterprise", "unsupported"],
                "application_types": ["web_app", "made_up"],
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
        self.assertEqual(criteria.application_types, ("web_app",))
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
