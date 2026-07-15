from __future__ import annotations

import io
import json
import unittest

from openpyxl import load_workbook

from appsec_scan_router.inventory_exports import rows_to_csv, rows_to_json, rows_to_xlsx


class InventoryExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.columns = ("repo_name", "score", "store_validation_passed")
        self.rows = [
            {
                "repo_name": '=HYPERLINK("https://example.test")',
                "score": 12,
                "store_validation_passed": True,
            }
        ]

    def test_csv_escapes_spreadsheet_formulas(self) -> None:
        content = rows_to_csv(self.rows, self.columns).decode("utf-8-sig")

        self.assertIn("'=HYPERLINK", content)

    def test_json_preserves_native_types(self) -> None:
        payload = json.loads(rows_to_json(self.rows))

        self.assertEqual(payload[0]["score"], 12)
        self.assertTrue(payload[0]["store_validation_passed"])

    def test_xlsx_is_filterable_and_formula_safe(self) -> None:
        workbook = load_workbook(
            io.BytesIO(rows_to_xlsx(self.rows, self.columns)), read_only=False
        )
        sheet = workbook["Inventory"]

        self.assertEqual(sheet.freeze_panes, "A2")
        self.assertEqual(sheet.auto_filter.ref, "A1:C1")
        self.assertEqual(sheet["A2"].value, '\'=HYPERLINK("https://example.test")')
        self.assertEqual(sheet["B2"].value, 12)


if __name__ == "__main__":
    unittest.main()
