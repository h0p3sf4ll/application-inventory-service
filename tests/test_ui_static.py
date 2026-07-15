import unittest
from html.parser import HTMLParser
from pathlib import Path

from appsec_scan_router.ui import static_cache_control


class UiStructureParser(HTMLParser):
    void_elements = {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }

    def __init__(self):
        super().__init__()
        self.stack = []
        self.ancestors_by_id = {}
        self.views = set()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        identifier = attributes.get("id")
        if identifier:
            self.ancestors_by_id[identifier] = tuple(
                ancestor_id for _, ancestor_id in self.stack if ancestor_id
            )
        if view := attributes.get("data-view"):
            self.views.add(view)
        if tag not in self.void_elements:
            self.stack.append((tag, identifier))

    def handle_endtag(self, tag):
        while self.stack:
            open_tag, _ = self.stack.pop()
            if open_tag == tag:
                return


class UiStaticTests(unittest.TestCase):
    def test_index_document_is_not_cached(self):
        self.assertEqual(static_cache_control("index.html"), "no-store, max-age=0")
        self.assertEqual(static_cache_control("styles.css"), "private, max-age=300")

    def test_inventory_table_has_its_own_navigation_view(self):
        index_path = (
            Path(__file__).resolve().parents[1]
            / "appsec_scan_router"
            / "ui_static"
            / "index.html"
        )
        parser = UiStructureParser()
        parser.feed(index_path.read_text(encoding="utf-8"))

        self.assertIn("inventoryView", parser.views)
        self.assertIn("databaseView", parser.views)
        table_ancestors = parser.ancestors_by_id["databaseResultRows"]
        self.assertIn("inventoryView", table_ancestors)
        self.assertNotIn("databaseView", table_ancestors)

    def test_language_has_a_sortable_multi_select_column(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        javascript = (static_root / "app.js").read_text(encoding="utf-8")

        self.assertIn('data-database-sort="language">Language', html)
        self.assertIn('id="filterLanguage"', html)
        self.assertIn('id="filterLanguageOptions"', html)
        self.assertIn('id="clearFilterLanguages"', html)
        self.assertIn('colspan="9"', html)
        self.assertIn("<td>${databaseCell(row.primary_language)}</td>", javascript)
        self.assertIn("filters.languages = languages", javascript)
        self.assertIn('input[name="databaseFilterLanguage"]', javascript)


if __name__ == "__main__":
    unittest.main()
