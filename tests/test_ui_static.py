import io
import unittest
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import Mock

from appsec_scan_router.ui import (
    ApplicationInventoryServiceHandler,
    report_content_type,
    static_asset_bundle,
    static_asset_path,
    static_cache_control,
    static_content,
)


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
        self.assertEqual(report_content_type(Path("failures.log")), "text/plain")

    def test_posture_risk_chart_uses_csp_safe_svg_attributes(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        javascript = (static_root / "aspm" / "posture.js").read_text(
            encoding="utf-8"
        )
        stylesheet = (static_root / "styles.css").read_text(encoding="utf-8")

        self.assertIn('class="risk-pie"', javascript)
        self.assertIn("donutSegmentPath", javascript)
        self.assertIn("data-risk-severity", javascript)
        self.assertNotIn('style="width:${width}%"', javascript)
        self.assertIn(".risk-pie-segment", stylesheet)

    def test_nested_static_assets_are_served_without_path_traversal(self):
        posture_module = static_asset_path("aspm/posture.js")

        self.assertTrue(posture_module.is_file())
        self.assertEqual(static_content("aspm/posture.js"), posture_module.read_bytes())
        for unsafe_name in (
            "../ui.py",
            "aspm/../app.js",
            "%2e%2e/ui.py",
            "__init__.py",
            ".hidden.js",
        ):
            with self.assertRaises(FileNotFoundError):
                static_asset_path(unsafe_name)

    def test_static_asset_bundle_remains_stable_after_source_files_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            asset = root / "app.js"
            asset.write_bytes(b"before")

            bundle = static_asset_bundle(root)
            asset.write_bytes(b"after")

        self.assertEqual(bundle["app.js"], b"before")

    def test_static_asset_bundle_excludes_external_symlinks(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external_directory:
            root = Path(directory)
            external_asset = Path(external_directory) / "external.js"
            external_asset.write_bytes(b"external")
            (root / "external.js").symlink_to(external_asset)

            bundle = static_asset_bundle(root)

        self.assertNotIn("external.js", bundle)

    def test_static_handler_serves_captured_bundle(self):
        handler = object.__new__(ApplicationInventoryServiceHandler)
        handler.static_assets = {"app.js": b"captured"}
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.send_error = Mock()
        handler.wfile = io.BytesIO()

        handler.send_static("app.js", "text/javascript")

        self.assertEqual(handler.wfile.getvalue(), b"captured")
        handler.send_error.assert_not_called()

    def test_runs_view_has_a_dedicated_failure_console(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        javascript = (static_root / "app.js").read_text(encoding="utf-8")
        stylesheet = (static_root / "styles.css").read_text(encoding="utf-8")

        self.assertIn("<h2>Failures</h2>", html)
        self.assertIn('id="failureCount"', html)
        self.assertIn('id="clearFailures"', html)
        self.assertIn('id="downloadFailures"', html)
        self.assertIn('id="failures"', html)
        self.assertIn(
            "data.failure === true || isFailureLogLine(data.line)", javascript
        )
        self.assertIn('item.name === "failures.log"', javascript)
        self.assertIn(".failure-panel", stylesheet)
        self.assertIn(".failure-logs", stylesheet)

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

    def test_inventory_pagination_displays_filtered_record_count(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        javascript = (static_root / "app.js").read_text(encoding="utf-8")
        stylesheet = (static_root / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="databasePagePosition"', html)
        self.assertIn('id="databaseRecordCount"', html)
        self.assertIn('class="database-page-summary"', html)
        self.assertIn('search.total === 1 ? "matching record"', javascript)
        self.assertIn("Number(search.total).toLocaleString()", javascript)
        self.assertIn(".database-page-summary", stylesheet)

    def test_inventory_pagination_defaults_to_25_and_supports_larger_pages(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        javascript = (static_root / "app.js").read_text(encoding="utf-8")
        stylesheet = (static_root / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="databasePageSize"', html)
        self.assertIn('<option value="25" selected>25</option>', html)
        self.assertIn('<option value="50">50</option>', html)
        self.assertIn('<option value="100">100</option>', html)
        self.assertIn("limit: 25, offset: 0, loaded: false", javascript)
        self.assertIn('databasePageSize.addEventListener("change"', javascript)
        self.assertIn("[25, 50, 100].includes(limit)", javascript)
        self.assertIn(".database-page-size", stylesheet)

    def test_asset_risk_pagination_defaults_to_25_and_ignores_stale_responses(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        javascript = (static_root / "aspm-ui.js").read_text(encoding="utf-8")

        self.assertIn('id="assetRiskPageSize"', html)
        self.assertIn('aria-label="Asset risk rows per page"', html)
        self.assertIn(
            "assetRisks: {rows: [], total: 0, limit: 25, offset: 0", javascript
        )
        self.assertIn(
            'this.elements.assetRiskPageSize.addEventListener("change"', javascript
        )
        self.assertIn("[25, 50, 100].includes(limit)", javascript)
        self.assertIn("activeOnly: this.state.assetRisks.activeOnly === true", javascript)

    def test_findings_pagination_and_dense_table_layout(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        javascript = (static_root / "aspm-ui.js").read_text(encoding="utf-8")
        stylesheet = (static_root / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="findingPageSize"', html)
        self.assertIn('aria-label="Findings rows per page"', html)
        self.assertIn("findings: {rows: [], total: 0, limit: 25, offset: 0", javascript)
        self.assertIn(
            'this.elements.findingPageSize.addEventListener("change"', javascript
        )
        self.assertIn('this.state.busy.has("findings")', javascript)
        self.assertIn("requestId !== this.state.findingRequest", javascript)
        self.assertIn("const includeFacets = !this.state.findings.loaded", javascript)
        self.assertIn(".finding-table th:nth-child(9)", stylesheet)
        self.assertIn(".finding-responsibility small", stylesheet)
        self.assertIn("-webkit-line-clamp: 5", stylesheet)

    def test_active_scan_reconnects_and_merges_missed_console_output(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        javascript = (static_root / "app.js").read_text(encoding="utf-8")

        self.assertIn("await selectScan(state.scans[0]);", javascript)
        self.assertIn("syncScanOutput(refreshed);", javascript)
        self.assertIn("ensureScanEventStream(refreshed);", javascript)
        self.assertIn("state.eventSourceScanId !== scanId", javascript)
        self.assertIn("sequence <= state.logSequence", javascript)
        self.assertIn("scanEventStreamNeedsReconnect(scanId)", javascript)
        self.assertIn("Date.now() - lastActivity >= 10000", javascript)

    def test_record_details_gate_mobile_fields_and_separate_scanner_targets(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        javascript = (static_root / "app.js").read_text(encoding="utf-8")
        stylesheet = (static_root / "styles.css").read_text(encoding="utf-8")

        self.assertIn(
            'const isMobileApp = inventoryRecordHasType(row, "mobile_app")',
            javascript,
        )
        self.assertIn(
            '{label: "Store validation", value: storeValidationDetailValue(row)}',
            javascript,
        )
        self.assertIn('{label: "NowSecure target"', javascript)
        self.assertIn('class="inventory-detail-target"', javascript)
        self.assertIn(".inventory-dialog .inventory-detail-target", stylesheet)
        self.assertIn("grid-column: 1 / -1", stylesheet)

    def test_aspm_workspace_has_dedicated_posture_findings_and_coverage_views(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        app_javascript = (static_root / "app.js").read_text(encoding="utf-8")
        aspm_javascript = (static_root / "aspm-ui.js").read_text(encoding="utf-8")

        parser = UiStructureParser()
        parser.feed(html)
        self.assertIn("dashboardView", parser.views)
        self.assertIn("findingsView", parser.views)
        self.assertIn("coverageView", parser.views)
        self.assertIn('id="findingImportFile"', html)
        self.assertIn('id="findingDialog"', html)
        self.assertIn('id="coverageResultRows"', html)
        self.assertIn("new AspmWorkspace", app_javascript)
        self.assertIn('"/api/aspm/findings/import"', aspm_javascript)
        self.assertIn('"/api/aspm/findings/update"', aspm_javascript)
        self.assertIn('"/api/aspm/coverage"', aspm_javascript)

    def test_configuration_view_owns_connectors_webhooks_and_setup_wizard(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        index_path = static_root / "index.html"
        html = index_path.read_text(encoding="utf-8")
        parser = UiStructureParser()
        parser.feed(html)

        self.assertIn('data-view="databaseView"', html)
        self.assertIn(">Configuration</button>", html)
        self.assertIn("connectorGrid", parser.ancestors_by_id)
        self.assertIn("databaseView", parser.ancestors_by_id["connectorGrid"])
        self.assertNotIn("postureView", parser.ancestors_by_id["connectorGrid"])
        self.assertIn('id="webhookForm"', html)
        self.assertIn('id="webhookList"', html)
        self.assertIn('id="connectorSetupDialog"', html)
        self.assertIn('id="connectorSetupFields"', html)

    def test_configuration_frontend_manages_webhooks_and_connector_setup(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        app_javascript = (static_root / "app.js").read_text(encoding="utf-8")
        aspm_javascript = (static_root / "aspm-ui.js").read_text(encoding="utf-8")

        self.assertIn('"/api/configuration/webhooks"', app_javascript)
        self.assertIn('"/api/configuration/webhooks/save"', app_javascript)
        self.assertIn('"/api/configuration/webhooks/delete"', app_javascript)
        self.assertIn('"/api/configuration/webhooks/test"', app_javascript)
        self.assertIn("saveWebhook", app_javascript)
        self.assertIn("renderWebhooks", app_javascript)
        self.assertIn('"/api/configuration/connectors/save"', aspm_javascript)
        self.assertIn("openConnectorSetup", aspm_javascript)
        self.assertIn("saveConnectorSetup", aspm_javascript)
        self.assertIn("connector.syncReady", aspm_javascript)
        self.assertIn("Managed", aspm_javascript)
        self.assertNotIn("data-connector-import", aspm_javascript)
        self.assertIn("setup.importFormat", aspm_javascript)
        self.assertIn("const importFormat = importProfile", aspm_javascript)
        self.assertIn("connector.configured ? \"checked\"", aspm_javascript)
        self.assertIn('id="toggleFindingImport" type="button">Import findings</button>', html)
        self.assertIn("Semgrep Community JSON", html)
        self.assertIn('id="githubAppStatus"', html)
        self.assertIn('id="githubAppConfigurationStatus"', html)
        self.assertIn("state.githubApp", app_javascript)
        self.assertIn("renderGithubAppStatus", app_javascript)
        self.assertIn('id="remediationPolicyForm"', html)
        self.assertIn('id="remediationCriticalDays"', html)
        self.assertIn('id="saveRemediationPolicy"', html)
        self.assertIn("An active finding is overdue after its due date passes.", html)
        self.assertIn('"/api/configuration/remediation-policy/save"', app_javascript)
        self.assertIn('id="testConnectors"', html)
        self.assertIn("testConnections", aspm_javascript)
        self.assertIn('"/api/aspm/connectors/test"', aspm_javascript)

    def test_appsec_atlas_uses_left_navigation_and_visible_database_connection(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        stylesheet = (static_root / "styles.css").read_text(encoding="utf-8")
        aspm_javascript = (static_root / "aspm-ui.js").read_text(encoding="utf-8")

        self.assertIn("AppSec Atlas", html)
        self.assertIn("Application Security Posture Management", html)
        self.assertIn('class="app-nav app-sidebar-nav"', html)
        self.assertIn("grid-template-columns: 224px minmax(0, 1fr)", stylesheet)
        self.assertIn('id="databaseConnectionTitle"', html)
        self.assertIn(">Database connection</h3>", html)
        self.assertNotIn("<summary>\n                <span>Connection settings</span>", html)
        self.assertIn(">Configure</button>", aspm_javascript)

    def test_dashboard_kpis_drill_down_and_risk_chart_has_hover_details(self):
        static_root = (
            Path(__file__).resolve().parents[1] / "appsec_scan_router" / "ui_static"
        )
        html = (static_root / "index.html").read_text(encoding="utf-8")
        app_javascript = (static_root / "app.js").read_text(encoding="utf-8")
        aspm_javascript = (static_root / "aspm-ui.js").read_text(encoding="utf-8")
        posture_javascript = (static_root / "aspm" / "posture.js").read_text(encoding="utf-8")

        self.assertIn('data-view="dashboardView"', html)
        self.assertIn(">Dashboard</button>", html)
        self.assertIn('data-dashboard-action="affected-assets"', html)
        self.assertIn('data-dashboard-action="overdue"', html)
        self.assertIn('data-dashboard-action="average-risk"', html)
        self.assertNotIn('id="startScan"', html)
        self.assertNotIn('id="refreshScans"', html)
        self.assertIn(">Scan</button>", html)
        self.assertIn("openDashboardAction", aspm_javascript)
        self.assertIn("activateQuickFilter(\"overdue\")", aspm_javascript)
        self.assertIn("openPriorityApplicationFindings", aspm_javascript)
        self.assertIn("openStatusFindings", aspm_javascript)
        self.assertIn("data-priority-asset", aspm_javascript)
        self.assertIn("data-finding-status", aspm_javascript)
        self.assertIn("riskDistributionTooltip", aspm_javascript)
        self.assertIn("risk-pie-tooltip", posture_javascript)
        self.assertIn("data-risk-severity", posture_javascript)
        self.assertNotIn("startScanButton", app_javascript)
        self.assertNotIn("refreshButton", app_javascript)


if __name__ == "__main__":
    unittest.main()
