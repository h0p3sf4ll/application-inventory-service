from .report_import import report_import_connector_definition


CONNECTOR_DEFINITION = report_import_connector_definition(
    "gitleaks",
    "Gitleaks",
    "Configure the SARIF report location produced by Gitleaks secrets detection.",
)