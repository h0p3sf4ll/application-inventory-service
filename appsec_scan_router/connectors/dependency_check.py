from .report_import import report_import_connector_definition


CONNECTOR_DEFINITION = report_import_connector_definition(
    "dependency_check",
    "OWASP Dependency-Check",
    "Configure the SARIF report location produced by OWASP Dependency-Check.",
)