from .report_import import report_import_connector_definition


CONNECTOR_DEFINITION = report_import_connector_definition(
    "trivy",
    "Trivy",
    "Configure the SARIF report location produced by Trivy container, dependency, and IaC scans.",
)