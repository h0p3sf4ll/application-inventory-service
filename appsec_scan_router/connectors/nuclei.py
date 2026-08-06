from .report_import import report_import_connector_definition


CONNECTOR_DEFINITION = report_import_connector_definition(
    "nuclei",
    "Nuclei",
    "Configure the SARIF report location produced by Nuclei exposure checks.",
)