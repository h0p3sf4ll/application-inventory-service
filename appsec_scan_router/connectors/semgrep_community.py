from .report_import import report_import_connector_definition


CONNECTOR_DEFINITION = report_import_connector_definition(
    "semgrep_community",
    "Semgrep Community",
    "Configure the local Semgrep Community JSON report location. Run semgrep --json, then upload the result from Findings.",
    report_format="Semgrep JSON",
    report_path_label="Semgrep JSON report path",
    connector_type="semgrep_json_profile",
)