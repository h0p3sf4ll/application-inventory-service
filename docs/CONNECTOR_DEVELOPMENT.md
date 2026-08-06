# Adding a Connector

AppSec Atlas connector implementations live in `appsec_scan_router/connectors/`. A connector is registered through a `ConnectorDefinition`; the registry uses that definition to create the connector, expose its configuration in the UI, and determine whether it can be synchronized remotely.

## Choose the Connector Mode

Use a remote connector when AppSec Atlas should call a scanner API. Remote connectors implement `status()`, `pull()`, and `close()` and use the default `remote_sync=True` registration. Implementing `test_connection()` is optional, but enables the UI's **Test connections** action.

Use a report-import connector when users upload scanner output through **Findings**. These profiles must set `remote_sync=False` so they cannot be selected for API synchronization. For SARIF and Semgrep JSON profiles, reuse `report_import_connector_definition()` from `connectors/report_import.py` rather than duplicating the report-only behavior.

## Implement a Remote Connector

Create a module such as `appsec_scan_router/connectors/example.py`. Export exactly one `CONNECTOR_DEFINITION` and keep its key lower-case and stable. `ConnectorRegistry` rejects duplicate or non-normalized keys.

```python
from collections.abc import Mapping
from typing import Any

from .models import (
    ConnectorDefinition,
    ConnectorField,
    ConnectorPullResult,
    ConnectorStatus,
)


class ExampleConnector:
    key = "example"
    name = "Example Scanner"

    def __init__(
        self,
        timeout_seconds: int = 30,
        configuration: Mapping[str, Any] | None = None,
    ) -> None:
        settings = dict(configuration or {})
        self.endpoint = str(settings.get("endpoint") or "").strip()
        self.token = str(settings.get("token") or "").strip()
        self.timeout_seconds = timeout_seconds

    def status(self) -> ConnectorStatus:
        missing = []
        if not self.endpoint:
            missing.append("endpoint")
        if not self.token:
            missing.append("token")
        return ConnectorStatus(
            self.key,
            self.name,
            not missing,
            self.endpoint,
            "Ready" if not missing else f"Configure {', '.join(missing)}.",
        )

    def pull(self) -> ConnectorPullResult:
        # Fetch scanner data and normalize it into a FindingDocument.
        raise NotImplementedError

    def close(self) -> None:
        # Close any HTTP clients or other external resources.
        return None


CONNECTOR_DEFINITION = ConnectorDefinition(
    key=ExampleConnector.key,
    name=ExampleConnector.name,
    connector_type="hosted_api",
    service_managed=True,
    description="Example Scanner findings API.",
    fields=(
        ConnectorField("endpoint", "API URL", required=True),
        ConnectorField("token", "API token", required=True, secret=True),
    ),
    factory=ExampleConnector,
)
```

`pull()` must return a `ConnectorPullResult` whose `document` is a normalized `FindingDocument`. Use stable source identifiers for `FindingInput.external_id`, populate `SourceLocation` with the strongest available repository, branch, domain, or mobile-package anchor, and set `complete_snapshot=True` only when the response is the complete result set for every scanned target. Follow the nearby vendor implementations for pagination, bounded batches, retry behavior, and source-specific normalization.

Configuration supplied by the account setup wizard is passed to the factory. A connector may also support deployment environment variables, as the existing direct connectors do. Never include tokens, credentials, or raw sensitive request data in `ConnectorStatus`, exceptions, observability logs, returned metadata, or tests. Mark every secret setup field with `secret=True`; the UI then stores it encrypted and does not return its value to the browser.

## Register the Connector

Add the definition import and the definition itself to `DEFAULT_CONNECTOR_REGISTRY` in `appsec_scan_router/connectors/registry.py`.

```python
from .example import CONNECTOR_DEFINITION as EXAMPLE_CONNECTOR


DEFAULT_CONNECTOR_REGISTRY = ConnectorRegistry(
    (
        # Existing definitions...
        EXAMPLE_CONNECTOR,
    )
)
```

Registration is the only wiring needed for `ConnectorService`, the ASPM CLI, and the configuration UI. The definition's `fields`, `description`, `connector_type`, `service_managed`, and `remote_sync` values drive their public behavior.

For a new public compatibility import, add a small forwarding module such as `appsec_scan_router/example_connector.py` that re-exports from `appsec_scan_router.connectors.example`. New internal code should import the package module directly, not the compatibility shim.

## Test and Document It

Add focused tests in `tests/test_aspm_connectors.py` for configuration validation, API normalization, pagination or batching, and cleanup. Mock upstream HTTP clients; tests must not require a scanner account or network access. Add registry and setup metadata assertions in `tests/test_configuration.py`, including the expected field keys and whether the connector is eligible for remote synchronization.

Update the direct-connector table in `docs/ASPM_OPERATIONS.md` with the collection method, required configuration, and correlation anchors. Add scanner-specific environment variables, rate-limit behavior, and vendor reference links there when they affect operators.

Run the focused checks before opening a change:

```bash
.venv/bin/python -m unittest tests.test_aspm_connectors tests.test_configuration
.venv/bin/python -m ruff check appsec_scan_router/connectors tests/test_aspm_connectors.py tests/test_configuration.py
```

Run the full suite for changes that affect the shared registry, normalization, or configuration flow:

```bash
.venv/bin/python -m unittest discover -s tests
```