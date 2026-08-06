"""Compatibility exports for the connector registry and service.

New connector integrations should define their metadata and factory in an
individual connector module, then register the definition in
``appsec_scan_router.connectors.registry``.
"""

from .connectors.registry import (
    CONNECTOR_KEYS,
    REPORT_IMPORT_CONNECTOR_KEYS,
    REMOTE_CONNECTOR_KEYS,
    ConnectorRegistry,
    DEFAULT_CONNECTOR_REGISTRY,
    connector_setup,
    normalize_connector_keys,
)
from .connectors.service import (
    ConnectorService,
    connector_status,
    public_connector_error,
)


__all__ = [
    "CONNECTOR_KEYS",
    "REPORT_IMPORT_CONNECTOR_KEYS",
    "REMOTE_CONNECTOR_KEYS",
    "ConnectorRegistry",
    "DEFAULT_CONNECTOR_REGISTRY",
    "ConnectorService",
    "connector_setup",
    "connector_status",
    "normalize_connector_keys",
    "public_connector_error",
]