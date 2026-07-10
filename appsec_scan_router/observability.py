from __future__ import annotations

import logging
import os
from typing import Any

from .constants import DEFAULT_POSTGRES_SCHEMA
from .postgres import PostgresLogHandler


LOGGER = logging.getLogger("appsec_scan_router")


def configure_logging(
    verbose: bool = False,
    dsn: str = "",
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    source: str = "service",
) -> dict[str, Any]:
    LOGGER.setLevel(logging.DEBUG if verbose else logging.INFO)
    LOGGER.propagate = False
    stream_handler = next(
        (handler for handler in LOGGER.handlers if getattr(handler, "application_inventory_stream", False)),
        None,
    )
    if stream_handler is None:
        stream_handler = logging.StreamHandler()
        stream_handler.application_inventory_stream = True
        stream_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
        LOGGER.addHandler(stream_handler)
    stream_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    resolved_dsn = observability_dsn(dsn)
    if resolved_dsn and not any(
        isinstance(handler, PostgresLogHandler)
        and handler.dsn == resolved_dsn
        and handler.schema == schema
        and handler.source == source
        for handler in LOGGER.handlers
    ):
        database_handler = PostgresLogHandler(resolved_dsn, schema=schema, source=source)
        database_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        LOGGER.addHandler(database_handler)

    return {
        "enabled": bool(resolved_dsn),
        "dsnConfigured": bool(resolved_dsn),
        "schema": schema,
        "table": f"{schema}.observability_events",
        "source": source,
    }


def observability_dsn(explicit_dsn: str = "") -> str:
    return str(explicit_dsn or "").strip() or env_value(
        "APPLICATION_INVENTORY_OBSERVABILITY_DSN",
        "APPSEC_INVENTORY_OBSERVABILITY_DSN",
        "APPLICATION_INVENTORY_POSTGRES_DSN",
        "APPSEC_INVENTORY_POSTGRES_DSN",
    )


def env_value(*names: str) -> str:
    for name in names:
        value = str(os.getenv(name) or "").strip()
        if value:
            return value
    return ""


def log_github_app_context(
    app_id: str,
    installation_id: str,
    scan_id: str = "",
    owner_user_id: str = "",
    owner_user_login: str = "",
) -> None:
    LOGGER.info(
        "GitHub App identifiers app_id=%s installation_id=%s",
        app_id,
        installation_id,
        extra={
            "event_type": "github_app.identifiers",
            "scan_id": scan_id,
            "owner_user_id": owner_user_id,
            "owner_user_login": owner_user_login,
            "metadata": {
                "app_id": app_id,
                "installation_id": installation_id,
            },
        },
    )
