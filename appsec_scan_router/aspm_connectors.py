from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from .aspm_connector_http import ConnectorConfigurationError, ConnectorError
from .aspm_connector_models import FindingsConnector
from .aspm_postgres import AspmRepository
from .invicti_connector import InvictiConnector
from .nowsecure_connector import NowSecureConnector
from .semgrep_connector import SemgrepConnector


LOGGER = logging.getLogger("appsec_scan_router")
CONNECTOR_KEYS = ("semgrep", "invicti", "nowsecure")


class ConnectorService:
    def __init__(
        self,
        repository: AspmRepository,
        owner_user_id: str,
        owner_user_login: str,
        timeout_seconds: int = 30,
        connectors: Iterable[FindingsConnector] | None = None,
    ) -> None:
        self.repository = repository
        self.owner_user_id = owner_user_id or "anonymous"
        self.owner_user_login = owner_user_login or self.owner_user_id
        configured = connectors or (
            SemgrepConnector(timeout_seconds),
            InvictiConnector(timeout_seconds),
            NowSecureConnector(timeout_seconds),
        )
        self.connectors = {connector.key: connector for connector in configured}

    def close(self) -> None:
        for connector in self.connectors.values():
            connector.close()

    def status(self) -> list[dict[str, Any]]:
        return [
            self.connectors[key].status().as_dict()
            for key in CONNECTOR_KEYS
            if key in self.connectors
        ]

    def sync(self, connector_keys: Iterable[str] | None = None) -> dict[str, Any]:
        keys = normalize_connector_keys(connector_keys)
        results: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for key in keys:
            connector = self.connectors.get(key)
            if connector is None:
                errors.append({"connector": key, "message": "Connector is unavailable."})
                continue
            status = connector.status()
            if not status.configured:
                errors.append({"connector": key, "message": status.message})
                continue
            sync_id = self.repository.start_connector_sync(
                self.owner_user_id,
                self.owner_user_login,
                connector.key,
                connector.name,
                status.endpoint,
            )
            try:
                batch_puller = getattr(connector, "pull_batches", None)
                if (
                    getattr(connector, "supports_streaming", False) is True
                    and callable(batch_puller)
                ):
                    imported = self.repository.ingest_batches(
                        self.owner_user_id,
                        self.owner_user_login,
                        batch_puller(),
                    )
                    records_read = int(imported["findings"])
                    pull_metadata = {
                        "streamed": True,
                        **dict(imported.get("metadata") or {}),
                    }
                else:
                    pulled = connector.pull()
                    imported = self.repository.ingest(
                        self.owner_user_id,
                        self.owner_user_login,
                        pulled.document,
                    )
                    records_read = pulled.records_read
                    pull_metadata = pulled.metadata
                result = {
                    "syncId": sync_id,
                    "connector": connector.key,
                    "name": connector.name,
                    "recordsRead": records_read,
                    "metadata": pull_metadata,
                    **imported,
                }
                self.repository.finish_connector_sync(
                    self.owner_user_id, sync_id, "completed", result
                )
                results.append(result)
                LOGGER.info(
                    "ASPM connector sync completed connector=%s findings=%s linked=%s unlinked=%s",
                    connector.key,
                    result["findings"],
                    result["linkedFindings"],
                    result["unlinkedFindings"],
                    extra={
                        "event_type": "aspm.connector.sync.completed",
                        "owner_user_id": self.owner_user_id,
                        "owner_user_login": self.owner_user_login,
                        "metadata": {
                            "sync_id": sync_id,
                            "connector": connector.key,
                            "findings": result["findings"],
                            "linked_findings": result["linkedFindings"],
                            "unlinked_findings": result["unlinkedFindings"],
                        },
                    },
                )
            except Exception as exc:
                message = public_connector_error(exc)
                self.repository.finish_connector_sync(
                    self.owner_user_id,
                    sync_id,
                    "failed",
                    {"metadata": {"connector": connector.key}},
                    message,
                )
                errors.append(
                    {"syncId": sync_id, "connector": connector.key, "message": message}
                )
                LOGGER.exception(
                    "ASPM connector sync failed connector=%s",
                    connector.key,
                    extra={
                        "event_type": "aspm.connector.sync.failed",
                        "owner_user_id": self.owner_user_id,
                        "owner_user_login": self.owner_user_login,
                        "metadata": {"sync_id": sync_id, "connector": connector.key},
                    },
                )
        return {
            "status": "completed" if results and not errors else "partial" if results else "failed",
            "results": results,
            "errors": errors,
        }


def normalize_connector_keys(values: Iterable[str] | None) -> tuple[str, ...]:
    supplied = tuple(str(value).strip().casefold() for value in values or ())
    if not supplied or "all" in supplied:
        return CONNECTOR_KEYS
    unknown = sorted(set(supplied) - set(CONNECTOR_KEYS))
    if unknown:
        raise ValueError(f"Unknown security connector: {', '.join(unknown)}.")
    return tuple(key for key in CONNECTOR_KEYS if key in supplied)


def public_connector_error(error: Exception) -> str:
    if isinstance(error, (ConnectorError, ConnectorConfigurationError, ValueError)):
        return str(error)
    return "The connector sync could not be completed."
