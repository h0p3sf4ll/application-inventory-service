from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from .http import ConnectorConfigurationError, ConnectorError
from .models import FindingsConnector
from .registry import ConnectorRegistry, DEFAULT_CONNECTOR_REGISTRY
from ..aspm_postgres import AspmRepository


LOGGER = logging.getLogger("appsec_scan_router")


def connector_status(
    connector: FindingsConnector,
    configuration_source: str = "",
    registry: ConnectorRegistry = DEFAULT_CONNECTOR_REGISTRY,
) -> dict[str, Any]:
    status = connector.status().as_dict()
    definition = registry.definition(connector.key)
    runnable = bool(status["configured"])
    status.update(
        {
            "syncReady": runnable and bool(definition and definition.remote_sync),
            "configurationSource": (configuration_source or "service") if runnable else "",
            "setup": registry.setup(connector.key),
        }
    )
    return status


class ConnectorService:
    def __init__(
        self,
        repository: AspmRepository | None,
        owner_user_id: str,
        owner_user_login: str,
        timeout_seconds: int = 30,
        connectors: Iterable[FindingsConnector] | None = None,
        connector_configurations: Mapping[str, Mapping[str, Any]] | None = None,
        registry: ConnectorRegistry = DEFAULT_CONNECTOR_REGISTRY,
    ) -> None:
        self.repository = repository
        self.owner_user_id = owner_user_id or "anonymous"
        self.owner_user_login = owner_user_login or self.owner_user_id
        self.registry = registry
        self.connector_configurations = connector_configurations or {}
        configured = (
            tuple(connectors)
            if connectors is not None
            else registry.create_all(timeout_seconds, self.connector_configurations)
        )
        self.connectors = {connector.key: connector for connector in configured}

    def close(self) -> None:
        for connector in self.connectors.values():
            connector.close()

    def status(self) -> list[dict[str, Any]]:
        return [
            connector_status(
                self.connectors[key],
                "account" if self.connector_configurations.get(key) else "",
                self.registry,
            )
            for key in self.registry.keys
            if key in self.connectors
        ]

    def test_connections(
        self, connector_keys: Iterable[str] | None = None
    ) -> dict[str, Any]:
        keys = self.registry.normalize_remote_keys(connector_keys)
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
            tester = getattr(connector, "test_connection", None)
            if not callable(tester):
                errors.append(
                    {"connector": key, "message": "Connection testing is unavailable."}
                )
                continue
            try:
                metadata = dict(tester() or {})
                results.append(
                    {
                        "connector": connector.key,
                        "name": connector.name,
                        "endpoint": status.endpoint,
                        "metadata": metadata,
                    }
                )
            except Exception as exc:
                errors.append({"connector": key, "message": public_connector_error(exc)})
        return operation_result(results, errors)

    def sync(self, connector_keys: Iterable[str] | None = None) -> dict[str, Any]:
        if self.repository is None:
            raise ValueError("A repository is required to synchronize connectors.")
        keys = self.registry.normalize_remote_keys(connector_keys)
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
                if getattr(connector, "supports_streaming", False) is True and callable(batch_puller):
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
            except (KeyboardInterrupt, SystemExit):
                message = "Connector sync was interrupted."
                self.repository.finish_connector_sync(
                    self.owner_user_id,
                    sync_id,
                    "failed",
                    {"metadata": {"connector": connector.key}},
                    message,
                )
                LOGGER.warning(
                    "ASPM connector sync interrupted connector=%s",
                    connector.key,
                    extra={
                        "event_type": "aspm.connector.sync.interrupted",
                        "owner_user_id": self.owner_user_id,
                        "owner_user_login": self.owner_user_login,
                        "metadata": {"sync_id": sync_id, "connector": connector.key},
                    },
                )
                raise
        return operation_result(results, errors)


def operation_result(
    results: list[dict[str, Any]], errors: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "status": "completed" if results and not errors else "partial" if results else "failed",
        "results": results,
        "errors": errors,
    }


def public_connector_error(error: Exception) -> str:
    if isinstance(error, (ConnectorError, ConnectorConfigurationError, ValueError)):
        return str(error)
    return "The connector sync could not be completed."