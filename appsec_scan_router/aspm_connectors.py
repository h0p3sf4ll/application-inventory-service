from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from copy import deepcopy
from typing import Any

from .aspm_connector_http import ConnectorConfigurationError, ConnectorError
from .aspm_connector_models import FindingsConnector
from .aspm_postgres import AspmRepository
from .invicti_connector import InvictiConnector
from .nowsecure_connector import NowSecureConnector
from .report_import_connector import ReportImportConnector
from .semgrep_connector import SemgrepConnector
from .sonarqube_connector import SonarQubeConnector
from .zap_connector import ZapConnector


LOGGER = logging.getLogger("appsec_scan_router")
CONNECTOR_KEYS = (
    "semgrep",
    "invicti",
    "nowsecure",
    "sonarqube",
    "zap",
    "trivy",
    "gitleaks",
    "nuclei",
    "dependency_check",
)
REPORT_IMPORT_CONNECTOR_KEYS = frozenset(
    {"trivy", "gitleaks", "nuclei", "dependency_check"}
)
REMOTE_CONNECTOR_KEYS = tuple(
    key for key in CONNECTOR_KEYS if key not in REPORT_IMPORT_CONNECTOR_KEYS
)
CONNECTOR_SETUP = {
    "semgrep": {
        "type": "cloud_api",
        "serviceManaged": True,
        "description": "Semgrep App findings API.",
        "fields": [
            {"key": "endpoint", "label": "API URL", "required": False, "secret": False},
            {"key": "token", "label": "App token", "required": True, "secret": True},
        ],
    },
    "invicti": {
        "type": "hosted_api",
        "serviceManaged": True,
        "description": "Invicti or Netsparker vulnerability management API.",
        "fields": [
            {"key": "endpoint", "label": "API URL", "required": True, "secret": False},
            {"key": "userId", "label": "User ID", "required": True, "secret": False},
            {"key": "token", "label": "API token", "required": True, "secret": True},
        ],
    },
    "nowsecure": {
        "type": "hosted_api",
        "serviceManaged": True,
        "description": "NowSecure mobile application security findings API.",
        "fields": [
            {"key": "endpoint", "label": "API URL", "required": False, "secret": False},
            {"key": "token", "label": "API token", "required": True, "secret": True},
        ],
    },
    "sonarqube": {
        "type": "self_hosted_api",
        "serviceManaged": False,
        "description": "SonarQube issues API for self-hosted static analysis.",
        "fields": [
            {"key": "endpoint", "label": "Server URL", "required": True, "secret": False},
            {"key": "token", "label": "User token", "required": True, "secret": True},
        ],
    },
    "zap": {
        "type": "self_hosted_api",
        "serviceManaged": False,
        "description": "OWASP ZAP alerts API for dynamic application security testing.",
        "fields": [
            {"key": "endpoint", "label": "ZAP API URL", "required": True, "secret": False},
            {"key": "apiKey", "label": "API key", "required": False, "secret": True},
        ],
    },
    "trivy": {
        "type": "sarif_profile",
        "serviceManaged": False,
        "description": "Configure the SARIF report location produced by Trivy container, dependency, and IaC scans.",
        "fields": [
            {"key": "reportPath", "label": "SARIF report path", "required": True, "secret": False},
        ],
    },
    "gitleaks": {
        "type": "sarif_profile",
        "serviceManaged": False,
        "description": "Configure the SARIF report location produced by Gitleaks secrets detection.",
        "fields": [
            {"key": "reportPath", "label": "SARIF report path", "required": True, "secret": False},
        ],
    },
    "nuclei": {
        "type": "sarif_profile",
        "serviceManaged": False,
        "description": "Configure the SARIF report location produced by Nuclei exposure checks.",
        "fields": [
            {"key": "reportPath", "label": "SARIF report path", "required": True, "secret": False},
        ],
    },
    "dependency_check": {
        "type": "sarif_profile",
        "serviceManaged": False,
        "description": "Configure the SARIF report location produced by OWASP Dependency-Check.",
        "fields": [
            {"key": "reportPath", "label": "SARIF report path", "required": True, "secret": False},
        ],
    },
}


def connector_setup(key: str) -> dict[str, Any]:
    return deepcopy(
        CONNECTOR_SETUP.get(
            key,
            {"type": "other", "serviceManaged": False, "description": "", "fields": []},
        )
    )


def connector_status(
    connector: FindingsConnector, configuration_source: str = ""
) -> dict[str, Any]:
    status = connector.status().as_dict()
    setup = connector_setup(connector.key)
    runnable = bool(status["configured"])
    status.update(
        {
            "syncReady": runnable and connector.key not in REPORT_IMPORT_CONNECTOR_KEYS,
            "configurationSource": configuration_source or "service" if runnable else "",
        }
    )
    status["setup"] = setup
    return status


class ConnectorService:
    def __init__(
        self,
        repository: AspmRepository,
        owner_user_id: str,
        owner_user_login: str,
        timeout_seconds: int = 30,
        connectors: Iterable[FindingsConnector] | None = None,
        connector_configurations: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self.repository = repository
        self.owner_user_id = owner_user_id or "anonymous"
        self.owner_user_login = owner_user_login or self.owner_user_id
        configurations = connector_configurations or {}
        self.connector_configurations = configurations
        configured = connectors or (
            SemgrepConnector(timeout_seconds, configurations.get("semgrep")),
            InvictiConnector(timeout_seconds, configurations.get("invicti")),
            NowSecureConnector(timeout_seconds, configurations.get("nowsecure")),
            SonarQubeConnector(timeout_seconds, configurations.get("sonarqube")),
            ZapConnector(timeout_seconds, configurations.get("zap")),
            ReportImportConnector("trivy", "Trivy", configurations.get("trivy")),
            ReportImportConnector("gitleaks", "Gitleaks", configurations.get("gitleaks")),
            ReportImportConnector("nuclei", "Nuclei", configurations.get("nuclei")),
            ReportImportConnector(
                "dependency_check", "OWASP Dependency-Check", configurations.get("dependency_check")
            ),
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
            )
            for key in CONNECTOR_KEYS
            if key in self.connectors
        ]

    def test_connections(
        self, connector_keys: Iterable[str] | None = None
    ) -> dict[str, Any]:
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
            tester = getattr(connector, "test_connection", None)
            if not callable(tester):
                errors.append({"connector": key, "message": "Connection testing is unavailable."})
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
        return {
            "status": "completed" if results and not errors else "partial" if results else "failed",
            "results": results,
            "errors": errors,
        }

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
                        "metadata": {
                            "sync_id": sync_id,
                            "connector": connector.key,
                        },
                    },
                )
                raise
        return {
            "status": "completed" if results and not errors else "partial" if results else "failed",
            "results": results,
            "errors": errors,
        }


def normalize_connector_keys(values: Iterable[str] | None) -> tuple[str, ...]:
    supplied = tuple(str(value).strip().casefold() for value in values or ())
    if not supplied or "all" in supplied:
        return REMOTE_CONNECTOR_KEYS
    unknown = sorted(set(supplied) - set(CONNECTOR_KEYS))
    if unknown:
        raise ValueError(f"Unknown security connector: {', '.join(unknown)}.")
    report_imports = sorted(set(supplied) & REPORT_IMPORT_CONNECTOR_KEYS)
    if report_imports:
        raise ValueError(
            f"{', '.join(report_imports)} uses SARIF import and cannot be synchronized remotely."
        )
    return tuple(key for key in REMOTE_CONNECTOR_KEYS if key in supplied)


def public_connector_error(error: Exception) -> str:
    if isinstance(error, (ConnectorError, ConnectorConfigurationError, ValueError)):
        return str(error)
    return "The connector sync could not be completed."
