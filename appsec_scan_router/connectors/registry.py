from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .models import ConnectorDefinition, FindingsConnector
from .dependency_check import CONNECTOR_DEFINITION as DEPENDENCY_CHECK_CONNECTOR
from .gitleaks import CONNECTOR_DEFINITION as GITLEAKS_CONNECTOR
from .invicti import CONNECTOR_DEFINITION as INVICTI_CONNECTOR
from .nowsecure import CONNECTOR_DEFINITION as NOWSECURE_CONNECTOR
from .nuclei import CONNECTOR_DEFINITION as NUCLEI_CONNECTOR
from .semgrep_enterprise import CONNECTOR_DEFINITION as SEMGREP_CONNECTOR
from .semgrep_community import CONNECTOR_DEFINITION as SEMGREP_COMMUNITY_CONNECTOR
from .sonarqube import CONNECTOR_DEFINITION as SONARQUBE_CONNECTOR
from .trivy import CONNECTOR_DEFINITION as TRIVY_CONNECTOR
from .zap import CONNECTOR_DEFINITION as ZAP_CONNECTOR


EMPTY_CONNECTOR_SETUP = {
    "type": "other",
    "serviceManaged": False,
    "description": "",
    "fields": [],
}


class ConnectorRegistry:
    def __init__(self, definitions: Iterable[ConnectorDefinition]) -> None:
        self._definitions = tuple(definitions)
        self._by_key: dict[str, ConnectorDefinition] = {}
        for definition in self._definitions:
            key = normalize_connector_key(definition.key)
            if key != definition.key:
                raise ValueError(f"Connector key must be normalized: {definition.key}.")
            if key in self._by_key:
                raise ValueError(f"Connector key is registered more than once: {key}.")
            self._by_key[key] = definition

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(definition.key for definition in self._definitions)

    @property
    def remote_keys(self) -> tuple[str, ...]:
        return tuple(
            definition.key for definition in self._definitions if definition.remote_sync
        )

    @property
    def report_import_keys(self) -> frozenset[str]:
        return frozenset(
            definition.key for definition in self._definitions if not definition.remote_sync
        )

    def definition(self, key: str) -> ConnectorDefinition | None:
        return self._by_key.get(normalize_connector_key(key))

    def require_definition(self, key: str) -> ConnectorDefinition:
        definition = self.definition(key)
        if definition is None:
            raise ValueError(f"Unknown security connector: {key}.")
        return definition

    def setup(self, key: str) -> dict[str, Any]:
        definition = self.definition(key)
        if definition:
            return definition.setup()
        return {
            "type": EMPTY_CONNECTOR_SETUP["type"],
            "serviceManaged": EMPTY_CONNECTOR_SETUP["serviceManaged"],
            "description": EMPTY_CONNECTOR_SETUP["description"],
            "fields": [],
        }

    def create_all(
        self,
        timeout_seconds: int,
        configurations: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> tuple[FindingsConnector, ...]:
        values = configurations or {}
        return tuple(
            definition.create(timeout_seconds, values.get(definition.key))
            for definition in self._definitions
        )

    def normalize_remote_keys(self, values: Iterable[str] | None) -> tuple[str, ...]:
        supplied = tuple(normalize_connector_key(value) for value in values or ())
        if not supplied or "all" in supplied:
            return self.remote_keys
        unknown = sorted(set(supplied) - set(self.keys))
        if unknown:
            raise ValueError(f"Unknown security connector: {', '.join(unknown)}.")
        report_imports = sorted(set(supplied) & self.report_import_keys)
        if report_imports:
            raise ValueError(
                f"{', '.join(report_imports)} is imported from a report and cannot be synchronized remotely."
            )
        return tuple(key for key in self.remote_keys if key in supplied)


def normalize_connector_key(value: Any) -> str:
    return str(value or "").strip().casefold()


DEFAULT_CONNECTOR_REGISTRY = ConnectorRegistry(
    (
        SEMGREP_CONNECTOR,
        SEMGREP_COMMUNITY_CONNECTOR,
        INVICTI_CONNECTOR,
        NOWSECURE_CONNECTOR,
        SONARQUBE_CONNECTOR,
        ZAP_CONNECTOR,
        TRIVY_CONNECTOR,
        GITLEAKS_CONNECTOR,
        NUCLEI_CONNECTOR,
        DEPENDENCY_CHECK_CONNECTOR,
    )
)
CONNECTOR_KEYS = DEFAULT_CONNECTOR_REGISTRY.keys
REPORT_IMPORT_CONNECTOR_KEYS = DEFAULT_CONNECTOR_REGISTRY.report_import_keys
REMOTE_CONNECTOR_KEYS = DEFAULT_CONNECTOR_REGISTRY.remote_keys


def connector_setup(key: str) -> dict[str, Any]:
    return DEFAULT_CONNECTOR_REGISTRY.setup(key)


def normalize_connector_keys(values: Iterable[str] | None) -> tuple[str, ...]:
    return DEFAULT_CONNECTOR_REGISTRY.normalize_remote_keys(values)