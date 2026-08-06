from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..aspm_models import FindingDocument


@dataclass(frozen=True, slots=True)
class ConnectorStatus:
    key: str
    name: str
    configured: bool
    endpoint: str
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "configured": self.configured,
            "endpoint": self.endpoint,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ConnectorField:
    key: str
    label: str
    required: bool = False
    secret: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "required": self.required,
            "secret": self.secret,
        }


@dataclass(frozen=True, slots=True)
class ConnectorPullResult:
    connector_key: str
    connector_name: str
    document: FindingDocument
    records_read: int
    metadata: dict[str, Any] = field(default_factory=dict)


class FindingsConnector(Protocol):
    key: str
    name: str

    def status(self) -> ConnectorStatus: ...

    def pull(self) -> ConnectorPullResult: ...

    def close(self) -> None: ...


ConnectorFactory = Callable[[int, Mapping[str, Any] | None], FindingsConnector]


@dataclass(frozen=True, slots=True)
class ConnectorDefinition:
    key: str
    name: str
    connector_type: str
    service_managed: bool
    description: str
    fields: tuple[ConnectorField, ...]
    factory: ConnectorFactory
    remote_sync: bool = True
    import_format: str = ""

    def create(
        self, timeout_seconds: int, configuration: Mapping[str, Any] | None = None
    ) -> FindingsConnector:
        return self.factory(timeout_seconds, configuration)

    def setup(self) -> dict[str, Any]:
        setup = {
            "type": self.connector_type,
            "serviceManaged": self.service_managed,
            "description": self.description,
            "fields": [field.as_dict() for field in self.fields],
        }
        if self.import_format:
            setup["importFormat"] = self.import_format
        return setup
