from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .aspm_models import FindingDocument


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
