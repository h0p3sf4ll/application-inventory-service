from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, Mapping
from urllib.parse import urlparse

import requests

from .constants import KNOWN_INVENTORY_TYPES
from .inventory_query import InventoryQueryPlan, QUERY_FIELDS, SORT_FIELDS


DEFAULT_LOCAL_LLM_URL = "http://127.0.0.1:11434"
DEFAULT_LOCAL_LLM_MODEL = "llama3.1:latest"
LOCAL_HOSTS = frozenset({"localhost", "host.docker.internal"})
MAX_RESPONSE_BYTES = 65_536
MAX_QUESTION_LENGTH = 2_000
STATUS_CACHE_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class LocalLlmConfig:
    enabled: bool = True
    base_url: str = DEFAULT_LOCAL_LLM_URL
    model: str = DEFAULT_LOCAL_LLM_MODEL
    timeout_seconds: float = 30.0
    allow_remote: bool = False

    @classmethod
    def from_env(cls) -> LocalLlmConfig:
        enabled = env_bool("APPLICATION_INVENTORY_LOCAL_LLM_ENABLED", True)
        allow_remote = env_bool("APPLICATION_INVENTORY_LOCAL_LLM_ALLOW_REMOTE", False)
        base_url = normalize_base_url(
            os.getenv("APPLICATION_INVENTORY_LOCAL_LLM_URL", DEFAULT_LOCAL_LLM_URL),
            allow_remote=allow_remote,
        )
        model = (
            clean_text(os.getenv("APPLICATION_INVENTORY_LOCAL_LLM_MODEL"))
            or DEFAULT_LOCAL_LLM_MODEL
        )
        timeout = bounded_float(
            os.getenv("APPLICATION_INVENTORY_LOCAL_LLM_TIMEOUT"), 30.0, 2.0, 120.0
        )
        return cls(
            enabled=enabled,
            base_url=base_url,
            model=model[:120],
            timeout_seconds=timeout,
            allow_remote=allow_remote,
        )

    def public_config(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": "Ollama",
            "model": self.model,
        }


class LocalInventoryAssistant:
    def __init__(
        self, config: LocalLlmConfig, session: requests.Session | None = None
    ) -> None:
        self.config = config
        self.session = session or requests.Session()
        self.session.trust_env = False
        self._status: dict[str, Any] | None = None
        self._status_at = 0.0
        self._lock = threading.RLock()

    @classmethod
    def from_env(cls) -> LocalInventoryAssistant:
        return cls(LocalLlmConfig.from_env())

    def public_config(self) -> dict[str, Any]:
        status = self.status()
        return {**self.config.public_config(), **status}

    def status(self, refresh: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            if (
                not refresh
                and self._status is not None
                and now - self._status_at < STATUS_CACHE_SECONDS
            ):
                return dict(self._status)
        status = self._load_status()
        with self._lock:
            self._status = status
            self._status_at = now
        return dict(status)

    def interpret(self, question: str) -> InventoryQueryPlan:
        prompt = clean_text(question)[:MAX_QUESTION_LENGTH]
        if not prompt:
            raise ValueError("Enter a question about the inventory.")
        if not self.config.enabled:
            raise ValueError("The local inventory assistant is disabled.")
        response = self.session.post(
            f"{self.config.base_url}/api/chat",
            json={
                "model": self.config.model,
                "stream": False,
                "format": "json",
                "messages": [
                    {"role": "system", "content": assistant_system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                "options": {"temperature": 0, "num_predict": 800},
            },
            timeout=(3.0, self.config.timeout_seconds),
        )
        response.raise_for_status()
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise ValueError("The local model returned an oversized response.")
        payload = response.json()
        content = clean_text(
            (payload.get("message") or {}).get("content") or payload.get("response")
        )
        plan_payload = parse_json_object(content)
        return InventoryQueryPlan.from_mapping(plan_payload)

    def _load_status(self) -> dict[str, Any]:
        if not self.config.enabled:
            return {"available": False, "status": "disabled", "message": "Disabled"}
        try:
            response = self.session.get(
                f"{self.config.base_url}/api/tags", timeout=(1.0, 2.0)
            )
            response.raise_for_status()
            if len(response.content) > MAX_RESPONSE_BYTES:
                raise ValueError("response too large")
            payload = response.json()
            models = tuple(
                clean_text(item.get("name") or item.get("model"))
                for item in payload.get("models", [])
                if isinstance(item, Mapping)
            )
            model_available = any(
                model_matches(self.config.model, candidate) for candidate in models
            )
            return {
                "available": model_available,
                "status": "ready" if model_available else "model_missing",
                "message": "Ready"
                if model_available
                else f"Install {self.config.model}",
            }
        except (requests.RequestException, ValueError, TypeError, json.JSONDecodeError):
            return {
                "available": False,
                "status": "offline",
                "message": "Ollama is offline",
            }


def assistant_system_prompt() -> str:
    schema = {
        "allowed_fields": sorted(QUERY_FIELDS),
        "application_types": list(KNOWN_INVENTORY_TYPES),
        "providers": ["azure-devops", "github-enterprise"],
        "confidence": ["low", "medium", "high"],
        "domain_statuses": ["confirmed", "configured", "inferred", "not_detected"],
        "sort_by": sorted(SORT_FIELDS),
        "action": ["search", "export"],
        "export_format": ["xlsx", "csv", "json"],
    }
    return (
        "Convert the user's inventory request into one JSON object. "
        "Return only JSON and only the allowed fields. Use arrays for plural filters. "
        "Use updated_within_days for recent records and older_than_days for stale records. "
        "Map high, medium, or low confidence requests to the confidences array. "
        "Use has_domain=false for applications without a domain. "
        "Use action=export only when the user explicitly asks to export or download. "
        "Never produce SQL, code, credentials, URLs, explanations, or invented field values. "
        f"Schema: {json.dumps(schema, separators=(',', ':'))}"
    )


def parse_json_object(value: str) -> Mapping[str, Any]:
    text = clean_text(value)
    if text.startswith("```"):
        text = (
            text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError(
                "The local model did not return a valid query plan."
            ) from exc
        try:
            payload = json.loads(text[start : end + 1])
        except json.JSONDecodeError as nested_exc:
            raise ValueError(
                "The local model did not return a valid query plan."
            ) from nested_exc
    if not isinstance(payload, Mapping):
        raise ValueError("The local model did not return a valid query plan.")
    return payload


def normalize_base_url(value: Any, allow_remote: bool = False) -> str:
    parsed = urlparse(clean_text(value).rstrip("/"))
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError(
            "Local LLM URL must be an HTTP or HTTPS origin without credentials."
        )
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Local LLM URL must not contain a path, query, or fragment.")
    if not allow_remote and not is_local_host(parsed.hostname):
        raise ValueError(
            "Local LLM URL must resolve to this host unless remote access is explicitly enabled."
        )
    return f"{parsed.scheme}://{parsed.netloc}"


def is_local_host(host: str) -> bool:
    if host.lower() in LOCAL_HOSTS:
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def model_matches(configured: str, available: str) -> bool:
    configured_name = configured.strip().lower()
    available_name = available.strip().lower()
    return available_name == configured_name or available_name.removesuffix(
        ":latest"
    ) == configured_name.removesuffix(":latest")


def clean_text(value: Any) -> str:
    return " ".join(str(value or "").split())


def env_bool(name: str, default: bool) -> bool:
    value = clean_text(os.getenv(name)).lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "on"}


def bounded_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(number, maximum))
