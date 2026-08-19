from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

import requests

from .constants import KNOWN_INVENTORY_TYPES
from .inventory_query import InventoryQueryPlan, QUERY_FIELDS, SORT_FIELDS
from .secure_store import EncryptedJsonStore


DEFAULT_LOCAL_LLM_URL = "http://127.0.0.1:11434"
DEFAULT_LOCAL_LLM_MODEL = "llama3.1:latest"
LOCAL_HOSTS = frozenset({"localhost", "host.docker.internal"})
MAX_RESPONSE_BYTES = 65_536
MAX_QUESTION_LENGTH = 2_000
STATUS_CACHE_SECONDS = 30.0

PROVIDER_OLLAMA = "ollama"
PROVIDER_LMSTUDIO = "lmstudio"
PROVIDER_OPENAI = "openai"
PROVIDER_ANTHROPIC = "anthropic"
KNOWN_PROVIDERS = frozenset({PROVIDER_OLLAMA, PROVIDER_LMSTUDIO, PROVIDER_OPENAI, PROVIDER_ANTHROPIC})
LOCAL_PROVIDERS = frozenset({PROVIDER_OLLAMA, PROVIDER_LMSTUDIO})
CLOUD_PROVIDERS = frozenset({PROVIDER_OPENAI, PROVIDER_ANTHROPIC})

OPENAI_BASE_URL = "https://api.openai.com"
ANTHROPIC_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"

PROVIDER_DISPLAY = {
    PROVIDER_OLLAMA: "Ollama",
    PROVIDER_LMSTUDIO: "LM Studio",
    PROVIDER_OPENAI: "OpenAI",
    PROVIDER_ANTHROPIC: "Anthropic",
}

PROVIDER_DEFAULT_MODELS = {
    PROVIDER_OPENAI: "gpt-4o-mini",
    PROVIDER_ANTHROPIC: "claude-haiku-4-5-20251001",
}


@dataclass(frozen=True, slots=True)
class LocalLlmConfig:
    """Env-based config (backwards compatibility / startup fallback)."""
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
            "provider": PROVIDER_OLLAMA,
            "providerDisplay": PROVIDER_DISPLAY[PROVIDER_OLLAMA],
            "model": self.model,
        }

    def to_provider_config(self) -> LlmProviderConfig:
        return LlmProviderConfig(
            provider=PROVIDER_OLLAMA,
            base_url=self.base_url,
            model=self.model,
            timeout_seconds=self.timeout_seconds,
            enabled=self.enabled,
        )


@dataclass(frozen=True, slots=True)
class LlmProviderConfig:
    """Persisted, multi-provider LLM configuration."""
    provider: str = PROVIDER_OLLAMA
    base_url: str = DEFAULT_LOCAL_LLM_URL
    model: str = DEFAULT_LOCAL_LLM_MODEL
    api_key: str = ""
    timeout_seconds: float = 30.0
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LlmProviderConfig:
        provider = clean_text(data.get("provider") or PROVIDER_OLLAMA).lower()
        if provider not in KNOWN_PROVIDERS:
            provider = PROVIDER_OLLAMA
        raw_url = clean_text(data.get("base_url") or "")
        if provider == PROVIDER_OPENAI and not raw_url:
            raw_url = OPENAI_BASE_URL
        elif provider == PROVIDER_ANTHROPIC and not raw_url:
            raw_url = ANTHROPIC_BASE_URL
        elif not raw_url:
            raw_url = DEFAULT_LOCAL_LLM_URL
        try:
            base_url = normalize_base_url(raw_url, allow_remote=True)
        except ValueError:
            base_url = DEFAULT_LOCAL_LLM_URL
        model = clean_text(data.get("model") or "")[:120] or PROVIDER_DEFAULT_MODELS.get(provider, DEFAULT_LOCAL_LLM_MODEL)
        return cls(
            provider=provider,
            base_url=base_url,
            model=model,
            api_key=clean_text(data.get("api_key") or "")[:2048],
            timeout_seconds=bounded_float(data.get("timeout_seconds"), 30.0, 2.0, 120.0),
            enabled=bool(data.get("enabled", True)),
        )

    def to_store_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "api_key": self.api_key,
            "timeout_seconds": self.timeout_seconds,
            "enabled": self.enabled,
        }

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "providerDisplay": PROVIDER_DISPLAY.get(self.provider, self.provider),
            "base_url": self.base_url if self.provider in LOCAL_PROVIDERS else "",
            "model": self.model,
            "has_api_key": bool(self.api_key),
            "timeout_seconds": self.timeout_seconds,
            "enabled": self.enabled,
        }

    @property
    def is_local(self) -> bool:
        return self.provider in LOCAL_PROVIDERS

    @property
    def effective_base_url(self) -> str:
        if self.provider == PROVIDER_OPENAI:
            return OPENAI_BASE_URL
        if self.provider == PROVIDER_ANTHROPIC:
            return ANTHROPIC_BASE_URL
        return self.base_url


class LlmConfigStore:
    def __init__(self, store: EncryptedJsonStore, env_fallback: LocalLlmConfig) -> None:
        self._store = store
        self._env_fallback = env_fallback
        self._lock = threading.RLock()

    @classmethod
    def from_state_dir(cls, state_dir: Path, env_fallback: LocalLlmConfig) -> LlmConfigStore:
        return cls(
            EncryptedJsonStore(state_dir, "llm_config.json.enc", lambda: {}),
            env_fallback,
        )

    def read(self) -> LlmProviderConfig:
        with self._lock:
            data = self._store.read()
        if not data:
            return self._env_fallback.to_provider_config()
        return LlmProviderConfig.from_dict(data)

    def write(self, config: LlmProviderConfig) -> None:
        with self._lock:
            self._store.write(config.to_store_dict())


class LocalInventoryAssistant:
    def __init__(
        self,
        config: LocalLlmConfig,
        session: requests.Session | None = None,
        config_store: LlmConfigStore | None = None,
    ) -> None:
        self.config = config
        self.config_store = config_store
        self.session = session or requests.Session()
        self.session.trust_env = False
        self._status: dict[str, Any] | None = None
        self._status_at = 0.0
        self._lock = threading.RLock()

    @classmethod
    def from_env(cls) -> LocalInventoryAssistant:
        return cls(LocalLlmConfig.from_env())

    def active_config(self) -> LlmProviderConfig:
        if self.config_store is not None:
            return self.config_store.read()
        return self.config.to_provider_config()

    def public_config(self) -> dict[str, Any]:
        provider_cfg = self.active_config()
        status = self.status()
        return {**provider_cfg.to_public_dict(), **status}

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

    def invalidate_status(self) -> None:
        with self._lock:
            self._status = None
            self._status_at = 0.0

    def interpret(self, question: str) -> InventoryQueryPlan:
        prompt = clean_text(question)[:MAX_QUESTION_LENGTH]
        if not prompt:
            raise ValueError("Enter a question about the inventory.")
        cfg = self.active_config()
        if not cfg.enabled:
            raise ValueError("The local inventory assistant is disabled.")
        content = self._chat(cfg, assistant_system_prompt(), prompt)
        plan_payload = parse_json_object(content)
        return InventoryQueryPlan.from_mapping(plan_payload)

    def interpret_asset_risk(self, question: str) -> dict[str, Any]:
        prompt = clean_text(question)[:MAX_QUESTION_LENGTH]
        if not prompt:
            raise ValueError("Enter a question about asset risk.")
        cfg = self.active_config()
        if not cfg.enabled:
            raise ValueError("The AI assistant is disabled.")
        content = self._chat(cfg, risk_assistant_system_prompt(), prompt)
        payload = parse_json_object(content)
        if not isinstance(payload, Mapping):
            raise ValueError("The model did not return a valid query plan.")
        return dict(payload)

    def list_models(self) -> list[str]:
        cfg = self.active_config()
        try:
            if cfg.provider == PROVIDER_OLLAMA:
                resp = self.session.get(f"{cfg.base_url}/api/tags", timeout=(2.0, 5.0))
                resp.raise_for_status()
                payload = resp.json()
                return sorted(
                    clean_text(item.get("name") or item.get("model"))
                    for item in payload.get("models", [])
                    if isinstance(item, Mapping)
                )
            if cfg.provider in {PROVIDER_LMSTUDIO, PROVIDER_OPENAI}:
                headers: dict[str, str] = {}
                if cfg.api_key:
                    headers["Authorization"] = f"Bearer {cfg.api_key}"
                resp = self.session.get(
                    f"{cfg.effective_base_url}/v1/models",
                    headers=headers,
                    timeout=(2.0, 8.0),
                )
                resp.raise_for_status()
                payload = resp.json()
                return sorted(
                    clean_text(item.get("id") or "")
                    for item in payload.get("data", [])
                    if isinstance(item, Mapping) and item.get("id")
                )
        except (requests.RequestException, ValueError, TypeError, json.JSONDecodeError):
            pass
        return []

    def test_connection(self) -> dict[str, Any]:
        cfg = self.active_config()
        if not cfg.enabled:
            return {"ok": False, "message": "AI assistant is disabled."}
        try:
            models = self.list_models()
            if cfg.provider in LOCAL_PROVIDERS:
                model_available = any(
                    model_matches(cfg.model, m) for m in models
                )
                if not model_available and models:
                    return {
                        "ok": False,
                        "message": f"Model '{cfg.model}' not installed. Available: {', '.join(models[:5])}",
                        "models": models,
                    }
                if not model_available:
                    return {"ok": False, "message": f"Model '{cfg.model}' not found — is the server running?", "models": []}
                return {"ok": True, "message": f"Connected · {len(models)} model(s) available", "models": models}
            if cfg.provider == PROVIDER_OPENAI:
                if not cfg.api_key:
                    return {"ok": False, "message": "An API key is required for OpenAI."}
                return {"ok": True, "message": f"API key accepted · {len(models)} model(s) available", "models": models}
            if cfg.provider == PROVIDER_ANTHROPIC:
                if not cfg.api_key:
                    return {"ok": False, "message": "An API key is required for Anthropic."}
                # Do a minimal completion to verify the key
                content = self._chat(cfg, "You are a test assistant.", "Reply with only: ok")
                if content:
                    return {"ok": True, "message": "API key accepted · connection verified"}
        except (requests.RequestException, ValueError) as exc:
            return {"ok": False, "message": str(exc)[:200]}
        except Exception:
            return {"ok": False, "message": "Connection test failed."}
        return {"ok": False, "message": "Could not verify connection."}

    def _chat(self, cfg: LlmProviderConfig, system: str, user: str) -> str:
        if cfg.provider == PROVIDER_ANTHROPIC:
            return self._chat_anthropic(cfg, system, user)
        return self._chat_openai_compat(cfg, system, user)

    def _chat_openai_compat(self, cfg: LlmProviderConfig, system: str, user: str) -> str:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if cfg.api_key:
            headers["Authorization"] = f"Bearer {cfg.api_key}"
        endpoint = f"{cfg.effective_base_url}/v1/chat/completions"
        body: dict[str, Any] = {
            "model": cfg.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if cfg.provider != PROVIDER_OLLAMA:
            body["response_format"] = {"type": "json_object"}
        else:
            # Ollama supports both endpoints; use OpenAI-compat with json format flag
            body["response_format"] = {"type": "json_object"}
        resp = self.session.post(
            endpoint, json=body, headers=headers,
            timeout=(3.0, cfg.timeout_seconds),
        )
        resp.raise_for_status()
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("The model returned an oversized response.")
        payload = resp.json()
        choices = payload.get("choices") or []
        if choices:
            return clean_text((choices[0].get("message") or {}).get("content") or "")
        # Ollama non-standard fallback
        return clean_text(payload.get("message", {}).get("content") or payload.get("response") or "")

    def _chat_anthropic(self, cfg: LlmProviderConfig, system: str, user: str) -> str:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": cfg.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }
        resp = self.session.post(
            f"{ANTHROPIC_BASE_URL}/v1/messages",
            json={
                "model": cfg.model,
                "max_tokens": 800,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            headers=headers,
            timeout=(3.0, cfg.timeout_seconds),
        )
        resp.raise_for_status()
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("The model returned an oversized response.")
        payload = resp.json()
        for block in payload.get("content", []):
            if isinstance(block, Mapping) and block.get("type") == "text":
                return clean_text(block.get("text") or "")
        return ""

    def _load_status(self) -> dict[str, Any]:
        cfg = self.active_config()
        if not cfg.enabled:
            return {"available": False, "status": "disabled", "message": "Disabled"}
        provider_label = PROVIDER_DISPLAY.get(cfg.provider, cfg.provider)
        if cfg.provider in CLOUD_PROVIDERS:
            if not cfg.api_key:
                return {
                    "available": False,
                    "status": "no_key",
                    "message": f"{provider_label}: no API key configured",
                }
            return {
                "available": True,
                "status": "ready",
                "message": f"{provider_label} ready",
            }
        try:
            response = self.session.get(
                f"{cfg.base_url}/api/tags", timeout=(1.0, 2.0)
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
                model_matches(cfg.model, candidate) for candidate in models
            )
            return {
                "available": model_available,
                "status": "ready" if model_available else "model_missing",
                "message": f"{provider_label} ready"
                if model_available
                else f"Install {cfg.model}",
            }
        except (requests.RequestException, ValueError, TypeError, json.JSONDecodeError):
            if cfg.provider == PROVIDER_LMSTUDIO:
                try:
                    resp = self.session.get(f"{cfg.base_url}/v1/models", timeout=(1.0, 3.0))
                    resp.raise_for_status()
                    payload = resp.json()
                    models_lms = [
                        clean_text(item.get("id") or "")
                        for item in payload.get("data", [])
                        if isinstance(item, Mapping) and item.get("id")
                    ]
                    available = any(model_matches(cfg.model, m) for m in models_lms)
                    return {
                        "available": available,
                        "status": "ready" if available else "model_missing",
                        "message": f"{provider_label} ready" if available else f"Model '{cfg.model}' not loaded",
                    }
                except Exception:
                    pass
            return {
                "available": False,
                "status": "offline",
                "message": f"{provider_label} is offline",
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


def risk_assistant_system_prompt() -> str:
    schema = {
        "risk_band": ["critical", "high", "medium", "low", ""],
        "data_types": [
            "payment_card_data", "health_data", "biometric_data", "credentials", "secrets",
            "authentication_data", "financial_data", "personal_data", "location_data",
            "device_identifiers", "tracking_data", "confidential_business_data", "source_code",
        ],
        "query": "free text search for application, repository, domain, owner",
        "active_only": "true to show only assets with active findings",
    }
    return (
        "Convert the user's asset risk request into one JSON object with these optional fields: "
        "risk_band (string), data_types (array), query (string), active_only (bool). "
        "Return only JSON. Never include SQL, explanations, or invented values. "
        "Set only fields relevant to the request; omit the rest. "
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
            "LLM URL must be an HTTP or HTTPS origin without credentials."
        )
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("LLM URL must not contain a path, query, or fragment.")
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
