from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

import requests

from .constants import APPLICATION_USER_AGENT


DEFAULT_WEBHOOK_TIMEOUT_SECONDS = 30
DEFAULT_WEBHOOK_BATCH_SIZE = 100
DEFAULT_WEBHOOK_RETRIES = 3
WEBHOOK_SCHEMA_VERSION = "application_inventory.webhook.v1"
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
PROTECTED_HEADERS = frozenset({"content-length", "host", "transfer-encoding"})


class WebhookConfigurationError(ValueError):
    pass


class WebhookDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class WebhookConfig:
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    bearer_token: str = ""
    signing_secret: str = ""
    timeout_seconds: int = DEFAULT_WEBHOOK_TIMEOUT_SECONDS
    batch_size: int = DEFAULT_WEBHOOK_BATCH_SIZE
    retries: int = DEFAULT_WEBHOOK_RETRIES
    delivery_mode: str = "batch"

    @classmethod
    def from_values(
        cls,
        url: str,
        headers: Mapping[str, str] | Iterable[tuple[str, str]] = (),
        bearer_token: str = "",
        signing_secret: str = "",
        timeout_seconds: int = DEFAULT_WEBHOOK_TIMEOUT_SECONDS,
        batch_size: int = DEFAULT_WEBHOOK_BATCH_SIZE,
        retries: int = DEFAULT_WEBHOOK_RETRIES,
        delivery_mode: str = "batch",
    ) -> WebhookConfig:
        normalized_mode = str(delivery_mode or "batch").strip().lower()
        if normalized_mode not in {"batch", "record"}:
            raise WebhookConfigurationError("Webhook delivery mode must be batch or record.")
        return cls(
            url=normalize_webhook_url(url),
            headers=normalize_webhook_headers(headers),
            bearer_token=str(bearer_token or "").strip(),
            signing_secret=str(signing_secret or "").strip(),
            timeout_seconds=positive_integer(timeout_seconds, DEFAULT_WEBHOOK_TIMEOUT_SECONDS),
            batch_size=positive_integer(batch_size, DEFAULT_WEBHOOK_BATCH_SIZE),
            retries=max(0, integer_value(retries, DEFAULT_WEBHOOK_RETRIES)),
            delivery_mode=normalized_mode,
        )


@dataclass(frozen=True)
class WebhookDeliveryResult:
    event: str
    records: int
    batches: int


class WebhookPublisher:
    def __init__(
        self,
        config: WebhookConfig,
        event: str,
        session: requests.Session | Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.event = clean_event_name(event)
        self.session = session or requests.Session()
        self._close_session = session is None
        self._sleep = sleep
        self._records: list[dict[str, Any]] = []
        self._record_count = 0
        self._batch_count = 0
        self._finished = False
        self._lock = threading.Lock()

    def publish(self, record: Mapping[str, Any]) -> None:
        normalized_record = dict(record)
        with self._lock:
            self._ensure_open()
            if self.config.delivery_mode == "record":
                self._deliver_record(normalized_record)
                return
            self._records.append(normalized_record)
            if len(self._records) >= self.config.batch_size:
                self._flush_batch()

    def finish(self) -> WebhookDeliveryResult:
        with self._lock:
            if not self._finished:
                self._flush_batch()
                self._finished = True
            return WebhookDeliveryResult(self.event, self._record_count, self._batch_count)

    def close(self) -> WebhookDeliveryResult:
        try:
            return self.finish()
        finally:
            self._close_http_session()

    def abort(self) -> None:
        with self._lock:
            self._records = []
            self._finished = True
            self._close_http_session()

    def _ensure_open(self) -> None:
        if self._finished:
            raise WebhookDeliveryError("Webhook publisher has already finished.")

    def _close_http_session(self) -> None:
        if self._close_session:
            self.session.close()
            self._close_session = False

    def _flush_batch(self) -> None:
        if not self._records:
            return
        records = self._records
        self._records = []
        self._deliver_batch(records)

    def _deliver_record(self, record: dict[str, Any]) -> None:
        payload = json_payload(record)
        self._send(payload, 1)

    def _deliver_batch(self, records: list[dict[str, Any]]) -> None:
        payload = json_payload(
            {
                "schemaVersion": WEBHOOK_SCHEMA_VERSION,
                "event": self.event,
                "sentAt": datetime.now(timezone.utc).isoformat(),
                "batch": {"sequence": self._batch_count + 1, "records": len(records)},
                "records": records,
            }
        )
        self._send(payload, len(records))

    def _send(self, payload: bytes, record_count: int) -> None:
        delivery_id = uuid.uuid4().hex
        headers = webhook_headers(self.config, self.event, delivery_id, payload)
        attempts = self.config.retries + 1
        for attempt in range(1, attempts + 1):
            try:
                response = self.session.post(
                    self.config.url,
                    data=payload,
                    headers=headers,
                    timeout=self.config.timeout_seconds,
                    allow_redirects=False,
                )
            except requests.RequestException as exc:
                if attempt >= attempts:
                    raise WebhookDeliveryError(
                        f"Webhook delivery to {public_webhook_url(self.config.url)} failed after {attempt} attempts."
                    ) from exc
                self._sleep(retry_delay(attempt))
                continue
            try:
                status_code = int(response.status_code)
            finally:
                response.close()
            if 200 <= status_code < 300:
                self._record_count += record_count
                self._batch_count += 1
                return
            if status_code not in {429, 500, 502, 503, 504} or attempt >= attempts:
                raise WebhookDeliveryError(
                    f"Webhook returned HTTP {status_code} from {public_webhook_url(self.config.url)}."
                )
            self._sleep(retry_delay(attempt))


def configured_webhook() -> WebhookConfig | None:
    url = os.getenv("APPLICATION_INVENTORY_WEBHOOK_URL", "").strip()
    if not url:
        return None
    return WebhookConfig.from_values(
        url,
        headers=environment_headers(),
        bearer_token=os.getenv("APPLICATION_INVENTORY_WEBHOOK_BEARER_TOKEN", ""),
        signing_secret=os.getenv("APPLICATION_INVENTORY_WEBHOOK_SIGNING_SECRET", ""),
        timeout_seconds=os.getenv(
            "APPLICATION_INVENTORY_WEBHOOK_TIMEOUT_SECONDS", str(DEFAULT_WEBHOOK_TIMEOUT_SECONDS)
        ),
        batch_size=os.getenv(
            "APPLICATION_INVENTORY_WEBHOOK_BATCH_SIZE", str(DEFAULT_WEBHOOK_BATCH_SIZE)
        ),
        retries=os.getenv(
            "APPLICATION_INVENTORY_WEBHOOK_RETRIES", str(DEFAULT_WEBHOOK_RETRIES)
        ),
        delivery_mode=os.getenv("APPLICATION_INVENTORY_WEBHOOK_DELIVERY_MODE", "batch"),
    )


def configured_webhooks() -> tuple[WebhookConfig, ...]:
    raw = os.getenv("APPLICATION_INVENTORY_WEBHOOK_CONFIGURATIONS", "").strip()
    if not raw:
        configured = configured_webhook()
        return (configured,) if configured else ()
    try:
        values = json.loads(raw)
    except ValueError as exc:
        raise WebhookConfigurationError(
            "APPLICATION_INVENTORY_WEBHOOK_CONFIGURATIONS must be a JSON array."
        ) from exc
    if not isinstance(values, list):
        raise WebhookConfigurationError(
            "APPLICATION_INVENTORY_WEBHOOK_CONFIGURATIONS must be a JSON array."
        )
    configurations: list[WebhookConfig] = []
    for value in values:
        if not isinstance(value, Mapping):
            raise WebhookConfigurationError("Each webhook configuration must be a JSON object.")
        headers = value.get("headers")
        configurations.append(
            WebhookConfig.from_values(
                str(value.get("url") or ""),
                headers=headers if isinstance(headers, Mapping) else {},
                bearer_token=str(value.get("bearerToken") or value.get("bearer_token") or ""),
                signing_secret=str(value.get("signingSecret") or value.get("signing_secret") or ""),
                timeout_seconds=value.get("timeoutSeconds", value.get("timeout_seconds", DEFAULT_WEBHOOK_TIMEOUT_SECONDS)),
                batch_size=value.get("batchSize", value.get("batch_size", DEFAULT_WEBHOOK_BATCH_SIZE)),
                retries=value.get("retries", DEFAULT_WEBHOOK_RETRIES),
                delivery_mode=str(value.get("deliveryMode") or value.get("delivery_mode") or "batch"),
            )
        )
    return tuple(configurations)


def normalize_webhook_url(value: str) -> str:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    if not raw or parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise WebhookConfigurationError("Webhook URL must be an absolute HTTP or HTTPS URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise WebhookConfigurationError(
            "Webhook URL cannot contain credentials, a query, or a fragment."
        )
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise WebhookConfigurationError("Webhook URL must use HTTPS unless it targets loopback.")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def normalize_webhook_headers(
    values: Mapping[str, str] | Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    source = values.items() if isinstance(values, Mapping) else values
    headers: dict[str, str] = {}
    for name, value in source:
        normalized_name = str(name or "").strip()
        normalized_value = str(value or "").strip()
        if not HEADER_NAME_RE.fullmatch(normalized_name):
            raise WebhookConfigurationError("Webhook header names may contain only letters, digits, and hyphens.")
        if normalized_name.lower() in PROTECTED_HEADERS:
            raise WebhookConfigurationError(f"Webhook header {normalized_name!r} cannot be overridden.")
        if "\r" in normalized_value or "\n" in normalized_value:
            raise WebhookConfigurationError("Webhook header values cannot contain line breaks.")
        if normalized_value:
            headers[normalized_name] = normalized_value
    return tuple(headers.items())


def environment_headers() -> Mapping[str, str]:
    raw = os.getenv("APPLICATION_INVENTORY_WEBHOOK_HEADERS", "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise WebhookConfigurationError(
            "APPLICATION_INVENTORY_WEBHOOK_HEADERS must be a JSON object."
        ) from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise WebhookConfigurationError(
            "APPLICATION_INVENTORY_WEBHOOK_HEADERS must be a JSON object with string keys."
        )
    return {key: str(header_value) for key, header_value in value.items()}


def parse_webhook_header_values(values: Iterable[str]) -> Mapping[str, str]:
    headers: dict[str, str] = {}
    for raw in values:
        name, separator, value = str(raw or "").partition("=")
        if not separator or not name.strip():
            raise WebhookConfigurationError("Webhook headers must use NAME=VALUE format.")
        headers[name.strip()] = value.strip()
    return headers


def webhook_headers(
    config: WebhookConfig, event: str, delivery_id: str, payload: bytes
) -> dict[str, str]:
    headers = dict(config.headers)
    headers.setdefault("Authorization", f"Bearer {config.bearer_token}")
    if not config.bearer_token and headers.get("Authorization") == "Bearer ":
        headers.pop("Authorization")
    headers.update(
        {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": APPLICATION_USER_AGENT,
            "X-Application-Inventory-Event": event,
            "X-Application-Inventory-Delivery-Id": delivery_id,
        }
    )
    if config.signing_secret:
        signature = hmac.new(
            config.signing_secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()
        headers["X-Application-Inventory-Signature"] = f"sha256={signature}"
    return headers


def json_payload(value: Any) -> bytes:
    return json.dumps(value, default=json_value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def json_value(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return str(value)


def clean_event_name(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or len(normalized) > 200:
        raise WebhookConfigurationError("Webhook event name must contain between 1 and 200 characters.")
    return normalized


def positive_integer(value: Any, default: int) -> int:
    return max(1, integer_value(value, default))


def integer_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def retry_delay(attempt: int) -> float:
    return min(10.0, 0.5 * (2 ** max(0, attempt - 1)))


def public_webhook_url(value: str) -> str:
    parsed = urlparse(value)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))