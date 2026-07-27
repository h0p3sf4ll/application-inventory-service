from __future__ import annotations

import json
import os
from pathlib import Path
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from .constants import APPLICATION_USER_AGENT, MISSING_REQUESTS_MESSAGE

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None
    HTTPAdapter = None
    Retry = None

try:
    import truststore
except ImportError:
    truststore = None


if truststore is not None and os.getenv(
    "APPLICATION_INVENTORY_CONNECTOR_SYSTEM_TRUST", "true"
).strip().casefold() not in {"0", "false", "no", "off"}:
    truststore.inject_into_ssl()


DEFAULT_CONNECTOR_TIMEOUT_SECONDS = 30
DEFAULT_CONNECTOR_RETRIES = 5
DEFAULT_CONNECTOR_POOL_SIZE = 4
DEFAULT_CONNECTOR_MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class ConnectorError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class ConnectorConfigurationError(ValueError):
    pass


class JsonApiClient:
    def __init__(
        self,
        base_url: str,
        headers: Mapping[str, str] | None = None,
        auth: Any = None,
        timeout_seconds: int = DEFAULT_CONNECTOR_TIMEOUT_SECONDS,
    ) -> None:
        if requests is None or HTTPAdapter is None or Retry is None:
            raise SystemExit(MISSING_REQUESTS_MESSAGE)
        self.base_url = normalize_api_url(base_url)
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.verify = connector_ca_bundle()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": APPLICATION_USER_AGENT,
                **dict(headers or {}),
            }
        )
        self.session.auth = auth
        retry = Retry(
            total=positive_env_int(
                "APPLICATION_INVENTORY_CONNECTOR_MAX_RETRIES",
                DEFAULT_CONNECTOR_RETRIES,
            ),
            connect=2,
            read=3,
            other=0,
            backoff_factor=0.8,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            respect_retry_after_header=True,
        )
        pool_size = positive_env_int(
            "APPLICATION_INVENTORY_CONNECTOR_POOL_SIZE", DEFAULT_CONNECTOR_POOL_SIZE
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            pool_block=True,
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def close(self) -> None:
        self.session.close()

    def get(
        self, path: str, params: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        return self.request("GET", path, params=params)

    def post(self, path: str, document: Mapping[str, Any]) -> dict[str, Any]:
        return self.request("POST", path, json=document)

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        url = api_url(self.base_url, path)
        try:
            with self.session.request(
                method,
                url,
                timeout=self.timeout_seconds,
                verify=self.verify,
                stream=True,
                **kwargs,
            ) as response:
                maximum = positive_env_int(
                    "APPLICATION_INVENTORY_CONNECTOR_MAX_RESPONSE_BYTES",
                    DEFAULT_CONNECTOR_MAX_RESPONSE_BYTES,
                )
                body = bounded_response_body(response, maximum)
                if not 200 <= response.status_code < 300:
                    detail = body[:500].decode("utf-8", errors="replace")
                    detail = detail.replace("\n", " ").strip()
                    raise ConnectorError(
                        "Connector returned HTTP "
                        f"{response.status_code} from {public_url(response.url)}: "
                        f"{detail}",
                        response.status_code,
                    )
        except requests.RequestException as exc:
            raise ConnectorError(
                f"Connector request to {public_url(url)} failed."
            ) from exc
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ConnectorError(
                f"Connector returned invalid JSON from {public_url(url)}."
            ) from exc
        if not isinstance(document, dict):
            raise ConnectorError(
                f"Connector returned an unexpected response from {public_url(url)}."
            )
        return document


def bounded_response_body(response: Any, maximum: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    try:
        declared_length = int(content_length) if content_length else 0
    except ValueError:
        declared_length = 0
    if declared_length > maximum:
        raise ConnectorError(
            f"Connector response exceeds the configured {maximum:,}-byte limit."
        )
    body = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        body.extend(chunk)
        if len(body) > maximum:
            raise ConnectorError(
                f"Connector response exceeds the configured {maximum:,}-byte limit."
            )
    return bytes(body)


def normalize_api_url(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ConnectorConfigurationError("Connector API URL is required.")
    parsed = urlparse(raw)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ConnectorConfigurationError("Connector API URL must be an absolute URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConnectorConfigurationError(
            "Connector API URL cannot contain credentials, a query, or a fragment."
        )
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ConnectorConfigurationError(
            "Connector API URL must use HTTPS unless it targets loopback."
        )
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", "")
    )


def api_url(base_url: str, path: str) -> str:
    if not path:
        return base_url
    return urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))


def public_url(value: str) -> str:
    parsed = urlparse(value)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def positive_env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


def connector_ca_bundle() -> str | bool:
    configured = os.getenv("APPLICATION_INVENTORY_CONNECTOR_CA_BUNDLE", "").strip()
    if not configured:
        return True
    path = Path(configured).expanduser()
    if not path.is_file() or not os.access(path, os.R_OK):
        raise ConnectorConfigurationError(
            "APPLICATION_INVENTORY_CONNECTOR_CA_BUNDLE must reference a readable CA bundle."
        )
    return str(path)
