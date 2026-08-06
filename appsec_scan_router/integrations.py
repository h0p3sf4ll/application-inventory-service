from __future__ import annotations

from copy import deepcopy
import json
from typing import Any, Mapping
from uuid import uuid4

from .connectors.http import ConnectorConfigurationError, normalize_api_url
from .connectors.registry import CONNECTOR_KEYS, connector_setup
from .remediation import default_remediation_policy, normalize_remediation_policy
from .webhooks import WebhookConfig, WebhookConfigurationError


INTEGRATIONS_VERSION = 1
MAX_WEBHOOKS_PER_USER = 25


def default_integrations() -> dict[str, Any]:
    return {
        "version": INTEGRATIONS_VERSION,
        "webhooks": [],
        "connectors": {},
        "remediationPolicy": default_remediation_policy(),
    }


def normalized_integrations(value: Mapping[str, Any] | None) -> dict[str, Any]:
    source = dict(value or {})
    webhooks = [
        normalized_webhook(item)
        for item in source.get("webhooks", [])
        if isinstance(item, Mapping)
    ]
    connectors = source.get("connectors")
    return {
        "version": INTEGRATIONS_VERSION,
        "webhooks": webhooks[:MAX_WEBHOOKS_PER_USER],
        "connectors": deepcopy(connectors) if isinstance(connectors, Mapping) else {},
        "remediationPolicy": normalize_remediation_policy(
            source.get("remediationPolicy")
            if isinstance(source.get("remediationPolicy"), Mapping)
            else None
        ),
    }


def upsert_webhook(
    integrations: Mapping[str, Any] | None, payload: Mapping[str, Any]
) -> dict[str, Any]:
    result = normalized_integrations(integrations)
    webhooks = result["webhooks"]
    webhook_id = clean_text(payload.get("id"))
    index = next(
        (position for position, item in enumerate(webhooks) if item["id"] == webhook_id),
        None,
    )
    if index is None and len(webhooks) >= MAX_WEBHOOKS_PER_USER:
        raise ValueError(f"A user may configure at most {MAX_WEBHOOKS_PER_USER} webhooks.")
    existing = webhooks[index] if index is not None else {}
    candidate = {
        **existing,
        "id": existing.get("id") or uuid4().hex,
        "name": clean_text(payload.get("name")) or existing.get("name", ""),
        "url": clean_text(payload.get("url")) or existing.get("url", ""),
        "enabled": bool(payload.get("enabled", existing.get("enabled", True))),
        "deliveryMode": clean_text(payload.get("deliveryMode")) or existing.get("deliveryMode", "batch"),
        "batchSize": payload.get("batchSize", existing.get("batchSize", 100)),
        "retries": payload.get("retries", existing.get("retries", 3)),
        "timeoutSeconds": payload.get("timeoutSeconds", existing.get("timeoutSeconds", 30)),
        "headers": payload.get("headers", existing.get("headers", {})),
        "bearerToken": secret_value(payload, "bearerToken", existing),
        "signingSecret": secret_value(payload, "signingSecret", existing),
    }
    normalized = normalized_webhook(candidate)
    if index is None:
        webhooks.append(normalized)
    else:
        webhooks[index] = normalized
    return result


def delete_webhook(integrations: Mapping[str, Any] | None, webhook_id: Any) -> dict[str, Any]:
    result = normalized_integrations(integrations)
    target = clean_text(webhook_id)
    result["webhooks"] = [item for item in result["webhooks"] if item["id"] != target]
    return result


def public_webhooks(integrations: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    return [
        {
            "id": item["id"],
            "name": item["name"],
            "url": item["url"],
            "enabled": item["enabled"],
            "deliveryMode": item["deliveryMode"],
            "batchSize": item["batchSize"],
            "retries": item["retries"],
            "timeoutSeconds": item["timeoutSeconds"],
            "headerNames": sorted(item["headers"]),
            "hasBearerToken": bool(item["bearerToken"]),
            "hasSigningSecret": bool(item["signingSecret"]),
        }
        for item in normalized_integrations(integrations)["webhooks"]
    ]


def webhook_configurations(integrations: Mapping[str, Any] | None) -> tuple[WebhookConfig, ...]:
    configurations: list[WebhookConfig] = []
    for item in normalized_integrations(integrations)["webhooks"]:
        if not item["enabled"]:
            continue
        configurations.append(
            WebhookConfig.from_values(
                item["url"],
                headers=item["headers"],
                bearer_token=item["bearerToken"],
                signing_secret=item["signingSecret"],
                timeout_seconds=item["timeoutSeconds"],
                batch_size=item["batchSize"],
                retries=item["retries"],
                delivery_mode=item["deliveryMode"],
            )
        )
    return tuple(configurations)


def webhook_environment_value(integrations: Mapping[str, Any] | None) -> str:
    records = [
        {
            "url": item["url"],
            "headers": item["headers"],
            "bearerToken": item["bearerToken"],
            "signingSecret": item["signingSecret"],
            "timeoutSeconds": item["timeoutSeconds"],
            "batchSize": item["batchSize"],
            "retries": item["retries"],
            "deliveryMode": item["deliveryMode"],
        }
        for item in normalized_integrations(integrations)["webhooks"]
        if item["enabled"]
    ]
    return json.dumps(records, separators=(",", ":"))


def connector_configurations(
    integrations: Mapping[str, Any] | None,
) -> dict[str, dict[str, str]]:
    values = normalized_integrations(integrations)["connectors"]
    return {
        key: {str(name): clean_text(value) for name, value in item.items()}
        for key, item in values.items()
        if key in CONNECTOR_KEYS and isinstance(item, Mapping)
    }


def remediation_policy(integrations: Mapping[str, Any] | None) -> dict[str, int]:
    return normalized_integrations(integrations)["remediationPolicy"]


def upsert_remediation_policy(
    integrations: Mapping[str, Any] | None, policy: Mapping[str, Any]
) -> dict[str, Any]:
    result = normalized_integrations(integrations)
    result["remediationPolicy"] = normalize_remediation_policy(policy)
    return result


def upsert_connector_configuration(
    integrations: Mapping[str, Any] | None, connector_key: Any, payload: Mapping[str, Any]
) -> dict[str, Any]:
    key = clean_text(connector_key).casefold()
    if key not in CONNECTOR_KEYS:
        raise ValueError("Unknown scanner connector.")
    result = normalized_integrations(integrations)
    current = connector_configurations(result).get(key, {})
    setup = connector_setup(key)
    configured: dict[str, str] = {}
    for field in setup["fields"]:
        field_key = field["key"]
        if field["secret"]:
            configured[field_key] = secret_value(payload, field_key, current)
            continue
        value = clean_text(payload.get(field_key)) or current.get(field_key, "")
        if field_key == "endpoint" and value:
            try:
                value = normalize_api_url(value)
            except ConnectorConfigurationError as exc:
                raise ValueError(str(exc)) from exc
        configured[field_key] = value
    result["connectors"][key] = configured
    return result


def public_connector_configuration(
    integrations: Mapping[str, Any] | None, connector_key: Any
) -> dict[str, Any]:
    key = clean_text(connector_key).casefold()
    if key not in CONNECTOR_KEYS:
        raise ValueError("Unknown scanner connector.")
    values = connector_configurations(integrations).get(key, {})
    setup = connector_setup(key)
    visible = {
        field["key"]: values.get(field["key"], "")
        for field in setup["fields"]
        if not field["secret"]
    }
    visible["secrets"] = {
        field["key"]: bool(values.get(field["key"]))
        for field in setup["fields"]
        if field["secret"]
    }
    return visible


def normalized_webhook(value: Mapping[str, Any]) -> dict[str, Any]:
    name = clean_text(value.get("name"))
    if not name or len(name) > 100:
        raise ValueError("Webhook name must contain between 1 and 100 characters.")
    webhook_id = clean_text(value.get("id")) or uuid4().hex
    if len(webhook_id) > 100:
        raise ValueError("Webhook identifier is invalid.")
    headers = value.get("headers")
    if not isinstance(headers, Mapping):
        headers = {}
    try:
        configuration = WebhookConfig.from_values(
            clean_text(value.get("url")),
            headers={clean_text(name): clean_text(item) for name, item in headers.items()},
            bearer_token=clean_text(value.get("bearerToken")),
            signing_secret=clean_text(value.get("signingSecret")),
            timeout_seconds=value.get("timeoutSeconds", 30),
            batch_size=value.get("batchSize", 100),
            retries=value.get("retries", 3),
            delivery_mode=clean_text(value.get("deliveryMode")) or "batch",
        )
    except WebhookConfigurationError as exc:
        raise ValueError(str(exc)) from exc
    return {
        "id": webhook_id,
        "name": name,
        "url": configuration.url,
        "enabled": bool(value.get("enabled", True)),
        "deliveryMode": configuration.delivery_mode,
        "batchSize": configuration.batch_size,
        "retries": configuration.retries,
        "timeoutSeconds": configuration.timeout_seconds,
        "headers": dict(configuration.headers),
        "bearerToken": configuration.bearer_token,
        "signingSecret": configuration.signing_secret,
    }


def secret_value(payload: Mapping[str, Any], field: str, existing: Mapping[str, Any]) -> str:
    clear_flag = f"clear{field[:1].upper()}{field[1:]}"
    if payload.get(clear_flag) is True:
        return ""
    value = clean_text(payload.get(field))
    return value or clean_text(existing.get(field))


def clean_text(value: Any) -> str:
    return str(value or "").strip()