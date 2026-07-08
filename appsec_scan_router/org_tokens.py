from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .models import AzureDevOpsOrgPat
from .utils import clean_value_without_resource_filter


def parse_ado_org_pat_values(values: Iterable[Any] | Any) -> tuple[AzureDevOpsOrgPat, ...]:
    if values is None:
        return ()
    candidates = (values,) if isinstance(values, (dict, str, bytes)) else values
    org_tokens: dict[str, AzureDevOpsOrgPat] = {}
    for value in candidates:
        for org_pat in parse_ado_org_pat_value(value):
            org_tokens[org_pat.org.lower()] = org_pat
    return tuple(org_tokens.values())


def parse_ado_org_pat_value(value: Any) -> tuple[AzureDevOpsOrgPat, ...]:
    if value is None:
        return ()
    if isinstance(value, dict):
        org = value.get("org") or value.get("organization")
        pat = value.get("pat") or value.get("token")
        if org or pat:
            org_pat = make_ado_org_pat(org, pat)
            return (org_pat,) if org_pat else ()
        parsed: list[AzureDevOpsOrgPat] = []
        for org_key, pat_value in value.items():
            org_pat = make_ado_org_pat(org_key, pat_value)
            if org_pat:
                parsed.append(org_pat)
        return tuple(parsed)
    if isinstance(value, list | tuple):
        return parse_ado_org_pat_sequence(value)
    text = clean_value_without_resource_filter(value)
    if not text:
        return ()
    if text.startswith("{") or text.startswith("["):
        try:
            return parse_ado_org_pat_value(json.loads(text))
        except ValueError as exc:
            raise ValueError("Azure DevOps org PAT JSON is invalid.") from exc
    return parse_ado_org_pat_sequence(split_ado_org_pat_text(text))


def parse_ado_org_pat_sequence(values: Iterable[Any]) -> tuple[AzureDevOpsOrgPat, ...]:
    parsed: list[AzureDevOpsOrgPat] = []
    for value in values:
        if isinstance(value, dict):
            parsed.extend(parse_ado_org_pat_value(value))
            continue
        text = clean_value_without_resource_filter(value)
        if not text:
            continue
        separator = "=" if "=" in text else ":"
        if separator not in text:
            raise ValueError("Azure DevOps org PAT entries must use ORG=PAT.")
        org, pat = text.split(separator, 1)
        org_pat = make_ado_org_pat(org, pat)
        if org_pat:
            parsed.append(org_pat)
    return tuple(parsed)


def split_ado_org_pat_text(text: str) -> list[str]:
    entries: list[str] = []
    for line in text.replace(";", "\n").splitlines():
        for value in line.split(","):
            cleaned = value.strip()
            if cleaned:
                entries.append(cleaned)
    return entries


def make_ado_org_pat(org: Any, pat: Any) -> AzureDevOpsOrgPat | None:
    org_value = clean_value_without_resource_filter(org)
    pat_value = clean_value_without_resource_filter(pat)
    if not org_value and not pat_value:
        return None
    if not org_value or not pat_value:
        raise ValueError("Azure DevOps org PAT entries must include both organization and PAT.")
    return AzureDevOpsOrgPat(org=org_value, pat=pat_value)


def ado_org_pats_to_json(org_pats: Iterable[AzureDevOpsOrgPat | dict[str, Any]]) -> str:
    values = []
    for item in org_pats:
        if isinstance(item, AzureDevOpsOrgPat):
            org = item.org
            pat = item.pat
        else:
            org = clean_value_without_resource_filter(item.get("org"))
            pat = clean_value_without_resource_filter(item.get("pat"))
        if org and pat:
            values.append({"org": org, "pat": pat})
    return json.dumps(values)
