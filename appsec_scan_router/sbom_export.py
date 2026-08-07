from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


_COMPONENT_TYPE_PRIORITY = (
    ("machine-learning-model", "ml_enabled"),
    ("library", "library"),
    ("framework", "framework"),
)


def _component_type(inventory_types: str) -> str:
    types_text = str(inventory_types or "").lower()
    for cdx_type, marker in _COMPONENT_TYPE_PRIORITY:
        if marker in types_text:
            return cdx_type
    return "application"


def _bom_ref(row: Mapping[str, Any]) -> str:
    key = "/".join(
        str(row.get(field) or "")
        for field in ("provider", "organization", "repo_name", "branch_name")
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _sbom_title(sbom_type: str) -> str:
    return {
        "aibom": "AI Bill of Materials",
        "mlbom": "ML Bill of Materials",
    }.get(sbom_type, "Software Bill of Materials")


def _sbom_description(sbom_type: str) -> str:
    return {
        "aibom": "AI-enabled application inventory exported from AppSec Atlas",
        "mlbom": "ML-enabled application inventory exported from AppSec Atlas",
    }.get(sbom_type, "Application inventory exported from AppSec Atlas")


def rows_to_sbom(rows: Iterable[Mapping[str, Any]], sbom_type: str = "sbom") -> bytes:
    components = []
    for row in rows:
        name = str(row.get("inventory_name") or row.get("repo_name") or "").strip()
        if not name:
            name = str(row.get("branch_name") or "unknown")
        version = str(row.get("inventory_version") or "").strip()
        inventory_types = str(row.get("inventory_types") or "")

        component: dict[str, Any] = {
            "type": _component_type(inventory_types),
            "bom-ref": _bom_ref(row),
            "name": name,
        }
        if version:
            component["version"] = version

        description_parts = []
        for label, field in (
            (None, "organization"),
            (None, "project"),
            ("repo", "repo_name"),
            ("branch", "branch_name"),
        ):
            val = str(row.get(field) or "").strip()
            if val and (field not in ("repo_name", "branch_name") or val != name):
                description_parts.append(f"{label}: {val}" if label else val)
        if description_parts:
            component["description"] = " / ".join(description_parts)

        external_refs = []
        repo_url = str(row.get("web_url") or row.get("source_url") or "").strip()
        if repo_url:
            external_refs.append({"type": "vcs", "url": repo_url})
        domain = str(row.get("primary_web_domain") or "").strip()
        if domain:
            url = domain if domain.startswith("http") else f"https://{domain}"
            external_refs.append({"type": "website", "url": url})
        if external_refs:
            component["externalReferences"] = external_refs

        properties = []
        for prop_name, field in (
            ("appsecat:provider", "provider"),
            ("appsecat:language", "primary_language"),
            ("appsecat:categories", "categories"),
            ("appsecat:contributors", "branch_contributing_developers"),
            ("appsecat:confidence", "confidence"),
            ("appsecat:inventory_types", "inventory_types"),
        ):
            val = str(row.get(field) or "").strip()
            if val:
                properties.append({"name": prop_name, "value": val})
        if properties:
            component["properties"] = properties

        components.append(component)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "AppSec Atlas", "name": "AppSec Atlas"}],
            "component": {
                "type": "application",
                "name": _sbom_title(sbom_type),
                "description": _sbom_description(sbom_type),
            },
        },
        "components": components,
    }
    return json.dumps(bom, indent=2, default=str).encode("utf-8")
