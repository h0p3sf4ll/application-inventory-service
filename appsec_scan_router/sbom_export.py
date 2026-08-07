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


def _component_name(row: Mapping[str, Any]) -> str:
    name = str(row.get("inventory_name") or row.get("repo_name") or "").strip()
    return name or str(row.get("branch_name") or "unknown")


def _component_description(row: Mapping[str, Any], name: str) -> str:
    parts = []
    for label, field in (
        (None, "organization"),
        (None, "project"),
        ("repo", "repo_name"),
        ("branch", "branch_name"),
    ):
        val = str(row.get(field) or "").strip()
        if val and (field not in ("repo_name", "branch_name") or val != name):
            parts.append(f"{label}: {val}" if label else val)
    return " / ".join(parts)


def _external_refs(row: Mapping[str, Any]) -> list[tuple[str, str]]:
    refs = []
    repo_url = str(row.get("web_url") or row.get("source_url") or "").strip()
    if repo_url:
        refs.append(("vcs", repo_url))
    domain = str(row.get("primary_web_domain") or "").strip()
    if domain:
        url = domain if domain.startswith("http") else f"https://{domain}"
        refs.append(("website", url))
    return refs


def _properties(row: Mapping[str, Any]) -> list[tuple[str, str]]:
    props = []
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
            props.append((prop_name, val))
    return props


def rows_to_sbom(
    rows: Iterable[Mapping[str, Any]],
    sbom_type: str = "sbom",
    bom_format: str = "cdx_json",
) -> bytes:
    if bom_format == "cdx_xml":
        return rows_to_cdx_xml(rows, sbom_type)
    if bom_format == "spdx_json":
        return rows_to_spdx_json(rows, sbom_type)
    return rows_to_cdx_json(rows, sbom_type)


def rows_to_cdx_json(rows: Iterable[Mapping[str, Any]], sbom_type: str = "sbom") -> bytes:
    components = []
    for row in rows:
        name = _component_name(row)
        version = str(row.get("inventory_version") or "").strip()
        inventory_types = str(row.get("inventory_types") or "")

        component: dict[str, Any] = {
            "type": _component_type(inventory_types),
            "bom-ref": _bom_ref(row),
            "name": name,
        }
        if version:
            component["version"] = version
        description = _component_description(row, name)
        if description:
            component["description"] = description
        refs = _external_refs(row)
        if refs:
            component["externalReferences"] = [{"type": t, "url": u} for t, u in refs]
        props = _properties(row)
        if props:
            component["properties"] = [{"name": n, "value": v} for n, v in props]
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


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def rows_to_cdx_xml(rows: Iterable[Mapping[str, Any]], sbom_type: str = "sbom") -> bytes:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">',
        "  <metadata>",
        f"    <timestamp>{timestamp}</timestamp>",
        "    <tools>",
        "      <tool><vendor>AppSec Atlas</vendor><name>AppSec Atlas</name></tool>",
        "    </tools>",
        '    <component type="application">',
        f"      <name>{_xml_escape(_sbom_title(sbom_type))}</name>",
        f"      <description>{_xml_escape(_sbom_description(sbom_type))}</description>",
        "    </component>",
        "  </metadata>",
        "  <components>",
    ]
    for row in rows:
        name = _component_name(row)
        inventory_types = str(row.get("inventory_types") or "")
        comp_type = _component_type(inventory_types)
        bom_ref = _bom_ref(row)
        version = str(row.get("inventory_version") or "").strip()

        lines.append(f'    <component type="{comp_type}" bom-ref="{bom_ref}">')
        lines.append(f"      <name>{_xml_escape(name)}</name>")
        if version:
            lines.append(f"      <version>{_xml_escape(version)}</version>")
        description = _component_description(row, name)
        if description:
            lines.append(f"      <description>{_xml_escape(description)}</description>")

        refs = _external_refs(row)
        if refs:
            lines.append("      <externalReferences>")
            for ref_type, url in refs:
                lines.append(
                    f'        <reference type="{ref_type}"><url>{_xml_escape(url)}</url></reference>'
                )
            lines.append("      </externalReferences>")

        props = _properties(row)
        if props:
            lines.append("      <properties>")
            for prop_name, prop_val in props:
                lines.append(
                    f'        <property name="{_xml_escape(prop_name)}">{_xml_escape(prop_val)}</property>'
                )
            lines.append("      </properties>")

        lines.append("    </component>")

    lines.append("  </components>")
    lines.append("</bom>")
    return "\n".join(lines).encode("utf-8")


def rows_to_spdx_json(rows: Iterable[Mapping[str, Any]], sbom_type: str = "sbom") -> bytes:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    packages = []
    seen_ids: set[str] = set()

    for row in rows:
        name = _component_name(row)
        version = str(row.get("inventory_version") or "").strip() or "NOASSERTION"
        base_id = _bom_ref(row)
        spdx_id = f"SPDXRef-{base_id}"
        if spdx_id in seen_ids:
            spdx_id = f"SPDXRef-{base_id}-{len(seen_ids)}"
        seen_ids.add(spdx_id)

        repo_url = str(row.get("web_url") or row.get("source_url") or "").strip()
        package: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": repo_url or "NOASSERTION",
            "filesAnalyzed": False,
        }

        ext_refs = []
        if repo_url:
            ext_refs.append({
                "referenceCategory": "OTHER",
                "referenceType": "vcs",
                "referenceLocator": repo_url,
            })
        domain = str(row.get("primary_web_domain") or "").strip()
        if domain:
            url = domain if domain.startswith("http") else f"https://{domain}"
            ext_refs.append({
                "referenceCategory": "OTHER",
                "referenceType": "website",
                "referenceLocator": url,
            })
        if ext_refs:
            package["externalRefs"] = ext_refs

        comment_parts = []
        for label, field in (
            ("Provider", "provider"),
            ("Organization", "organization"),
            ("Project", "project"),
            ("Repository", "repo_name"),
            ("Branch", "branch_name"),
            ("Language", "primary_language"),
            ("Categories", "categories"),
            ("Inventory types", "inventory_types"),
            ("Confidence", "confidence"),
            ("Contributors", "branch_contributing_developers"),
        ):
            val = str(row.get(field) or "").strip()
            if val:
                comment_parts.append(f"{label}: {val}")
        if comment_parts:
            package["comment"] = "; ".join(comment_parts)

        packages.append(package)

    ns_id = hashlib.sha256(f"appsec-atlas-{sbom_type}-{timestamp}".encode()).hexdigest()[:16]
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"appsec-atlas-{sbom_type}",
        "documentNamespace": f"https://spdx.org/spdxdocs/appsec-atlas-{sbom_type}-{ns_id}",
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: AppSec Atlas"],
            "comment": _sbom_description(sbom_type),
        },
        "packages": packages,
    }
    return json.dumps(doc, indent=2, default=str).encode("utf-8")
