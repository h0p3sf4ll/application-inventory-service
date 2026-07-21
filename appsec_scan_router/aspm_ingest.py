from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urlparse

from .aspm_models import (
    FindingDocument,
    FindingInput,
    SourceLocation,
    bounded_text,
    clean_identity,
    float_or_none,
    json_safe_mapping,
    normalize_severity,
    normalize_status,
    string_tuple,
    utc_datetime,
)


SUPPORTED_FINDING_FORMATS = ("auto", "sarif", "semgrep", "sonarqube", "generic")
MAX_FINDINGS_PER_IMPORT = 100_000


def parse_finding_document(payload: Mapping[str, Any]) -> FindingDocument:
    source_format = clean_identity(payload.get("format") or "auto")
    if source_format not in SUPPORTED_FINDING_FORMATS:
        raise ValueError(
            "Finding format must be auto, sarif, semgrep, sonarqube, or generic."
        )
    document = payload.get("document")
    if document is None:
        document = payload.get("findings")
    if document is None:
        raise ValueError("A scanner document or findings array is required.")
    detected_format = (
        detect_format(document) if source_format == "auto" else source_format
    )
    context = mapping_value(payload.get("context"))
    scanned_targets = parse_scanned_targets(payload.get("scannedTargets"), context)
    complete_snapshot = payload.get("completeSnapshot") is True
    parser = {
        "sarif": parse_sarif,
        "semgrep": parse_semgrep,
        "sonarqube": parse_sonarqube,
        "generic": parse_generic,
    }[detected_format]
    parsed = parser(document, context)
    tool = mapping_value(payload.get("tool"))
    tool_name = bounded_text(
        tool.get("name") or parsed["tool_name"] or detected_format.title(), 200
    )
    tool_key = clean_identity(tool.get("key") or parsed["tool_key"] or tool_name)
    if not tool_key:
        raise ValueError("Scanner tool name or key is required.")
    findings = tuple(parsed["findings"])
    if not findings and not scanned_targets:
        raise ValueError(
            "The scanner document contains no findings or scanned targets."
        )
    if len(findings) > MAX_FINDINGS_PER_IMPORT:
        raise ValueError(
            f"Finding import exceeds the {MAX_FINDINGS_PER_IMPORT:,} record limit."
        )
    return FindingDocument(
        tool_key=tool_key,
        tool_name=tool_name,
        tool_type=clean_identity(tool.get("type") or parsed["tool_type"] or "other"),
        source_format=detected_format,
        findings=findings,
        scanned_targets=scanned_targets,
        complete_snapshot=complete_snapshot,
        metadata=json_safe_mapping(mapping_value(payload.get("metadata"))),
    )


def detect_format(document: Any) -> str:
    if isinstance(document, Mapping):
        if str(document.get("version", "")).startswith("2.1") and isinstance(
            document.get("runs"), list
        ):
            return "sarif"
        if isinstance(document.get("results"), list):
            return "semgrep"
        if isinstance(document.get("issues"), list):
            return "sonarqube"
        if isinstance(document.get("findings"), list):
            return "generic"
    if isinstance(document, list):
        return "generic"
    raise ValueError("The scanner document format could not be detected.")


def parse_sarif(document: Any, context: Mapping[str, Any]) -> dict[str, Any]:
    root = required_mapping(document, "SARIF document")
    runs = sequence_value(root.get("runs"))
    findings: list[FindingInput] = []
    tool_names: list[str] = []
    for run in runs:
        run_data = mapping_value(run)
        inferred_context = {
            key: value for key, value in sarif_source_context(run_data).items() if value
        }
        run_context = {**context, **inferred_context}
        driver = mapping_value(mapping_value(run_data.get("tool")).get("driver"))
        tool_name = bounded_text(driver.get("fullName") or driver.get("name"), 200)
        if tool_name:
            tool_names.append(tool_name)
        rules = {
            bounded_text(rule.get("id"), 500): rule
            for item in sequence_value(driver.get("rules"))
            if (rule := mapping_value(item)).get("id")
        }
        for item in sequence_value(run_data.get("results")):
            result = mapping_value(item)
            rule_id = bounded_text(result.get("ruleId"), 500)
            rule = mapping_value(rules.get(rule_id))
            properties = {
                **mapping_value(rule.get("properties")),
                **mapping_value(result.get("properties")),
            }
            location = sarif_location(result, run_context)
            message = message_text(result.get("message"))
            rule_description = message_text(
                rule.get("fullDescription")
            ) or message_text(rule.get("shortDescription"))
            cwes = extract_identifiers(
                properties.get("cwe") or properties.get("cwes"), "CWE"
            )
            tags = string_tuple(properties.get("tags"))
            if not cwes:
                cwes = extract_identifiers(tags, "CWE")
            cves = extract_identifiers(properties.get("cve") or tags, "CVE")
            fingerprints = mapping_value(result.get("partialFingerprints"))
            if not fingerprints:
                fingerprints = mapping_value(result.get("fingerprints"))
            findings.append(
                FindingInput(
                    external_id=bounded_text(
                        result.get("guid") or result.get("correlationGuid") or rule_id,
                        500,
                    ),
                    fingerprint_hint=first_mapping_value(fingerprints),
                    title=bounded_text(
                        message
                        or message_text(rule.get("shortDescription"))
                        or rule_id
                        or "Security finding",
                        1000,
                    ),
                    description=bounded_text(rule_description or message, 20_000),
                    rule_id=rule_id,
                    category=bounded_text(
                        properties.get("category") or first_security_tag(tags), 300
                    ),
                    severity=sarif_severity(result, properties),
                    confidence=bounded_text(properties.get("confidence"), 50),
                    location=location,
                    scanner_url=bounded_text(
                        result.get("hostedViewerUri") or rule.get("helpUri"), 2000
                    ),
                    remediation=bounded_text(message_text(rule.get("help")), 20_000),
                    cwes=cwes,
                    cves=cves,
                    package_name=bounded_text(properties.get("packageName"), 500),
                    package_version=bounded_text(properties.get("packageVersion"), 200),
                    fixed_version=bounded_text(properties.get("fixedVersion"), 200),
                    cvss_score=float_or_none(
                        properties.get("security-severity") or properties.get("cvss"),
                        maximum=10,
                    ),
                    epss_score=float_or_none(properties.get("epss")),
                    exploit_available=boolean_value(
                        properties.get("exploitAvailable")
                        or properties.get("knownExploit")
                    ),
                    first_seen=utc_datetime(properties.get("firstSeen")),
                    last_seen=utc_datetime(properties.get("lastSeen")),
                    raw_data=json_safe_mapping(result),
                )
            )
    tool_name = tool_names[0] if tool_names else "SARIF"
    return {
        "tool_name": tool_name,
        "tool_key": clean_identity(tool_name),
        "tool_type": "sast",
        "findings": findings,
    }


def parse_semgrep(document: Any, context: Mapping[str, Any]) -> dict[str, Any]:
    root = required_mapping(document, "Semgrep document")
    findings: list[FindingInput] = []
    for item in sequence_value(root.get("results")):
        result = mapping_value(item)
        extra = mapping_value(result.get("extra"))
        metadata = mapping_value(extra.get("metadata"))
        start = mapping_value(result.get("start"))
        end = mapping_value(result.get("end"))
        location = source_location(
            context,
            path=result.get("path"),
            start_line=start.get("line"),
            end_line=end.get("line"),
        )
        rule_id = bounded_text(result.get("check_id"), 500)
        findings.append(
            FindingInput(
                external_id=bounded_text(
                    extra.get("fingerprint") or result.get("fingerprint") or rule_id,
                    500,
                ),
                fingerprint_hint=bounded_text(
                    extra.get("fingerprint") or result.get("fingerprint"), 1000
                ),
                title=bounded_text(
                    extra.get("message") or rule_id or "Semgrep finding", 1000
                ),
                description=bounded_text(extra.get("lines"), 20_000),
                rule_id=rule_id,
                category=bounded_text(
                    metadata.get("category") or metadata.get("technology"), 300
                ),
                severity=normalize_severity(
                    metadata.get("impact") or extra.get("severity") or "medium"
                ),
                confidence=bounded_text(metadata.get("confidence"), 50),
                location=location,
                scanner_url=bounded_text(
                    metadata.get("source") or metadata.get("reference"), 2000
                ),
                remediation=bounded_text(extra.get("fix"), 20_000),
                cwes=extract_identifiers(metadata.get("cwe"), "CWE"),
                cves=extract_identifiers(metadata.get("cve"), "CVE"),
                cvss_score=float_or_none(metadata.get("cvss"), maximum=10),
                exploit_available=boolean_value(metadata.get("exploit")),
                raw_data=json_safe_mapping(result),
            )
        )
    return {
        "tool_name": "Semgrep",
        "tool_key": "semgrep",
        "tool_type": "sast",
        "findings": findings,
    }


def parse_sonarqube(document: Any, context: Mapping[str, Any]) -> dict[str, Any]:
    root = required_mapping(document, "SonarQube document")
    findings: list[FindingInput] = []
    for item in sequence_value(root.get("issues")):
        issue = mapping_value(item)
        text_range = mapping_value(issue.get("textRange"))
        component = bounded_text(issue.get("component"), 2000)
        path = component.split(":", 1)[-1] if ":" in component else component
        rule_id = bounded_text(issue.get("rule"), 500)
        findings.append(
            FindingInput(
                external_id=bounded_text(issue.get("key") or rule_id, 500),
                fingerprint_hint=bounded_text(issue.get("hash"), 1000),
                title=bounded_text(
                    issue.get("message") or rule_id or "SonarQube issue", 1000
                ),
                description=bounded_text(issue.get("message"), 20_000),
                rule_id=rule_id,
                category=bounded_text(
                    issue.get("type") or issue.get("cleanCodeAttributeCategory"), 300
                ),
                severity=normalize_severity(issue.get("severity") or "medium"),
                location=source_location(
                    context,
                    project=issue.get("project"),
                    path=path,
                    start_line=text_range.get("startLine") or issue.get("line"),
                    end_line=text_range.get("endLine"),
                ),
                scanner_url=bounded_text(issue.get("url"), 2000),
                remediation=bounded_text(issue.get("effort"), 20_000),
                cwes=extract_identifiers(issue.get("tags"), "CWE"),
                first_seen=utc_datetime(issue.get("creationDate")),
                last_seen=utc_datetime(issue.get("updateDate")),
                raw_data=json_safe_mapping(issue),
            )
        )
    return {
        "tool_name": "SonarQube",
        "tool_key": "sonarqube",
        "tool_type": "sast",
        "findings": findings,
    }


def parse_generic(document: Any, context: Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(document, Mapping):
        root = document
        items = sequence_value(root.get("findings"))
        document_tool = mapping_value(root.get("tool"))
    elif isinstance(document, list):
        items = document
        document_tool = {}
    else:
        raise ValueError(
            "Generic findings must be an array or an object with findings."
        )
    findings: list[FindingInput] = []
    for item in items:
        finding = mapping_value(item)
        location_data = {
            **context,
            **finding,
            **mapping_value(finding.get("source")),
            **mapping_value(finding.get("location")),
        }
        location = SourceLocation.from_mapping(location_data)
        title = bounded_text(
            finding.get("title") or finding.get("message") or finding.get("name"),
            1000,
        )
        if not title:
            raise ValueError("Every generic finding requires a title or message.")
        identifiers = mapping_value(finding.get("identifiers"))
        findings.append(
            FindingInput(
                external_id=bounded_text(
                    finding.get("external_id")
                    or finding.get("externalId")
                    or finding.get("id"),
                    500,
                ),
                fingerprint_hint=bounded_text(finding.get("fingerprint"), 1000),
                title=title,
                description=bounded_text(finding.get("description"), 20_000),
                rule_id=bounded_text(
                    finding.get("rule_id")
                    or finding.get("ruleId")
                    or finding.get("rule"),
                    500,
                ),
                category=bounded_text(
                    finding.get("category") or finding.get("type"), 300
                ),
                severity=normalize_severity(finding.get("severity") or "medium"),
                status=normalize_status(finding.get("status") or "open"),
                confidence=bounded_text(finding.get("confidence"), 50),
                location=location,
                scanner_url=bounded_text(
                    finding.get("url") or finding.get("scanner_url"), 2000
                ),
                remediation=bounded_text(
                    finding.get("remediation") or finding.get("fix"), 20_000
                ),
                cwes=extract_identifiers(
                    finding.get("cwe") or finding.get("cwes") or identifiers.get("cwe"),
                    "CWE",
                ),
                cves=extract_identifiers(
                    finding.get("cve") or finding.get("cves") or identifiers.get("cve"),
                    "CVE",
                ),
                package_name=bounded_text(
                    finding.get("package_name") or finding.get("packageName"), 500
                ),
                package_version=bounded_text(
                    finding.get("package_version") or finding.get("packageVersion"), 200
                ),
                fixed_version=bounded_text(
                    finding.get("fixed_version") or finding.get("fixedVersion"), 200
                ),
                cvss_score=float_or_none(
                    finding.get("cvss_score") or finding.get("cvssScore"), maximum=10
                ),
                epss_score=float_or_none(
                    finding.get("epss_score") or finding.get("epssScore")
                ),
                exploit_available=boolean_value(
                    finding.get("exploit_available") or finding.get("exploitAvailable")
                ),
                first_seen=utc_datetime(
                    finding.get("first_seen") or finding.get("firstSeen")
                ),
                last_seen=utc_datetime(
                    finding.get("last_seen") or finding.get("lastSeen")
                ),
                raw_data=json_safe_mapping(finding),
            )
        )
    tool_name = bounded_text(document_tool.get("name"), 200) or "Generic scanner"
    return {
        "tool_name": tool_name,
        "tool_key": clean_identity(document_tool.get("key") or tool_name),
        "tool_type": clean_identity(document_tool.get("type") or "other"),
        "findings": findings,
    }


def parse_scanned_targets(
    value: Any, context: Mapping[str, Any]
) -> tuple[SourceLocation, ...]:
    targets = []
    for item in sequence_value(value):
        targets.append(SourceLocation.from_mapping({**context, **mapping_value(item)}))
    return tuple(target for target in targets if target.repository)


def sarif_location(
    result: Mapping[str, Any], context: Mapping[str, Any]
) -> SourceLocation:
    location = mapping_value(next(iter(sequence_value(result.get("locations"))), {}))
    physical = mapping_value(location.get("physicalLocation"))
    artifact = mapping_value(physical.get("artifactLocation"))
    region = mapping_value(physical.get("region"))
    uri = bounded_text(artifact.get("uri"), 2000)
    parsed = urlparse(uri)
    path = unquote(parsed.path.lstrip("/")) if parsed.scheme else unquote(uri)
    return source_location(
        context,
        path=path,
        start_line=region.get("startLine"),
        end_line=region.get("endLine"),
    )


def sarif_source_context(run: Mapping[str, Any]) -> dict[str, Any]:
    provenance = mapping_value(
        next(iter(sequence_value(run.get("versionControlProvenance"))), {})
    )
    repository_uri = bounded_text(provenance.get("repositoryUri"), 2000)
    branch = bounded_text(provenance.get("branch"), 500).removeprefix("refs/heads/")
    if not repository_uri:
        return {"branch": branch} if branch else {}
    parsed = urlparse(repository_uri)
    host = parsed.hostname or ""
    parts = [unquote(item) for item in parsed.path.strip("/").split("/") if item]
    if host.lower() in {"github.com", "www.github.com"} and len(parts) >= 2:
        return {
            "provider": "github-enterprise",
            "organization": parts[0],
            "repository": parts[1].removesuffix(".git"),
            "branch": branch,
        }
    if host.lower() == "dev.azure.com" and "_git" in parts:
        git_index = parts.index("_git")
        if git_index >= 2 and len(parts) > git_index + 1:
            return {
                "provider": "azure-devops",
                "organization": parts[0],
                "project": parts[1],
                "repository": parts[git_index + 1].removesuffix(".git"),
                "branch": branch,
            }
    return {"branch": branch} if branch else {}


def source_location(
    context: Mapping[str, Any],
    path: Any = "",
    project: Any = "",
    start_line: Any = None,
    end_line: Any = None,
) -> SourceLocation:
    return SourceLocation.from_mapping(
        {
            **context,
            "project": project or context.get("project"),
            "path": path,
            "start_line": start_line,
            "end_line": end_line,
        }
    )


def sarif_severity(result: Mapping[str, Any], properties: Mapping[str, Any]) -> str:
    score = float_or_none(
        properties.get("security-severity") or properties.get("cvss"), maximum=10
    )
    if score is not None:
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        if score > 0:
            return "low"
        return "info"
    return normalize_severity(result.get("level") or properties.get("severity"))


def extract_identifiers(value: Any, prefix: str) -> tuple[str, ...]:
    items = string_tuple(value)
    expression = (
        r"\bCVE[-_: ]?\d{4}[-_: ]\d+\b"
        if prefix.upper() == "CVE"
        else rf"\b{re.escape(prefix)}[-_: ]?\d+\b"
    )
    pattern = re.compile(expression, re.IGNORECASE)
    matches = {
        match.group(0).upper().replace("_", "-").replace(":", "-").replace(" ", "-")
        for item in items
        for match in pattern.finditer(item)
    }
    return tuple(sorted(matches))


def first_security_tag(tags: tuple[str, ...]) -> str:
    for tag in tags:
        if not re.search(r"(?i)\b(?:CWE|CVE)[-_: ]?\d+\b", tag):
            return tag
    return ""


def first_mapping_value(value: Mapping[str, Any]) -> str:
    for item in value.values():
        text = bounded_text(item, 1000)
        if text:
            return text
    return ""


def message_text(value: Any) -> str:
    if isinstance(value, Mapping):
        return bounded_text(value.get("text") or value.get("markdown"), 20_000)
    return bounded_text(value, 20_000)


def boolean_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return clean_identity(value) in {"1", "true", "yes", "available", "known"}


def mapping_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def required_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a JSON object.")
    return dict(value)


def sequence_value(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []
