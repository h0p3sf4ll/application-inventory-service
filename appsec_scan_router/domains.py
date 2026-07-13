from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlparse, urlunparse

from .models import WebDomainEvidence
from .utils import clean_value, is_domain_config_path, load_json_object


NETWORKED_INVENTORY_TYPES = frozenset({"web_app", "api_service", "microservice", "serverless"})
WEB_DOMAIN_CONFIDENCE_RANK = {"inferred": 1, "configured": 2, "confirmed": 3}
URL_RE = re.compile(r"https?://[^\s\"'<>\]\[{}]+", re.IGNORECASE)
HOST_RE = re.compile(
    r"(?<![@A-Za-z0-9_.-])(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?::\d{1,5})?"
)
ASSIGNMENT_RE = re.compile(
    r"^\s*(?:-\s*)?[\"']?(?P<key>[A-Za-z0-9_.-]+)[\"']?\s*[:=]\s*(?P<value>.*?)\s*[,;]?\s*$"
)
SERVER_NAME_RE = re.compile(r"^\s*server_name\s+(?P<value>[^;]+);?\s*$", re.IGNORECASE)
AZURE_APP_NAME_RE = re.compile(
    r"(?im)^\s*(?:-\s*)?(?:appName|webAppName|azureWebAppName|functionAppName)\s*:\s*[\"']?([A-Za-z0-9][A-Za-z0-9-]{1,58}[A-Za-z0-9])[\"']?\s*$"
)
FLY_APP_NAME_RE = re.compile(r"(?im)^\s*app\s*=\s*[\"']([a-z0-9][a-z0-9-]{1,61}[a-z0-9])[\"']\s*$")
SEMANTIC_KEY_SUFFIXES = (
    "baseurl",
    "domain",
    "domainname",
    "domains",
    "endpoint",
    "environmenturl",
    "homepage",
    "host",
    "hostname",
    "hosts",
    "origin",
    "siteurl",
    "url",
    "urls",
)
EXCLUDED_KEY_TOKENS = frozenset(
    {
        "artifact",
        "auth",
        "broker",
        "database",
        "db",
        "docs",
        "documentation",
        "image",
        "issuer",
        "jdbc",
        "jwks",
        "kafka",
        "license",
        "oauth",
        "redis",
        "registry",
        "repository",
        "schema",
        "smtp",
        "support",
        "token",
    }
)
RESERVED_SUFFIXES = (
    ".example",
    ".invalid",
    ".local",
    ".localhost",
    ".test",
)
RESERVED_DOMAINS = frozenset(
    {
        "example.com",
        "example.net",
        "example.org",
        "localhost",
    }
)
NON_APPLICATION_HOSTS = frozenset(
    {
        "accounts.google.com",
        "api.github.com",
        "apps.apple.com",
        "dev.azure.com",
        "docker.io",
        "docs.github.com",
        "github.com",
        "login.microsoftonline.com",
        "management.azure.com",
        "npmjs.com",
        "npmjs.org",
        "play.google.com",
        "pypi.org",
        "schema.org",
        "schemas.microsoft.com",
        "www.w3.org",
    }
)
NON_APPLICATION_SUFFIXES = (
    ".docker.io",
    ".github.com",
    ".githubusercontent.com",
    ".googleapis.com",
    ".npmjs.org",
    ".pypi.org",
)


def discover_web_domains(
    contents: Mapping[str, str],
    repository: Mapping[str, Any] | None = None,
    deployment_endpoints: Iterable[Mapping[str, Any]] = (),
) -> tuple[WebDomainEvidence, ...]:
    candidates: list[tuple[str, str, str, str]] = []
    repository_data = repository or {}
    homepage = clean_value(repository_data.get("homepageUrl"))
    if homepage:
        candidates.append((homepage, "repository:homepage", "configured", ""))
    pages_url = clean_value(repository_data.get("pagesUrl"))
    if pages_url:
        candidates.append((pages_url, "repository:github_pages", "inferred", "production"))
    for endpoint in deployment_endpoints:
        value = clean_value(endpoint.get("url"))
        if not value:
            continue
        candidates.append(
            (
                value,
                clean_value(endpoint.get("source")) or "provider:deployment",
                normalized_confidence(endpoint.get("confidence")),
                clean_value(endpoint.get("environment")),
            )
        )
    for path, content in contents.items():
        candidates.extend(source_domain_candidates(path, content))
    return merge_domain_candidates(candidates)


def source_domain_candidates(path: str, content: str) -> list[tuple[str, str, str, str]]:
    normalized_path = path.replace("\\", "/")
    filename = normalized_path.rsplit("/", 1)[-1].lower()
    source = f"source:{normalized_path}"
    if filename == "package.json":
        homepage = clean_value(load_json_object(content).get("homepage"))
        return [(homepage, f"{source}:homepage", "configured", "")] if homepage else []
    if filename == "cname":
        values = candidate_values(next((line.strip() for line in content.splitlines() if line.strip()), ""))
        return [(value, f"{source}:cname", "configured", "") for value in values]
    if not is_domain_config_path(normalized_path):
        return []
    candidates = structured_content_candidates(content, source)
    candidates.extend(text_content_candidates(content, source))
    if filename == "caddyfile":
        candidates.extend(caddy_content_candidates(content, source))
    candidates.extend(inferred_cloud_candidates(filename, content, source))
    return candidates


def structured_content_candidates(content: str, source: str) -> list[tuple[str, str, str, str]]:
    data = load_json_object(content)
    if not data:
        return []
    candidates: list[tuple[str, str, str, str]] = []

    def walk(value: Any, path: tuple[str, ...]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, (*path, str(key)))
            return
        if isinstance(value, list):
            for child in value:
                walk(child, path)
            return
        if isinstance(value, str) and path and is_domain_key(path):
            for candidate in candidate_values(value):
                candidates.append((candidate, f"{source}:{'.'.join(path)}", "configured", ""))

    walk(data, ())
    return candidates


def text_content_candidates(content: str, source: str) -> list[tuple[str, str, str, str]]:
    candidates: list[tuple[str, str, str, str]] = []
    active_key = ""
    active_indent = -1
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        server_name = SERVER_NAME_RE.match(line)
        if server_name:
            for candidate in candidate_values(server_name.group("value")):
                candidates.append((candidate, f"{source}:server_name:{line_number}", "configured", ""))
            continue
        assignment = ASSIGNMENT_RE.match(line)
        if assignment:
            key = assignment.group("key")
            value = assignment.group("value").strip()
            indent = len(line) - len(line.lstrip())
            if is_domain_key((key,)):
                active_key = key
                active_indent = indent
                for candidate in candidate_values(value):
                    candidates.append((candidate, f"{source}:{key}:{line_number}", "configured", ""))
            elif indent <= active_indent:
                active_key = ""
                active_indent = -1
            continue
        indent = len(line) - len(line.lstrip())
        if active_key and indent > active_indent and stripped.startswith("-"):
            for candidate in candidate_values(stripped[1:]):
                candidates.append((candidate, f"{source}:{active_key}:{line_number}", "configured", ""))
    return candidates


def caddy_content_candidates(content: str, source: str) -> list[tuple[str, str, str, str]]:
    candidates: list[tuple[str, str, str, str]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        if "{" not in line:
            continue
        site_value = line.split("{", 1)[0].strip()
        if not site_value or site_value.startswith(("#", ":")):
            continue
        for candidate in candidate_values(site_value):
            candidates.append((candidate, f"{source}:site:{line_number}", "configured", ""))
    return candidates


def inferred_cloud_candidates(filename: str, content: str, source: str) -> list[tuple[str, str, str, str]]:
    candidates: list[tuple[str, str, str, str]] = []
    if filename.startswith(("azure-pipeline", "azure-pipelines")) or ".github/workflows/" in source.lower():
        for name in AZURE_APP_NAME_RE.findall(content):
            candidates.append((f"https://{name.lower()}.azurewebsites.net", f"{source}:azure_app_name", "inferred", ""))
    if filename == "fly.toml":
        match = FLY_APP_NAME_RE.search(content)
        if match:
            candidates.append((f"https://{match.group(1)}.fly.dev", f"{source}:fly_app", "inferred", ""))
    if filename == ".firebaserc":
        data = load_json_object(content)
        projects = data.get("projects") if isinstance(data.get("projects"), dict) else {}
        project_id = clean_value(projects.get("default"))
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{4,28}[a-z0-9]", project_id):
            candidates.append((f"https://{project_id}.web.app", f"{source}:firebase_project", "inferred", "production"))
    return candidates


def candidate_values(value: str) -> list[str]:
    text = clean_value(value)
    if not text:
        return []
    candidates = URL_RE.findall(text)
    remainder = URL_RE.sub(" ", text)
    candidates.extend(match.group(0) for match in HOST_RE.finditer(remainder))
    return list(dict.fromkeys(candidates))


def is_domain_key(path: Iterable[str]) -> bool:
    normalized_parts = [re.sub(r"[^a-z0-9]+", "", part.lower()) for part in path]
    combined = "".join(normalized_parts)
    if any(token in combined for token in EXCLUDED_KEY_TOKENS):
        return False
    return bool(normalized_parts and normalized_parts[-1].endswith(SEMANTIC_KEY_SUFFIXES))


def merge_domain_candidates(candidates: Iterable[tuple[str, str, str, str]]) -> tuple[WebDomainEvidence, ...]:
    merged: dict[str, dict[str, Any]] = {}
    for value, source, confidence, environment in candidates:
        normalized = normalize_web_endpoint(value, confidence)
        if normalized is None:
            continue
        domain, url, normalized_level = normalized
        current = merged.get(domain)
        if current is None:
            merged[domain] = {
                "domain": domain,
                "url": url,
                "confidence": normalized_level,
                "sources": {source},
                "environment": environment,
            }
            continue
        current["sources"].add(source)
        if candidate_priority(normalized_level, environment, url) > candidate_priority(
            current["confidence"], current["environment"], current["url"]
        ):
            current["url"] = url
            current["confidence"] = normalized_level
            current["environment"] = environment
    ordered = sorted(
        merged.values(),
        key=lambda item: (
            -WEB_DOMAIN_CONFIDENCE_RANK[item["confidence"]],
            -environment_rank(item["environment"]),
            item["domain"],
        ),
    )
    return tuple(
        WebDomainEvidence(
            domain=item["domain"],
            url=item["url"],
            confidence=item["confidence"],
            sources=tuple(sorted(item["sources"])),
            environment=item["environment"],
        )
        for item in ordered
    )


def normalize_web_endpoint(value: Any, confidence: str = "configured") -> tuple[str, str, str] | None:
    raw = clean_value(value).strip().rstrip(".,;)")
    if not raw or any(marker in raw for marker in ("{{", "}}", "${", "$(", "<", ">")):
        return None
    wildcard = raw.startswith("*.")
    if wildcard:
        raw = raw[2:]
    candidate = raw if re.match(r"^https?://", raw, re.IGNORECASE) else f"https://{raw.lstrip('/')}"
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
        return None
    host = normalize_hostname(parsed.hostname)
    if not host or excluded_hostname(host):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = host
    if port and not (parsed.scheme.lower() == "http" and port == 80) and not (parsed.scheme.lower() == "https" and port == 443):
        netloc = f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "").rstrip("/")
    url = urlunparse((parsed.scheme.lower(), netloc, path, "", "", ""))
    level = normalized_confidence(confidence)
    if wildcard and level != "inferred":
        level = "inferred"
    return host, url, level


def normalize_hostname(value: Any) -> str:
    hostname = clean_value(value).lower().rstrip(".")
    if not hostname or "." not in hostname:
        return ""
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(hostname) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in hostname.split(".")):
        return ""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    return ""


def excluded_hostname(hostname: str) -> bool:
    if hostname in RESERVED_DOMAINS or hostname.endswith(RESERVED_SUFFIXES):
        return True
    if hostname in NON_APPLICATION_HOSTS or hostname.endswith(NON_APPLICATION_SUFFIXES):
        return True
    labels = set(hostname.split("."))
    return bool(labels & {"changeme", "placeholder", "yourdomain"})


def normalized_confidence(value: Any) -> str:
    normalized = clean_value(value).lower()
    return normalized if normalized in WEB_DOMAIN_CONFIDENCE_RANK else "configured"


def candidate_priority(confidence: str, environment: str, url: str) -> tuple[int, int, int, int]:
    return (
        WEB_DOMAIN_CONFIDENCE_RANK[confidence],
        environment_rank(environment),
        int(url.startswith("https://")),
        -len(url),
    )


def environment_rank(environment: str) -> int:
    normalized = re.sub(r"[^a-z0-9]+", "", clean_value(environment).lower())
    if normalized in {"production", "prod"}:
        return 3
    if normalized in {"preproduction", "preprod", "staging", "stage"}:
        return 2
    return 1 if normalized else 0


def web_domain_columns(evidence: Iterable[WebDomainEvidence]) -> dict[str, str]:
    entries = tuple(evidence)
    primary = entries[0] if entries else None
    return {
        "primary_web_domain": primary.domain if primary else "",
        "web_domains": "; ".join(item.domain for item in entries),
        "web_urls": "; ".join(item.url for item in entries if item.url),
        "web_domain_status": primary.confidence if primary else "not_detected",
        "web_domain_sources": "; ".join(
            f"{item.domain} [{', '.join(item.sources)}]" for item in entries
        ),
        "web_domain_evidence": json.dumps([item.as_dict() for item in entries], sort_keys=True),
    }
