from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .constants import (
    DEFAULT_BRANCH_AGE_DAYS,
    DEFAULT_BRANCH_WORKERS,
    DEFAULT_CONTENT_WORKERS,
    DEFAULT_MAX_WORKERS,
    DEFAULT_OUT_PREFIX,
    DEFAULT_POSTGRES_DATABASE,
    DEFAULT_POSTGRES_HOST,
    DEFAULT_POSTGRES_PASSWORD,
    DEFAULT_POSTGRES_PORT,
    DEFAULT_POSTGRES_SCHEMA,
    DEFAULT_POSTGRES_TABLE,
    DEFAULT_POSTGRES_USER,
    DEFAULT_SOURCE_WORKERS,
    DEFAULT_STORE_COUNTRY,
    DEFAULT_STORE_TIMEOUT_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
)
from .github import (
    GitHubAppCredentials,
    configured_github_api_url,
    configured_github_app_id,
    configured_github_installation_id,
    configured_github_owners,
    parse_github_urls,
)
from .org_tokens import ado_org_pats_to_json, parse_ado_org_pat_values
from .scanner import normalize_application_types, normalize_store_countries, store_lookup_allowed
from .target_filters import parse_source_target_filter_values, target_filter_value


SAFE_CHILD_ENV_KEYS = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


def normalize_scan_config(config: dict[str, Any]) -> dict[str, Any]:
    provider = clean_choice(config.get("provider"), {"azure-devops", "github-enterprise", "mixed"}, "azure-devops")
    legacy_org = clean_text(config.get("org"))
    github_urls = parse_github_urls(
        config.get("githubUrls"),
        default=legacy_org if provider in {"github-enterprise", "mixed"} else "",
    )
    if provider in {"github-enterprise", "mixed"} and not github_urls:
        github_urls = configured_github_owners()
    if provider in {"github-enterprise", "mixed"} and not github_urls:
        raise ValueError("Configure at least one GitHub organization in the UI or APPLICATION_INVENTORY_GITHUB_URLS.")

    org = github_urls[0] if provider in {"github-enterprise", "mixed"} else legacy_org
    ado_org_pats = parse_ado_org_pat_values([config.get("adoOrgPats")])
    target_filters = parse_source_target_filter_values([config.get("targetFilters")])
    if provider in {"github-enterprise", "mixed"} and not target_filters:
        target_filters = parse_source_target_filter_values(
            [env_value("APPLICATION_INVENTORY_GITHUB_REPOSITORIES", "APPSEC_INVENTORY_GITHUB_REPOSITORIES")]
        )
    if provider == "azure-devops" and not ado_org_pats:
        raise ValueError("Add at least one Azure organization and PAT.")
    if provider == "mixed" and not ado_org_pats:
        raise ValueError("Add at least one Azure organization and PAT for a mixed scan.")

    base_url = configured_github_api_url()
    if provider in {"github-enterprise", "mixed"} and not base_url:
        raise ValueError("GitHub Enterprise API URL is required.")
    github_app_id = configured_github_app_id() if provider in {"github-enterprise", "mixed"} else ""
    github_app_installation_id = (
        configured_github_installation_id() if provider in {"github-enterprise", "mixed"} else ""
    )
    github_app_private_key = clean_text(config.get("githubAppPrivateKey"))
    github_app_private_key_file = clean_text(config.get("githubAppPrivateKeyFile"))
    validate_github_app_config(
        provider,
        github_app_id,
        github_app_installation_id,
        github_app_private_key,
        github_app_private_key_file,
    )

    application_types = list(normalize_ui_application_types(config.get("applicationTypes")))
    database_config = normalize_database_config(config)
    store_countries = normalize_store_countries(
        config.get("storeCountries") or config.get("storeCountry") or DEFAULT_STORE_COUNTRY
    )
    normalized = {
        "provider": provider,
        "org": org,
        "orgDisplay": provider_summary(provider, github_urls, ado_org_pats, org),
        "githubUrls": list(github_urls),
        "adoOrgPats": [{"org": item.org, "pat": item.pat} for item in ado_org_pats],
        "targetFilters": [{"org": item.org, "project": item.project} for item in target_filters],
        "project": clean_text(config.get("project")),
        "repo": clean_text(config.get("repo")),
        "baseUrl": base_url,
        "token": clean_text(config.get("token")),
        "githubAppId": github_app_id,
        "githubAppInstallationId": github_app_installation_id,
        "githubAppPrivateKey": github_app_private_key,
        "githubAppPrivateKeyFile": github_app_private_key_file,
        "outPrefix": DEFAULT_OUT_PREFIX,
        "applicationTypes": application_types,
        "ownerUserId": clean_text(config.get("ownerUserId")) or "anonymous",
        "ownerUserLogin": clean_text(config.get("ownerUserLogin")) or "anonymous",
        "saveToken": bool(config.get("saveToken")),
        **database_config,
        "minConfidence": clean_choice(config.get("minConfidence"), {"low", "medium", "high"}, "low"),
        "activityMode": clean_choice(config.get("activityMode"), {"contributors", "latest"}, "contributors"),
        "maxWorkers": positive_int(config.get("maxWorkers"), DEFAULT_MAX_WORKERS),
        "sourceWorkers": positive_int(config.get("sourceWorkers"), DEFAULT_SOURCE_WORKERS),
        "branchWorkers": positive_int(config.get("branchWorkers"), DEFAULT_BRANCH_WORKERS),
        "contentWorkers": positive_int(config.get("contentWorkers"), DEFAULT_CONTENT_WORKERS),
        "maxCommitsPerRepo": nonnegative_int(config.get("maxCommitsPerRepo"), 0),
        "timeout": positive_int(config.get("timeout"), DEFAULT_TIMEOUT_SECONDS),
        "branchAgeDays": positive_int(config.get("branchAgeDays"), DEFAULT_BRANCH_AGE_DAYS),
        "storeLookup": bool(config.get("storeLookup")) and store_lookup_allowed(application_types),
        "storeCountry": store_countries[0],
        "storeCountries": list(store_countries),
        "storeTimeout": positive_int(config.get("storeTimeout"), DEFAULT_STORE_TIMEOUT_SECONDS),
        "verbose": bool(config.get("verbose")),
    }
    if normalized["project"] and normalized["repo"] and normalized["project"] != normalized["repo"]:
        raise ValueError("Project and repository cannot be different values.")
    return normalized


def validate_github_app_config(
    provider: str,
    app_id: str,
    installation_id: str,
    private_key: str,
    private_key_file: str,
) -> None:
    if provider not in {"github-enterprise", "mixed"}:
        return
    private_key_names = (
        "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY",
        "APPSEC_INVENTORY_GITHUB_APP_PRIVATE_KEY",
        "GITHUB_APP_PRIVATE_KEY",
        "GHE_APP_PRIVATE_KEY",
        "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE",
        "APPSEC_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE",
        "GITHUB_APP_PRIVATE_KEY_FILE",
        "GHE_APP_PRIVATE_KEY_FILE",
    )
    if not any((private_key, private_key_file, *(env_value(name) for name in private_key_names))):
        return
    try:
        GitHubAppCredentials.from_values(app_id, installation_id, private_key, private_key_file)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


def provider_summary(provider: str, github_urls: tuple[str, ...], org_pats: tuple[Any, ...], org: str) -> str:
    if provider == "mixed":
        return mixed_org_summary(", ".join(github_urls), org_pats)
    if provider == "github-enterprise":
        return ", ".join(github_urls)
    return ado_org_summary(org_pats) if org_pats else org


def normalize_database_config(config: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "postgresEnabled": bool(config.get("postgresEnabled", True)),
        "postgresDsn": clean_text(
            config.get("postgresDsn")
            or env_value("APPLICATION_INVENTORY_POSTGRES_DSN", "APPSEC_INVENTORY_POSTGRES_DSN")
        ),
        "postgresHost": clean_text(
            config.get("postgresHost")
            or env_value("APPLICATION_INVENTORY_POSTGRES_HOST", "APPSEC_INVENTORY_POSTGRES_HOST")
            or DEFAULT_POSTGRES_HOST
        ),
        "postgresPort": positive_int(config.get("postgresPort"), DEFAULT_POSTGRES_PORT),
        "postgresDatabase": clean_text(config.get("postgresDatabase") or DEFAULT_POSTGRES_DATABASE),
        "postgresUser": clean_text(config.get("postgresUser") or DEFAULT_POSTGRES_USER),
        "postgresPassword": clean_text(
            config.get("postgresPassword")
            or env_value("APPLICATION_INVENTORY_POSTGRES_PASSWORD", "APPSEC_INVENTORY_POSTGRES_PASSWORD")
            or DEFAULT_POSTGRES_PASSWORD
        ),
        "postgresSchema": clean_text(
            config.get("postgresSchema")
            or env_value("APPLICATION_INVENTORY_POSTGRES_SCHEMA", "APPSEC_INVENTORY_POSTGRES_SCHEMA")
            or DEFAULT_POSTGRES_SCHEMA
        ),
        "postgresTable": clean_text(config.get("postgresTable") or DEFAULT_POSTGRES_TABLE),
    }
    if not normalized["postgresDsn"]:
        normalized["postgresDsn"] = postgres_dsn_from_config(normalized)
    return normalized


def build_scan_command(config: dict[str, Any], reports_dir: Path) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "application_inventory_service",
        "--provider",
        config["provider"],
        "--out-dir",
        str(reports_dir),
        "--out-prefix",
        config["outPrefix"],
        "--min-confidence",
        config["minConfidence"],
        "--activity-mode",
        config["activityMode"],
        "--max-workers",
        str(config["maxWorkers"]),
        "--source-workers",
        str(config["sourceWorkers"]),
        "--branch-workers",
        str(config["branchWorkers"]),
        "--content-workers",
        str(config["contentWorkers"]),
        "--max-commits-per-repo",
        str(config["maxCommitsPerRepo"]),
        "--timeout",
        str(config["timeout"]),
        "--branch-age-days",
        str(config["branchAgeDays"]),
        "--owner-user-id",
        config["ownerUserId"],
        "--owner-user-login",
        config["ownerUserLogin"],
        "--store-timeout",
        str(config["storeTimeout"]),
    ]
    for country in config.get("storeCountries", [config["storeCountry"]]):
        command.extend(["--store-country", country])
    for application_type in config["applicationTypes"]:
        command.extend(["--application-type", application_type])
    if config["postgresEnabled"]:
        command.extend(["--postgres-schema", config["postgresSchema"]])
        command.extend(["--postgres-table", config["postgresTable"]])
    target_filters = config.get("targetFilters") if isinstance(config.get("targetFilters"), list) else []
    for target_filter in target_filters:
        value = target_filter_value(target_filter)
        if value:
            command.extend(["--target-filter", value])
    if config["provider"] in {"github-enterprise", "mixed"}:
        command.extend(["--base-url", config["baseUrl"]])
        for github_url in config.get("githubUrls", []):
            command.extend(["--github-url", github_url])
    if config["provider"] == "azure-devops":
        if not config.get("adoOrgPats"):
            command.extend(["--org", config["org"]])
        if config["project"] and not target_filters:
            command.extend(["--project", config["project"]])
    if config["storeLookup"]:
        command.append("--store-lookup")
    if config["verbose"]:
        command.append("--verbose")
    return command


def redact_command(command: tuple[str, ...] | list[str]) -> list[str]:
    secret_options = {"--pat", "--postgres-dsn", "--ado-org-pat"}
    redacted: list[str] = []
    redact_next = False
    for part in command:
        if redact_next:
            redacted.append("[redacted]")
            redact_next = False
            continue
        redacted.append(part)
        redact_next = part in secret_options
    return redacted


def scan_environment(config: dict[str, Any]) -> dict[str, str]:
    env = base_process_environment()
    env["PYTHONUNBUFFERED"] = "1"
    token = clean_text(config.get("token"))
    ado_org_pats = config.get("adoOrgPats") if isinstance(config.get("adoOrgPats"), list) else []
    provider = config.get("provider")
    if provider in {"azure-devops", "mixed"} and ado_org_pats:
        org_pats_json = ado_org_pats_to_json(ado_org_pats)
        env["APPLICATION_INVENTORY_ADO_ORG_PATS"] = org_pats_json
        env["APPSEC_INVENTORY_ADO_ORG_PATS"] = org_pats_json
        env.pop("ADO_PAT", None)
    elif provider == "azure-devops":
        if token:
            env["ADO_PAT"] = token
        else:
            inherit_secret(env, "ADO_PAT")
    if provider in {"github-enterprise", "mixed"}:
        if token:
            env["GITHUB_TOKEN"] = token
        else:
            inherit_secret(env, "GITHUB_TOKEN")
            inherit_secret(env, "GHE_TOKEN")
            set_github_app_environment(env, config)
    set_postgres_environment(env, config)
    set_scan_context_environment(env, config)
    return env


def set_postgres_environment(env: dict[str, str], config: dict[str, Any]) -> None:
    names = (
        "APPLICATION_INVENTORY_POSTGRES_DSN",
        "APPLICATION_INVENTORY_POSTGRES_SCHEMA",
        "APPLICATION_INVENTORY_POSTGRES_TABLE",
        "APPSEC_INVENTORY_POSTGRES_DSN",
        "APPSEC_INVENTORY_POSTGRES_SCHEMA",
        "APPSEC_INVENTORY_POSTGRES_TABLE",
    )
    postgres_dsn = clean_text(config.get("postgresDsn"))
    if not config.get("postgresEnabled") or not postgres_dsn:
        for name in names:
            env.pop(name, None)
        return
    postgres_schema = clean_text(config.get("postgresSchema") or DEFAULT_POSTGRES_SCHEMA)
    postgres_table = clean_text(config.get("postgresTable") or DEFAULT_POSTGRES_TABLE)
    values = (postgres_dsn, postgres_schema, postgres_table, postgres_dsn, postgres_schema, postgres_table)
    env.update(zip(names, values, strict=True))


def set_scan_context_environment(env: dict[str, str], config: dict[str, Any]) -> None:
    owner_user_id = clean_text(config.get("ownerUserId") or "anonymous")
    owner_user_login = clean_text(config.get("ownerUserLogin") or "anonymous")
    scan_id = clean_text(config.get("scanId"))
    provider = clean_text(config.get("provider"))
    if scan_id:
        env["APPLICATION_INVENTORY_SCAN_ID"] = scan_id
    if provider:
        env["APPLICATION_INVENTORY_PROVIDER"] = provider
    env["APPLICATION_INVENTORY_OWNER_USER_ID"] = owner_user_id
    env["APPLICATION_INVENTORY_OWNER_USER_LOGIN"] = owner_user_login
    env["APPSEC_INVENTORY_OWNER_USER_ID"] = owner_user_id
    env["APPSEC_INVENTORY_OWNER_USER_LOGIN"] = owner_user_login


def set_github_app_environment(env: dict[str, str], config: dict[str, Any]) -> None:
    aliases = {
        "APPLICATION_INVENTORY_GITHUB_APP_ID": (
            "APPLICATION_INVENTORY_GITHUB_APP_ID",
            "APPSEC_INVENTORY_GITHUB_APP_ID",
            "GITHUB_APP_ID",
            "GHE_APP_ID",
        ),
        "APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID": (
            "APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID",
            "APPSEC_INVENTORY_GITHUB_APP_INSTALLATION_ID",
            "GITHUB_APP_INSTALLATION_ID",
            "GHE_APP_INSTALLATION_ID",
        ),
        "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY": (
            "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY",
            "APPSEC_INVENTORY_GITHUB_APP_PRIVATE_KEY",
            "GITHUB_APP_PRIVATE_KEY",
            "GHE_APP_PRIVATE_KEY",
        ),
        "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE": (
            "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE",
            "APPSEC_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE",
            "GITHUB_APP_PRIVATE_KEY_FILE",
            "GHE_APP_PRIVATE_KEY_FILE",
        ),
    }
    private_key_supplied = any(
        (
            clean_text(config.get("githubAppPrivateKey")),
            clean_text(config.get("githubAppPrivateKeyFile")),
            *(
                clean_text(os.getenv(alias))
                for names in aliases.values()
                for alias in names
                if "PRIVATE_KEY" in alias
            ),
        )
    )
    if not private_key_supplied:
        return
    values = {
        "APPLICATION_INVENTORY_GITHUB_APP_ID": configured_github_app_id(),
        "APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID": configured_github_installation_id(),
        "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY": clean_text(config.get("githubAppPrivateKey")),
        "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE": clean_text(config.get("githubAppPrivateKeyFile")),
    }
    for name, value in values.items():
        inherited = next((clean_text(os.getenv(alias)) for alias in aliases[name] if clean_text(os.getenv(alias))), "")
        resolved = value or inherited
        if resolved:
            env[name] = resolved


def base_process_environment() -> dict[str, str]:
    return {key: value for key in SAFE_CHILD_ENV_KEYS if (value := os.getenv(key)) is not None}


def inherit_secret(env: dict[str, str], name: str) -> None:
    value = clean_text(os.getenv(name))
    if value:
        env[name] = value


def normalize_ui_application_types(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raw_values = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        raw_values = [str(part).strip() for part in value]
    else:
        raw_values = []
    return normalize_application_types(raw_values)


def postgres_dsn_from_config(config: dict[str, Any]) -> str:
    host = clean_text(config.get("postgresHost"))
    database = clean_text(config.get("postgresDatabase"))
    user = clean_text(config.get("postgresUser"))
    password = clean_text(config.get("postgresPassword"))
    port = positive_int(config.get("postgresPort"), DEFAULT_POSTGRES_PORT)
    if not host:
        raise ValueError("PostgreSQL host is required when database sync is enabled.")
    if not database:
        raise ValueError("PostgreSQL database is required when database sync is enabled.")
    if not user:
        raise ValueError("PostgreSQL user is required when database sync is enabled.")
    auth = quote(user, safe="")
    if password:
        auth = f"{auth}:{quote(password, safe='')}"
    return f"postgresql://{auth}@{host}:{port}/{quote(database, safe='')}"


def ado_org_summary(org_pats: tuple[Any, ...]) -> str:
    if not org_pats:
        return ""
    if len(org_pats) == 1:
        return org_pats[0].org
    return f"{len(org_pats)} Azure DevOps organizations"


def mixed_org_summary(github_owner: str, org_pats: tuple[Any, ...]) -> str:
    ado_summary = ado_org_summary(org_pats)
    return f"{github_owner} + {ado_summary}" if ado_summary else github_owner


def clean_choice(value: Any, allowed: set[str], default: str) -> str:
    text = clean_text(value)
    return text if text in allowed else default


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def env_value(*names: str) -> str:
    for name in names:
        value = clean_text(os.getenv(name))
        if value:
            return value
    return ""


def positive_int(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def nonnegative_int(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number >= 0 else default
