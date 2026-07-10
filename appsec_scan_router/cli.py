from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .constants import (
    DEFAULT_ACTIVITY_MODE,
    DEFAULT_BRANCH_AGE_DAYS,
    DEFAULT_BRANCH_WORKERS,
    DEFAULT_CONTENT_WORKERS,
    DEFAULT_GITHUB_API_URL,
    DEFAULT_GITHUB_APP_ID,
    DEFAULT_GITHUB_APP_INSTALLATION_ID,
    DEFAULT_MAX_WORKERS,
    DEFAULT_OUT_PREFIX,
    DEFAULT_POSTGRES_TABLE,
    DEFAULT_POSTGRES_SCHEMA,
    DEFAULT_STORE_COUNTRY,
    DEFAULT_STORE_TIMEOUT_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    KNOWN_INVENTORY_TYPES,
)
from .github import (
    GitHubAppCredentials,
    configured_github_api_url,
    configured_github_app_id,
    configured_github_installation_id,
    configured_github_owners,
    normalize_github_api_url,
    parse_github_urls,
)
from .models import AzureDevOpsOrgPat, ScanConfig, SourceTargetFilter
from .observability import configure_logging as configure_observability_logging, log_github_app_context
from .org_tokens import parse_ado_org_pat_values
from .scanner import normalize_application_types, normalize_store_countries, scan_to_reports, store_lookup_allowed
from .target_filters import parse_source_target_filter_values


def parse_args(argv: list[str]) -> ScanConfig:
    parser = argparse.ArgumentParser(
        prog="application-inventory-service",
        description="Inventory applications, services, middleware, and mobile apps across Azure DevOps or GitHub Enterprise.",
    )
    parser.add_argument(
        "--provider",
        choices=("azure-devops", "github-enterprise", "mixed"),
        default=env_value("APPLICATION_INVENTORY_PROVIDER", "APPSEC_SCAN_PROVIDER") or "azure-devops",
        help="Source provider, or mixed to scan Azure DevOps and GitHub Enterprise in one run.",
    )
    parser.add_argument("--org", help="Azure DevOps organization. Kept as a compatibility alias for one GitHub URL.")
    parser.add_argument(
        "--github-url",
        action="append",
        default=[],
        metavar="OWNER_OR_URL",
        help="GitHub owner or github.com owner URL. May be repeated. Defaults to APPLICATION_INVENTORY_GITHUB_URLS.",
    )
    parser.add_argument(
        "--ado-org-pat",
        action="append",
        default=[],
        metavar="ORG=PAT",
        help=(
            "Azure DevOps organization and PAT pair. May be repeated. "
            "When provided, each organization is scanned with its own PAT."
        ),
    )
    parser.add_argument(
        "--project",
        action="append",
        default=[],
        help="Azure DevOps project or GitHub repository name. May be repeated. Omit to scan all.",
    )
    parser.add_argument(
        "--repo",
        action="append",
        default=[],
        help="GitHub repository name. Alias for --project. May be repeated. Omit to scan all.",
    )
    parser.add_argument(
        "--target-filter",
        action="append",
        default=[],
        metavar="[ORG=]PROJECT_OR_REPO",
        help=(
            "Provider target filter. May be repeated. Use ORG=PROJECT for Azure DevOps multi-org scans, "
            "or a repository name for GitHub Enterprise."
        ),
    )
    parser.add_argument(
        "--base-url",
        default=configured_github_api_url(),
        help=f"GitHub API URL. Defaults to the fixed public endpoint {DEFAULT_GITHUB_API_URL}.",
    )
    parser.add_argument(
        "--pat",
        help="Provider token. Use ADO_PAT for Azure DevOps. GitHub Enterprise should use GitHub App settings.",
    )
    parser.add_argument(
        "--github-app-id",
        default=configured_github_app_id() or DEFAULT_GITHUB_APP_ID,
        help="GitHub App ID. Prefer the environment variable for automation.",
    )
    parser.add_argument(
        "--github-app-installation-id",
        default=env_value(
            "APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID",
            "APPSEC_INVENTORY_GITHUB_APP_INSTALLATION_ID",
            "GITHUB_APP_INSTALLATION_ID",
            "GHE_APP_INSTALLATION_ID",
        ) or configured_github_installation_id() or DEFAULT_GITHUB_APP_INSTALLATION_ID,
        help="GitHub App installation ID. Prefer the environment variable for automation.",
    )
    parser.add_argument(
        "--github-app-private-key-file",
        default=env_value(
            "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE",
            "APPSEC_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE",
            "GITHUB_APP_PRIVATE_KEY_FILE",
            "GHE_APP_PRIVATE_KEY_FILE",
        ),
        help="Path to the GitHub App PEM private key. Prefer a secret-mounted file.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory for XLSX, Semgrep, and SonarQube target outputs. Defaults to the current directory.",
    )
    parser.add_argument(
        "--out-prefix",
        default=DEFAULT_OUT_PREFIX,
        help=f"Report file prefix. Defaults to {DEFAULT_OUT_PREFIX}.",
    )
    parser.add_argument(
        "--application-type",
        "--inventory-type",
        action="append",
        choices=KNOWN_INVENTORY_TYPES,
        default=[],
        dest="application_types",
        help=(
            "Application type to include in reports. May be repeated. "
            f"Defaults to all types. Valid values: {', '.join(KNOWN_INVENTORY_TYPES)}."
        ),
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help=f"Maximum concurrent repository preparation tasks. Defaults to {DEFAULT_MAX_WORKERS}.",
    )
    parser.add_argument(
        "--branch-workers",
        type=int,
        default=DEFAULT_BRANCH_WORKERS,
        help=f"Maximum concurrent resolved-branch scans. Defaults to {DEFAULT_BRANCH_WORKERS}.",
    )
    parser.add_argument(
        "--content-workers",
        type=int,
        default=DEFAULT_CONTENT_WORKERS,
        help=(
            "Maximum concurrent config/manifest file fetches across resolved repository branches. "
            f"Defaults to {DEFAULT_CONTENT_WORKERS}."
        ),
    )
    parser.add_argument(
        "--max-commits-per-repo",
        type=int,
        default=0,
        help=(
            "Maximum commits to inspect per matched resolved branch for contributors. "
            "Use 0 for all available history. Defaults to 0."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"HTTP request timeout in seconds. Defaults to {DEFAULT_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--min-confidence",
        choices=("low", "medium", "high"),
        default="low",
        help="Minimum confidence to include in reports. Defaults to low.",
    )
    parser.add_argument(
        "--branch-age-days",
        type=int,
        default=DEFAULT_BRANCH_AGE_DAYS,
        help=f"Age cutoff for workbook active/older branch sheets. Defaults to {DEFAULT_BRANCH_AGE_DAYS}.",
    )
    parser.add_argument(
        "--activity-mode",
        choices=("contributors", "latest"),
        default=DEFAULT_ACTIVITY_MODE,
        help=(
            "Commit activity mode. Use contributors for full contributor extraction, "
            "or latest for fast latest-commit-only activity. Defaults to contributors."
        ),
    )
    parser.add_argument(
        "--store-lookup",
        action="store_true",
        help="Enable public Apple App Store and Google Play enrichment from detected app identifiers.",
    )
    parser.add_argument(
        "--store-country",
        action="append",
        default=[],
        help=f"Two-letter store country code for public lookups. Repeat for multiple countries. Defaults to {DEFAULT_STORE_COUNTRY}.",
    )
    parser.add_argument(
        "--store-timeout",
        type=int,
        default=DEFAULT_STORE_TIMEOUT_SECONDS,
        help=f"Store lookup HTTP timeout in seconds. Defaults to {DEFAULT_STORE_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--postgres-dsn",
        default=env_value("APPLICATION_INVENTORY_POSTGRES_DSN", "APPSEC_INVENTORY_POSTGRES_DSN"),
        help=(
            "PostgreSQL DSN for streaming upserts, for example "
            "postgresql://user:password@localhost:5432/postgres. "
            "Prefer APPLICATION_INVENTORY_POSTGRES_DSN for sensitive values."
        ),
    )
    parser.add_argument(
        "--postgres-schema",
        default=env_value("APPLICATION_INVENTORY_POSTGRES_SCHEMA", "APPSEC_INVENTORY_POSTGRES_SCHEMA") or DEFAULT_POSTGRES_SCHEMA,
        help=f"PostgreSQL schema for normalized inventory tables. Defaults to {DEFAULT_POSTGRES_SCHEMA}.",
    )
    parser.add_argument(
        "--postgres-table",
        default=env_value("APPLICATION_INVENTORY_POSTGRES_TABLE", "APPSEC_INVENTORY_POSTGRES_TABLE") or DEFAULT_POSTGRES_TABLE,
        help=f"PostgreSQL compatibility table for flat inventory upserts. Defaults to {DEFAULT_POSTGRES_TABLE}.",
    )
    parser.add_argument("--owner-user-id", default=env_value("APPLICATION_INVENTORY_OWNER_USER_ID", "APPSEC_INVENTORY_OWNER_USER_ID") or "anonymous", help=argparse.SUPPRESS)
    parser.add_argument("--owner-user-login", default=env_value("APPLICATION_INVENTORY_OWNER_USER_LOGIN", "APPSEC_INVENTORY_OWNER_USER_LOGIN") or "anonymous", help=argparse.SUPPRESS)
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    args = parser.parse_args(argv)

    configure_logging(args.verbose, args.postgres_dsn, args.postgres_schema)
    if args.provider in {"github-enterprise", "mixed"}:
        log_github_app_context(args.github_app_id, args.github_app_installation_id)
    application_types = normalize_application_types(args.application_types)
    ado_org_pats = collect_ado_org_pats(args)
    target_filters = collect_target_filters(args)
    github_urls = collect_github_urls(args)
    validate_args(args, application_types, ado_org_pats, github_urls)
    token = provider_token(args)
    if args.provider == "azure-devops" and ado_org_pats:
        token = ""
    target_projects = provider_projects(args)
    target_project = target_projects[0] if len(target_projects) == 1 and not target_filters else None
    org = args.org or (ado_org_pats[0].org if len(ado_org_pats) == 1 else "")
    if args.provider in {"github-enterprise", "mixed"}:
        org = github_urls[0]
    base_url = normalize_github_api_url(args.base_url) if args.provider in {"github-enterprise", "mixed"} else args.base_url

    store_countries = normalize_store_countries(args.store_country or [DEFAULT_STORE_COUNTRY])
    return ScanConfig(
        org=org,
        pat=token,
        project=target_project,
        out_dir=args.out_dir,
        out_prefix=args.out_prefix,
        max_workers=args.max_workers,
        branch_workers=args.branch_workers,
        content_workers=args.content_workers,
        max_commits_per_repo=args.max_commits_per_repo,
        timeout_seconds=args.timeout,
        min_confidence=args.min_confidence,
        branch_age_days=args.branch_age_days,
        activity_mode=args.activity_mode,
        store_lookup=args.store_lookup,
        store_country=store_countries[0],
        store_countries=store_countries,
        store_timeout_seconds=args.store_timeout,
        provider=args.provider,
        base_url=base_url,
        application_types=application_types,
        postgres_dsn=args.postgres_dsn,
        postgres_schema=args.postgres_schema,
        postgres_table=args.postgres_table,
        owner_user_id=args.owner_user_id,
        owner_user_login=args.owner_user_login,
        ado_org_pats=ado_org_pats,
        target_filters=target_filters or tuple(SourceTargetFilter("", project) for project in target_projects),
        github_urls=github_urls,
        github_app_id=args.github_app_id,
        github_app_installation_id=args.github_app_installation_id,
        github_app_private_key=env_value(
            "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY",
            "APPSEC_INVENTORY_GITHUB_APP_PRIVATE_KEY",
            "GITHUB_APP_PRIVATE_KEY",
            "GHE_APP_PRIVATE_KEY",
        ),
        github_app_private_key_file=args.github_app_private_key_file,
    )


def validate_args(
    args: argparse.Namespace,
    application_types: tuple[str, ...],
    ado_org_pats: tuple[AzureDevOpsOrgPat, ...],
    github_urls: tuple[str, ...],
) -> None:
    project_values = tuple(args.project or ())
    repo_values = tuple(args.repo or ())
    if project_values and repo_values and project_values != repo_values:
        raise SystemExit("--project and --repo cannot refer to different repositories.")
    if args.provider == "github-enterprise":
        if ado_org_pats or args.ado_org_pat:
            raise SystemExit("--ado-org-pat only applies to Azure DevOps scans.")
    if args.provider in {"github-enterprise", "mixed"}:
        if not github_urls:
            raise SystemExit("Missing GitHub URL. Set --github-url.")
        try:
            app_credentials = GitHubAppCredentials.from_values(
                args.github_app_id,
                args.github_app_installation_id,
                env_value(
                    "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY",
                    "APPSEC_INVENTORY_GITHUB_APP_PRIVATE_KEY",
                    "GITHUB_APP_PRIVATE_KEY",
                    "GHE_APP_PRIVATE_KEY",
                ),
                args.github_app_private_key_file,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        if not provider_token(args) and not app_credentials:
            raise SystemExit(provider_token_message(args.provider))
        if not args.base_url:
            raise SystemExit("Missing GitHub Enterprise API URL. Set --base-url or GITHUB_API_URL.")
        try:
            normalize_github_api_url(args.base_url)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    if args.provider in {"azure-devops", "mixed"}:
        if args.provider == "mixed" and not ado_org_pats:
            raise SystemExit("Mixed scans require at least one --ado-org-pat ORG=PAT or APPLICATION_INVENTORY_ADO_ORG_PATS.")
        if not args.org and not ado_org_pats:
            raise SystemExit("Missing Azure DevOps organization. Set --org or pass --ado-org-pat ORG=PAT.")
        if not ado_org_pats and not provider_token(args):
            raise SystemExit(provider_token_message(args.provider))
    if args.max_workers < 1:
        raise SystemExit("--max-workers must be at least 1.")
    if args.branch_workers < 1:
        raise SystemExit("--branch-workers must be at least 1.")
    if args.content_workers < 1:
        raise SystemExit("--content-workers must be at least 1.")
    if args.max_commits_per_repo < 0:
        raise SystemExit("--max-commits-per-repo must be 0 or greater.")
    if args.timeout < 1:
        raise SystemExit("--timeout must be at least 1.")
    if args.branch_age_days < 1:
        raise SystemExit("--branch-age-days must be at least 1.")
    try:
        normalize_store_countries(args.store_country or [DEFAULT_STORE_COUNTRY])
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if args.store_timeout < 1:
        raise SystemExit("--store-timeout must be at least 1.")
    if args.store_lookup and not store_lookup_allowed(application_types):
        raise SystemExit("--store-lookup only applies when scanning mobile apps or all application types.")


def provider_projects(args: argparse.Namespace) -> tuple[str, ...]:
    values = list(args.project or args.repo or [])
    deduped: dict[str, str] = {}
    for value in values:
        cleaned = str(value or "").strip()
        if cleaned:
            deduped[cleaned.lower()] = cleaned
    return tuple(deduped.values())


def collect_github_urls(args: argparse.Namespace) -> tuple[str, ...]:
    if args.provider not in {"github-enterprise", "mixed"}:
        return ()
    values: list[object] = []
    env_value = os.getenv("APPLICATION_INVENTORY_GITHUB_URLS") or os.getenv("APPSEC_INVENTORY_GITHUB_URLS") or ""
    if env_value:
        values.append(env_value)
    values.extend(args.github_url or [])
    if not values and args.org:
        values.append(args.org)
    try:
        return parse_github_urls(values) or configured_github_owners()
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


def provider_token(args: argparse.Namespace) -> str:
    if args.pat:
        return args.pat
    if args.provider in {"github-enterprise", "mixed"}:
        return os.getenv("GITHUB_TOKEN") or os.getenv("GHE_TOKEN") or ""
    return os.getenv("ADO_PAT") or ""


def collect_ado_org_pats(args: argparse.Namespace) -> tuple[AzureDevOpsOrgPat, ...]:
    if args.provider not in {"azure-devops", "mixed"}:
        return ()
    values: list[object] = []
    org_pat_env_value = env_value("APPLICATION_INVENTORY_ADO_ORG_PATS", "APPSEC_INVENTORY_ADO_ORG_PATS", "ADO_ORG_PATS")
    if org_pat_env_value:
        values.append(org_pat_env_value)
    values.extend(args.ado_org_pat or [])
    try:
        org_pats = list(parse_ado_org_pat_values(values))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    token = provider_token(args)
    if args.provider == "azure-devops" and org_pats and args.org and token:
        org_pats.append(AzureDevOpsOrgPat(args.org, token))
    deduped: dict[str, AzureDevOpsOrgPat] = {}
    for org_pat in org_pats:
        deduped[org_pat.org.lower()] = org_pat
    return tuple(deduped.values())


def collect_target_filters(args: argparse.Namespace) -> tuple[SourceTargetFilter, ...]:
    values: list[object] = []
    target_filter_env_value = env_value("APPLICATION_INVENTORY_TARGET_FILTERS", "APPSEC_INVENTORY_TARGET_FILTERS")
    if target_filter_env_value:
        values.append(target_filter_env_value)
    if args.provider in {"github-enterprise", "mixed"}:
        github_repository_env_value = env_value(
            "APPLICATION_INVENTORY_GITHUB_REPOSITORIES",
            "APPSEC_INVENTORY_GITHUB_REPOSITORIES",
        )
        if github_repository_env_value:
            values.append(github_repository_env_value)
    values.extend(args.target_filter or [])
    try:
        return parse_source_target_filter_values(values)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


def provider_token_message(provider: str) -> str:
    if provider in {"github-enterprise", "mixed"}:
        source = "GitHub Enterprise" if provider == "github-enterprise" else "GitHub Enterprise for the mixed scan"
        return (
            f"Missing {source} App configuration. Set GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, "
            "and GITHUB_APP_PRIVATE_KEY_FILE, or use GITHUB_TOKEN as a compatibility fallback."
        )
    return "Missing Azure DevOps PAT. Set ADO_PAT or pass --pat."


def configure_logging(
    verbose: bool,
    dsn: str = "",
    schema: str = "application_inventory",
) -> dict[str, object]:
    return configure_observability_logging(verbose, dsn=dsn, schema=schema, source="cli")


def env_value(*names: str) -> str:
    for name in names:
        value = str(os.getenv(name) or "").strip()
        if value:
            return value
    return ""


def main(argv: list[str] | None = None) -> int:
    config = parse_args(sys.argv[1:] if argv is None else argv)
    results, xlsx_path, semgrep_path, sonarqube_path = scan_to_reports(config)
    print(f"Done. Found {len(results)} inventory branches.")
    print(f"XLSX:              {xlsx_path}")
    print(f"Semgrep targets:   {semgrep_path}")
    print(f"SonarQube targets: {sonarqube_path}")
    return 0
