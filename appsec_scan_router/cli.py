from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .constants import (
    DEFAULT_ACTIVITY_MODE,
    DEFAULT_BRANCH_AGE_DAYS,
    DEFAULT_BRANCH_WORKERS,
    DEFAULT_CONTENT_WORKERS,
    DEFAULT_MAX_WORKERS,
    DEFAULT_OUT_PREFIX,
    DEFAULT_POSTGRES_TABLE,
    DEFAULT_POSTGRES_SCHEMA,
    DEFAULT_STORE_COUNTRY,
    DEFAULT_STORE_TIMEOUT_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    KNOWN_INVENTORY_TYPES,
)
from .github import normalize_github_api_url
from .models import AzureDevOpsOrgPat, ScanConfig, SourceTargetFilter
from .org_tokens import parse_ado_org_pat_values
from .scanner import normalize_application_types, scan_to_reports, store_lookup_allowed
from .target_filters import parse_source_target_filter_values


def parse_args(argv: list[str]) -> ScanConfig:
    parser = argparse.ArgumentParser(
        prog="application-inventory-service",
        description="Inventory applications, services, middleware, and mobile apps across Azure DevOps or GitHub Enterprise.",
    )
    parser.add_argument(
        "--provider",
        choices=("azure-devops", "github-enterprise"),
        default=env_value("APPLICATION_INVENTORY_PROVIDER", "APPSEC_SCAN_PROVIDER") or "azure-devops",
        help="Source provider. Defaults to azure-devops.",
    )
    parser.add_argument("--org", help="Azure DevOps organization or GitHub owner.")
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
        default=env_value("APPLICATION_INVENTORY_BASE_URL", "APPSEC_SCAN_BASE_URL", "GITHUB_API_URL", "GHE_API_URL"),
        help="GitHub Enterprise API URL, for example https://github.example.com/api/v3.",
    )
    parser.add_argument(
        "--pat",
        help="Provider token. Prefer ADO_PAT for Azure DevOps or GITHUB_TOKEN/GHE_TOKEN for GitHub Enterprise.",
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
        default=DEFAULT_STORE_COUNTRY,
        help=f"Two-letter store country code for public lookups. Defaults to {DEFAULT_STORE_COUNTRY}.",
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

    configure_logging(args.verbose)
    application_types = normalize_application_types(args.application_types)
    ado_org_pats = collect_ado_org_pats(args)
    target_filters = collect_target_filters(args)
    validate_args(args, application_types, ado_org_pats)
    token = "" if ado_org_pats else provider_token(args)
    target_projects = provider_projects(args)
    target_project = target_projects[0] if len(target_projects) == 1 and not target_filters else None
    org = args.org or (ado_org_pats[0].org if len(ado_org_pats) == 1 else "")
    base_url = normalize_github_api_url(args.base_url) if args.provider == "github-enterprise" else args.base_url

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
        store_country=args.store_country.strip().upper(),
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
    )


def validate_args(
    args: argparse.Namespace,
    application_types: tuple[str, ...],
    ado_org_pats: tuple[AzureDevOpsOrgPat, ...],
) -> None:
    project_values = tuple(args.project or ())
    repo_values = tuple(args.repo or ())
    if project_values and repo_values and project_values != repo_values:
        raise SystemExit("--project and --repo cannot refer to different repositories.")
    if args.provider == "github-enterprise":
        if ado_org_pats or args.ado_org_pat:
            raise SystemExit("--ado-org-pat only applies to Azure DevOps scans.")
        if not args.org:
            raise SystemExit("Missing GitHub owner. Set --org.")
        if not provider_token(args):
            raise SystemExit(provider_token_message(args.provider))
        if not args.base_url:
            raise SystemExit("Missing GitHub Enterprise API URL. Set --base-url or GITHUB_API_URL.")
        try:
            normalize_github_api_url(args.base_url)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    else:
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
    store_country = args.store_country.strip()
    if len(store_country) != 2 or not store_country.isalpha():
        raise SystemExit("--store-country must be a two-letter country code.")
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


def provider_token(args: argparse.Namespace) -> str:
    if args.pat:
        return args.pat
    if args.provider == "github-enterprise":
        return os.getenv("GITHUB_TOKEN") or os.getenv("GHE_TOKEN") or ""
    return os.getenv("ADO_PAT") or ""


def collect_ado_org_pats(args: argparse.Namespace) -> tuple[AzureDevOpsOrgPat, ...]:
    if args.provider != "azure-devops":
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
    if org_pats and args.org and token:
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
    values.extend(args.target_filter or [])
    try:
        return parse_source_target_filter_values(values)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


def provider_token_message(provider: str) -> str:
    if provider == "github-enterprise":
        return "Missing GitHub token. Set GITHUB_TOKEN, GHE_TOKEN, or pass --pat."
    return "Missing Azure DevOps PAT. Set ADO_PAT or pass --pat."


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


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
