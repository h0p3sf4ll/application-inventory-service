from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, TypeVar

from .azure import AzureDevOpsClient
from .constants import DEFAULT_SOURCE_WORKERS, DEFAULT_TIMEOUT_SECONDS
from .github import (
    GitHubAppCredentials,
    GitHubEnterpriseClient,
    configured_github_api_url,
    configured_github_owners,
    parse_github_urls,
)
from .models import AzureDevOpsError
from .org_tokens import parse_ado_org_pat_values
from .scan_request import clean_choice, clean_text, positive_int


Source = TypeVar("Source")


def discover_source_targets(config: dict[str, Any]) -> dict[str, Any]:
    provider = clean_choice(config.get("provider"), {"azure-devops", "github-enterprise", "mixed"}, "azure-devops")
    timeout = positive_int(config.get("timeout"), DEFAULT_TIMEOUT_SECONDS)
    workers = positive_int(config.get("sourceWorkers"), DEFAULT_SOURCE_WORKERS)
    if provider == "github-enterprise":
        return discover_github_targets(config, timeout, workers)
    if provider == "azure-devops":
        return discover_azure_targets(config, timeout, workers)

    targets: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="source-discovery") as executor:
        futures = (
            executor.submit(discover_azure_targets, config, timeout, workers),
            executor.submit(discover_github_targets, config, timeout, workers),
        )
        for future in as_completed(futures):
            try:
                response = future.result()
            except ValueError as exc:
                errors.append({"org": clean_text(config.get("org")), "message": str(exc)})
                continue
            targets.extend(response.get("targets", []))
            errors.extend(response.get("errors", []))
    return {"provider": "mixed", "targets": sorted_targets(targets), "errors": errors}


def discover_azure_targets(config: dict[str, Any], timeout: int, max_workers: int = 1) -> dict[str, Any]:
    org_pats = parse_ado_org_pat_values([config.get("adoOrgPats")])
    if not org_pats:
        raise ValueError("Add at least one Azure organization and PAT.")

    def load_projects(org_pat: Any) -> tuple[list[dict[str, str]], dict[str, str] | None]:
        client = AzureDevOpsClient(org_pat.org, org_pat.pat, timeout)
        try:
            projects = client.list_projects()
        except AzureDevOpsError as exc:
            return [], {"org": org_pat.org, "message": str(exc)}
        finally:
            client.close()
        targets = [
            source_target("azure-devops", org_pat.org, name, "project")
            for project in projects
            if (name := clean_text(project.get("name")))
        ]
        return targets, None

    targets, errors = discover_concurrently(org_pats, load_projects, max_workers)
    return {"provider": "azure-devops", "targets": sorted_targets(targets), "errors": errors}


def discover_github_targets(config: dict[str, Any], timeout: int, max_workers: int = 1) -> dict[str, Any]:
    owners = parse_github_urls(config.get("githubUrls"), default=clean_text(config.get("org"))) or configured_github_owners()
    if not owners:
        raise ValueError("Configure at least one GitHub organization in the UI or APPLICATION_INVENTORY_GITHUB_URLS.")
    base_url = configured_github_api_url()
    token = discovery_token(config, "github-enterprise")
    try:
        app_credentials = GitHubAppCredentials.from_values(
            config.get("githubAppId", ""),
            config.get("githubAppInstallationId", ""),
            config.get("githubAppPrivateKey", ""),
            config.get("githubAppPrivateKeyFile", ""),
        )
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    if not token and not app_credentials:
        raise ValueError("GitHub App credentials are required to load repositories.")

    def load_repositories(owner: str) -> tuple[list[dict[str, str]], dict[str, str] | None]:
        try:
            client_kwargs = {"app_credentials": app_credentials} if app_credentials and not token else {}
            client = GitHubEnterpriseClient(base_url, owner, token, timeout, **client_kwargs)
        except ValueError as exc:
            return [], {"org": owner, "message": str(exc)}
        try:
            repos = client.list_repos("")
        except AzureDevOpsError as exc:
            return [], {"org": owner, "message": str(exc)}
        finally:
            client.close()
        targets = [
            source_target(
                "github-enterprise",
                owner,
                name,
                "repository",
                clean_text(repo.get("fullName")) or name,
            )
            for repo in repos
            if not repo.get("isDisabled") and (name := clean_text(repo.get("name")))
        ]
        return targets, None

    targets, errors = discover_concurrently(owners, load_repositories, max_workers)
    return {"provider": "github-enterprise", "targets": sorted_targets(targets), "errors": errors}


def discover_concurrently(
    sources: Iterable[Source],
    loader: Callable[[Source], tuple[list[dict[str, str]], dict[str, str] | None]],
    max_workers: int,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    source_values = tuple(sources)
    workers = max(1, min(max_workers, len(source_values)))
    if workers == 1:
        results = [loader(source) for source in source_values]
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="source-targets") as executor:
            results = list(executor.map(loader, source_values))
    targets = [target for source_targets, _ in results for target in source_targets]
    errors = [error for _, error in results if error is not None]
    return targets, errors


def discovery_token(config: dict[str, Any], provider: str) -> str:
    token = clean_text(config.get("token"))
    if token:
        return token
    if provider == "github-enterprise":
        return clean_text(os.getenv("GITHUB_TOKEN") or os.getenv("GHE_TOKEN"))
    return clean_text(os.getenv("ADO_PAT"))


def source_target(
    provider: str,
    org: str,
    project: str,
    kind: str,
    display_name: str = "",
) -> dict[str, str]:
    return {
        "provider": provider,
        "org": org,
        "project": project,
        "repo": project if provider == "github-enterprise" else "",
        "kind": kind,
        "name": project,
        "label": display_name or f"{org} / {project}",
    }


def sorted_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        targets,
        key=lambda target: (
            clean_text(target.get("org")).lower(),
            clean_text(target.get("project")).lower(),
        ),
    )
