from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace

from .azure import AzureDevOpsClient
from .github import (
    GitHubAppCredentials,
    GitHubEnterpriseClient,
    configured_github_owners,
    parse_github_urls,
)
from .models import AzureDevOpsError, ScanConfig
from .target_filters import target_filters_for_source


LOGGER = logging.getLogger("appsec_scan_router")


def create_source_client(
    config: ScanConfig,
) -> AzureDevOpsClient | GitHubEnterpriseClient:
    if config.provider == "github-enterprise":
        app_credentials = GitHubAppCredentials.from_values(
            config.github_app_id,
            config.github_app_installation_id,
            config.github_app_private_key,
            config.github_app_private_key_file,
        )
        return GitHubEnterpriseClient(
            base_url=config.base_url,
            owner=config.org,
            token=config.pat,
            timeout_seconds=config.timeout_seconds,
            app_credentials=app_credentials,
        )
    return AzureDevOpsClient(config.org, config.pat, config.timeout_seconds)


def validate_scan_source_access(config: ScanConfig) -> None:
    source_configs = source_access_configs(config)
    if not source_configs:
        return

    failures: list[tuple[ScanConfig, Exception]] = []
    workers = max(1, min(config.source_workers, len(source_configs)))

    def validate(source_config: ScanConfig) -> None:
        client = create_source_client(source_config)
        try:
            client.validate_access()
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(validate, source_config): source_config
            for source_config in source_configs
        }
        for future in as_completed(futures):
            source_config = futures[future]
            try:
                future.result()
            except Exception as exc:
                failures.append((source_config, exc))

    if failures:
        failures.sort(key=lambda item: (item[0].provider, item[0].org.casefold()))
        messages = [source_access_failure(item, exc) for item, exc in failures]
        status_code = next(
            (
                exc.status_code
                for _, exc in failures
                if isinstance(exc, AzureDevOpsError) and exc.status_code is not None
            ),
            None,
        )
        raise AzureDevOpsError(
            "Source access validation failed: " + "; ".join(messages),
            status_code=status_code,
        )

    count = len(source_configs)
    LOGGER.info("Validated access to %s configured source%s", count, "s" if count != 1 else "")


def source_access_configs(config: ScanConfig) -> list[ScanConfig]:
    source_configs: list[ScanConfig] = []
    if config.provider in {"azure-devops", "mixed"}:
        if config.ado_org_pats:
            for org_pat in config.ado_org_pats:
                org_filters = target_filters_for_source(
                    config.target_filters, org_pat.org
                )
                if config.target_filters and not org_filters:
                    continue
                source_configs.append(
                    replace(
                        config,
                        provider="azure-devops",
                        org=org_pat.org,
                        pat=org_pat.pat,
                        ado_org_pats=(),
                        github_urls=(),
                        target_filters=org_filters,
                    )
                )
        elif config.provider == "azure-devops" and config.org:
            source_configs.append(config)

    if config.provider in {"github-enterprise", "mixed"}:
        owners = (
            parse_github_urls(config.github_urls or (config.org,))
            or configured_github_owners()
        )
        for owner in owners:
            owner_filters = target_filters_for_source(config.target_filters, owner)
            if config.target_filters and not owner_filters:
                continue
            source_configs.append(
                replace(
                    config,
                    provider="github-enterprise",
                    org=owner,
                    ado_org_pats=(),
                    github_urls=(),
                    target_filters=owner_filters,
                )
            )
    return source_configs


def source_access_failure(config: ScanConfig, error: Exception) -> str:
    provider = "Azure DevOps" if config.provider == "azure-devops" else "GitHub"
    status_code = error.status_code if isinstance(error, AzureDevOpsError) else None
    error_text = str(error).casefold()
    if config.provider == "azure-devops" and status_code == 401:
        reason = (
            "the PAT has expired"
            if "expired" in error_text
            else "the PAT was rejected or has expired"
        )
    elif config.provider == "github-enterprise" and status_code == 401:
        reason = "the GitHub App installation credentials were rejected"
    elif status_code == 403:
        reason = "the configured credential does not have permission"
    elif status_code == 404:
        reason = (
            "the organization was not found or the configured credential cannot access it"
        )
    elif status_code == 429:
        reason = "the provider rate limit was reached; retry after the provider backoff period"
    elif status_code is not None:
        reason = f"the provider returned HTTP {status_code}"
    else:
        detail = re.sub(r"\s+", " ", str(error)).strip()
        reason = detail[:300] or "the provider could not be reached"
    return (
        f"{provider} organization '{config.org}' could not be authenticated because "
        f"{reason}"
    )
