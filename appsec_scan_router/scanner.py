from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, as_completed, wait
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .activity import extract_repo_activity, parse_ado_datetime
from .azure import AzureDevOpsClient
from .constants import (
    DEFAULT_ACTIVITY_MODE,
    FALLBACK_BRANCH_PRIORITY,
    KNOWN_CATEGORIES,
    KNOWN_INVENTORY_TYPES,
    active_sheet_name,
    older_sheet_name,
)
from .detection import detect_inventory_repo
from .github import GitHubAppCredentials, GitHubEnterpriseClient
from .metadata import extract_mobile_metadata
from .models import (
    AzureDevOpsError,
    BranchScanTarget,
    DetectionEvidence,
    MobileAppMetadata,
    RepoActivityMetadata,
    RepoScanTarget,
    ScanConfig,
    SourceTargetFilter,
)
from .postgres import PostgresInventoryWriter
from .reports import StreamingReportWriter
from .store_lookup import StoreLookupClient, store_columns
from .utils import clean_value, clean_version, confidence_rank, load_json_object, should_fetch_content, xml_text, yaml_scalar


LOGGER = logging.getLogger("appsec_scan_router")


def scan_to_reports(config: ScanConfig) -> tuple[list[dict[str, Any]], Path, Path, Path]:
    with ExitStack() as stack:
        writer = stack.enter_context(
            StreamingReportWriter(
                config.out_dir,
                config.out_prefix,
                config.branch_age_days,
                config.application_types,
            )
        )
        postgres_writer = stack.enter_context(PostgresInventoryWriter(config)) if config.postgres_dsn else None
        LOGGER.info("Streaming Excel report to %s", writer.xlsx_path)
        LOGGER.info("Streaming Semgrep targets to %s", writer.semgrep_targets_path)
        LOGGER.info("Streaming SonarQube targets to %s", writer.sonarqube_projects_path)
        if postgres_writer:
            LOGGER.info("Streaming PostgreSQL updates to schema %s and table %s", config.postgres_schema, config.postgres_table)

        def write_result(result: dict[str, Any]) -> None:
            writer.write_result(result)
            if postgres_writer:
                postgres_writer.write_result(result)

        results = scan(config, on_result=write_result)
        return results, writer.xlsx_path, writer.semgrep_targets_path, writer.sonarqube_projects_path


def scan(
    config: ScanConfig,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    if config.provider == "mixed":
        return scan_mixed(config, on_result=on_result)
    if config.provider == "azure-devops" and config.ado_org_pats:
        return scan_ado_organizations(config, on_result=on_result)
    return scan_single_org(config, on_result=on_result)


def scan_ado_organizations(
    config: ScanConfig,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    start = time.monotonic()
    for org_pat in config.ado_org_pats:
        org_filters = target_filters_for_source(config.target_filters, org_pat.org)
        if config.target_filters and not org_filters:
            LOGGER.info("Skipping Azure DevOps organization without selected targets: %s", org_pat.org)
            continue
        LOGGER.info("Scanning Azure DevOps organization: %s", org_pat.org)
        org_config = replace(config, org=org_pat.org, pat=org_pat.pat, ado_org_pats=(), target_filters=org_filters)
        results.extend(scan_single_org(org_config, on_result=on_result))
    results.sort(key=row_sort_key)
    LOGGER.info(
        "Finished multi-organization Azure DevOps scan in %.1fs; found %s inventory branches",
        time.monotonic() - start,
        len(results),
    )
    return results


def scan_mixed(
    config: ScanConfig,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    start = time.monotonic()
    results: list[dict[str, Any]] = []
    ado_config = replace(
        config,
        provider="azure-devops",
        org="",
        pat="",
        project=None,
        base_url="",
    )
    results.extend(scan_ado_organizations(ado_config, on_result=on_result))
    github_config = replace(
        config,
        provider="github-enterprise",
        ado_org_pats=(),
        target_filters=target_filters_for_source(config.target_filters, config.org),
    )
    results.extend(scan_single_org(github_config, on_result=on_result))
    results.sort(key=row_sort_key)
    LOGGER.info("Finished mixed-source scan in %.1fs; found %s inventory branches", time.monotonic() - start, len(results))
    return results


def scan_single_org(
    config: ScanConfig,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    start = time.monotonic()
    client = create_source_client(config)
    store_client = create_store_client(config)
    try:
        targets = collect_targets(client, config.project, config.target_filters)
        LOGGER.info("Scanning resolved default or fallback branches for %s repositories", len(targets))
        if config.application_types:
            LOGGER.info("Filtering inventory to application types: %s", ", ".join(config.application_types))

        results: list[dict[str, Any]] = []
        repo_workers = max(1, min(config.max_workers, len(targets) or 1))
        branch_workers = max(1, config.branch_workers)
        content_workers = max(1, config.content_workers)
        min_rank = confidence_rank(config.min_confidence)

        with (
            ThreadPoolExecutor(max_workers=repo_workers) as repo_executor,
            ThreadPoolExecutor(max_workers=branch_workers) as branch_executor,
            ThreadPoolExecutor(max_workers=content_workers) as content_executor,
        ):
            completed_branch_lists = iter_completed_branch_target_lists(
                repo_executor=repo_executor,
                client=client,
                targets=targets,
                max_in_flight=max(repo_workers * 4, repo_workers),
            )
            pending_branch_scans: set[Future[dict[str, Any] | None]] = set()
            submitted_branches = 0
            completed_branches = 0
            log_scan_progress(0, len(targets), 0, 0)

            for repo_index, future in completed_branch_lists:
                try:
                    branch_targets = future.result()
                except Exception as exc:
                    LOGGER.warning("Failed to resolve repository branch: %s", exc)
                    log_scan_progress(repo_index, len(targets), completed_branches, submitted_branches)
                    continue

                for branch_target in branch_targets:
                    while len(pending_branch_scans) >= max(branch_workers * 4, branch_workers):
                        completed_branches += drain_branch_scans(
                            pending_branch_scans=pending_branch_scans,
                            results=results,
                            on_result=on_result,
                            block=True,
                        )

                    pending_branch_scans.add(
                        branch_executor.submit(
                            scan_branch_target,
                            client,
                            branch_target,
                            content_executor,
                            min_rank,
                            config.max_commits_per_repo,
                            config.branch_age_days,
                            config.activity_mode,
                            store_client,
                            config.application_types,
                        )
                    )
                    submitted_branches += 1

                completed_branches += drain_branch_scans(
                    pending_branch_scans=pending_branch_scans,
                    results=results,
                    on_result=on_result,
                    block=False,
                )
                log_scan_progress(repo_index, len(targets), completed_branches, submitted_branches)

                if repo_index % 25 == 0:
                    LOGGER.info(
                        "Progress: %s/%s repositories prepared; %s/%s resolved branches scanned",
                        repo_index,
                        len(targets),
                        completed_branches,
                        submitted_branches,
                    )

            while pending_branch_scans:
                completed_branches += drain_branch_scans(
                    pending_branch_scans=pending_branch_scans,
                    results=results,
                    on_result=on_result,
                    block=True,
                )
                log_scan_progress(len(targets), len(targets), completed_branches, submitted_branches)
                if completed_branches % 100 == 0:
                    LOGGER.info("Progress: %s/%s resolved branches scanned", completed_branches, submitted_branches)

        results.sort(key=row_sort_key)
        LOGGER.info("Finished in %.1fs; found %s inventory branches", time.monotonic() - start, len(results))
        return results
    finally:
        client.close()
        if store_client:
            store_client.close()


def create_source_client(config: ScanConfig) -> AzureDevOpsClient | GitHubEnterpriseClient:
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


def drain_branch_scans(
    pending_branch_scans: set[Future[dict[str, Any] | None]],
    results: list[dict[str, Any]],
    on_result: Callable[[dict[str, Any]], None] | None,
    block: bool,
) -> int:
    if not pending_branch_scans:
        return 0

    done, pending = wait(
        pending_branch_scans,
        timeout=0 if not block else None,
        return_when=FIRST_COMPLETED,
    )
    pending_branch_scans.clear()
    pending_branch_scans.update(pending)

    for future in done:
        result = handle_branch_scan_future(future, on_result)
        if result:
            results.append(result)

    return len(done)


def handle_branch_scan_future(
    future: Future[dict[str, Any] | None],
    on_result: Callable[[dict[str, Any]], None] | None,
) -> dict[str, Any] | None:
    try:
        result = future.result()
    except Exception as exc:
        LOGGER.warning("Failed to scan branch: %s", exc)
        return None

    if result and on_result:
        on_result(result)
    if result:
        log_detected_result(result)
    return result


def scan_branch_target(
    client: AzureDevOpsClient,
    target: BranchScanTarget,
    content_executor: ThreadPoolExecutor,
    min_confidence_rank: int,
    max_commits_per_repo: int,
    branch_age_days: int,
    activity_mode: str,
    store_client: StoreLookupClient | None,
    application_types: Iterable[str] = (),
) -> dict[str, Any] | None:
    return scan_branch(
        client=client,
        target=RepoScanTarget(
            project_name=target.project_name,
            repo=target.repo,
            organization=target.organization,
            provider=target.provider,
        ),
        branch_name=target.branch_name,
        content_executor=content_executor,
        min_confidence_rank=min_confidence_rank,
        max_commits_per_repo=max_commits_per_repo,
        branch_age_days=branch_age_days,
        activity_mode=activity_mode,
        store_client=store_client,
        application_types=application_types,
    )


def scan_repo(
    client: AzureDevOpsClient,
    target: RepoScanTarget,
    content_executor: ThreadPoolExecutor,
    min_confidence_rank: int,
    max_commits_per_repo: int,
    branch_age_days: int,
    store_client: StoreLookupClient | None,
    activity_mode: str = DEFAULT_ACTIVITY_MODE,
    application_types: Iterable[str] = (),
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for branch_target in list_branch_targets(client, target):
        try:
            row = scan_branch_target(
                client=client,
                target=branch_target,
                content_executor=content_executor,
                min_confidence_rank=min_confidence_rank,
                max_commits_per_repo=max_commits_per_repo,
                branch_age_days=branch_age_days,
                activity_mode=activity_mode,
                store_client=store_client,
                application_types=application_types,
            )
        except AzureDevOpsError as exc:
            LOGGER.info(
                "Skipping branch %s/%s@%s: %s",
                branch_target.project_name,
                branch_target.repo.get("name", ""),
                branch_target.branch_name,
                exc,
            )
            continue
        if row:
            rows.append(row)
    return rows


def list_branch_targets(
    client: AzureDevOpsClient,
    target: RepoScanTarget,
) -> list[BranchScanTarget]:
    repo = target.repo
    repo_id = repo.get("id", "")
    repo_name = repo.get("name", "")

    if not repo_id:
        LOGGER.warning("Skipping repo without id in project %s: %s", target.project_name, repo)
        return []
    if repo.get("isDisabled"):
        LOGGER.info("Skipping disabled repo: %s/%s", target.project_name, repo_name)
        return []

    branch_name = default_branch_name_from_repo(repo)
    if not branch_name:
        branch_name = fallback_branch_name(client, target)
    if not branch_name:
        LOGGER.info(
            "Skipping repo without a scannable default or fallback branch: %s/%s",
            target.project_name,
            repo_name,
        )
        return []

    return [
        BranchScanTarget(
            project_name=target.project_name,
            repo=repo,
            branch_name=branch_name,
            organization=target.organization,
            provider=target.provider,
        )
    ]


def scan_branch(
    client: AzureDevOpsClient,
    target: RepoScanTarget,
    branch_name: str,
    content_executor: ThreadPoolExecutor,
    min_confidence_rank: int,
    max_commits_per_repo: int,
    branch_age_days: int,
    activity_mode: str,
    store_client: StoreLookupClient | None,
    application_types: Iterable[str] = (),
) -> dict[str, Any] | None:
    repo = target.repo
    repo_id = repo.get("id", "")
    repo_name = repo.get("name", "")

    try:
        items = client.list_repo_items(target.project_name, repo_id, branch_name)
    except AzureDevOpsError as exc:
        if exc.status_code == 404:
            LOGGER.debug("Skipping unavailable branch contents: %s/%s@%s", target.project_name, repo_name, branch_name)
            return None
        raise

    paths = [item.get("path", "") for item in items if item.get("path")]
    if not paths:
        LOGGER.debug("Skipping empty branch: %s/%s@%s", target.project_name, repo_name, branch_name)
        return None

    content_paths = [path for path in paths if should_fetch_content(path)]
    contents = fetch_contents(client, target.project_name, repo_id, branch_name, content_paths, content_executor)
    confidence, evidence, score = detect_inventory_repo(paths, contents)

    if confidence == "none" or confidence_rank(confidence) < min_confidence_rank:
        LOGGER.debug("No match: %s/%s@%s", target.project_name, repo_name, branch_name)
        return None

    categories = sorted({item.category for item in evidence})
    inventory_types = inventory_types_from_categories(categories)
    normalized_application_types = normalize_application_types(application_types)
    if not inventory_type_matches(inventory_types, normalized_application_types):
        LOGGER.debug(
            "Skipping type-filtered match: %s/%s@%s types=%s filter=%s",
            target.project_name,
            repo_name,
            branch_name,
            ", ".join(inventory_types) or "(unknown)",
            ", ".join(normalized_application_types),
        )
        return None

    metadata = extract_mobile_metadata(contents)
    activity = fetch_repo_activity(
        client=client,
        project_name=target.project_name,
        repo_id=repo_id,
        branch_name=branch_name,
        max_commits=max_commits_per_repo,
        activity_mode=activity_mode,
    )

    return build_scan_row(
        target=target,
        branch_name=branch_name,
        metadata=metadata,
        contents=contents,
        paths=paths,
        activity=activity,
        confidence=confidence,
        score=score,
        categories=categories,
        evidence=evidence,
        branch_age_days=branch_age_days,
        store_client=store_client,
    )


def build_scan_row(
    target: RepoScanTarget,
    branch_name: str,
    metadata: MobileAppMetadata,
    contents: dict[str, str],
    paths: list[str],
    activity: RepoActivityMetadata,
    confidence: str,
    score: int,
    categories: list[str],
    evidence: list[DetectionEvidence],
    branch_age_days: int,
    store_client: StoreLookupClient | None,
) -> dict[str, Any]:
    repo = target.repo
    age_bucket = branch_age_bucket(activity.last_updated, branch_age_days)
    store_metadata = store_columns(metadata.identifier, categories, store_client)
    source_url = repo_source_url(repo)
    inventory_name = inventory_name_from_metadata(metadata, contents, repo.get("name", ""))
    inventory_version = inventory_version_from_metadata(metadata, contents)
    inventory_types = inventory_types_from_categories(categories)
    primary_language = primary_language_for_branch(contents, paths, categories)
    scanner_target = scanner_target_ref(source_url, branch_name)
    sonarqube_project_key = sonar_project_key(target.project_name, repo.get("name", ""), branch_name)
    branch_contributing_developers = "; ".join(activity.contributing_developers)
    return {
        "provider": target.provider,
        "organization": target.organization,
        "project": target.project_name,
        "repo_name": repo.get("name", ""),
        "branch_name": branch_name,
        "branch_last_updated": activity.last_updated,
        "branch_age_bucket": age_bucket,
        "web_url": repo.get("webUrl", ""),
        "source_url": source_url,
        "inventory_name": inventory_name,
        "inventory_version": inventory_version,
        "inventory_types": "; ".join(inventory_types),
        "primary_language": primary_language,
        "scanner_target": scanner_target,
        "semgrep_target": scanner_target,
        "sonarqube_project_key": sonarqube_project_key,
        "sonarqube_project_name": inventory_name,
        "mobile_name": metadata.name,
        "mobile_version": metadata.version,
        "mobile_identifier": metadata.identifier,
        "mobile_identifier_source": metadata.identifier_source,
        "mobile_identifier_status": identifier_status(metadata.identifier),
        "branch_contributing_developers": branch_contributing_developers,
        "contributing_developers": branch_contributing_developers,
        "last_updated": activity.last_updated,
        "confidence": confidence,
        "score": score,
        "categories": "; ".join(categories),
        **type_columns(inventory_types),
        **category_columns(categories),
        **store_metadata,
        "detection_evidence": json.dumps([item.as_dict() for item in evidence], sort_keys=True),
    }


def row_sort_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("organization", "")).lower(),
        str(row.get("project", "")).lower(),
        str(row.get("repo_name", "")).lower(),
        str(row.get("branch_name", "")).lower(),
    )


def log_detected_result(result: dict[str, Any]) -> None:
    LOGGER.info(
        "DETECTED asset=%s version=%s id=%s types=%s confidence=%s repo=%s/%s/%s branch=%s age=%s categories=%s",
        result["inventory_name"] or "(unknown)",
        result["inventory_version"] or "(unknown)",
        result["mobile_identifier"] or "(not_applicable)",
        result["inventory_types"] or "(unknown)",
        result["confidence"],
        result.get("organization", ""),
        result["project"],
        result["repo_name"],
        result["branch_name"],
        result["branch_age_bucket"],
        result["categories"],
    )


def create_store_client(config: ScanConfig) -> StoreLookupClient | None:
    if not config.store_lookup:
        return None
    return StoreLookupClient(config.store_country, config.store_timeout_seconds)


def branch_name_from_ref(ref_name: str) -> str:
    prefix = "refs/heads/"
    if ref_name.startswith(prefix):
        return ref_name[len(prefix):]
    return ref_name


def default_branch_name_from_repo(repo: dict[str, Any]) -> str:
    return branch_name_from_ref(str(repo.get("defaultBranch") or ""))


def fallback_branch_name(client: AzureDevOpsClient, target: RepoScanTarget) -> str:
    repo = target.repo
    repo_id = str(repo.get("id") or "")
    repo_name = str(repo.get("name") or "")
    try:
        refs = client.list_branches(target.project_name, repo_id)
    except AzureDevOpsError as exc:
        LOGGER.info("Could not list fallback branches for %s/%s: %s", target.project_name, repo_name, exc)
        return ""

    branch_names = branch_names_from_refs(refs)
    if not branch_names:
        LOGGER.info("No fallback branches found for %s/%s", target.project_name, repo_name)
        return ""

    pipeline_branch = pipeline_fallback_branch_name(client, target, branch_names)
    if pipeline_branch:
        LOGGER.info(
            "Using pipeline-associated fallback branch for %s/%s: %s",
            target.project_name,
            repo_name,
            pipeline_branch,
        )
        return pipeline_branch

    selected = select_fallback_branch_name(branch_names)
    if selected:
        LOGGER.info(
            "Using deployment-name fallback branch for %s/%s: %s",
            target.project_name,
            repo_name,
            selected,
        )
    return selected


def pipeline_fallback_branch_name(
    client: AzureDevOpsClient,
    target: RepoScanTarget,
    branch_names: list[str],
) -> str:
    repo = target.repo
    repo_id = str(repo.get("id") or "")
    repo_name = str(repo.get("name") or "")
    try:
        definitions = client.list_build_definitions_for_repo(target.project_name, repo_id)
    except AzureDevOpsError as exc:
        LOGGER.debug(
            "Could not inspect build definitions for %s/%s: %s",
            target.project_name,
            repo_name,
            exc,
        )
        return ""
    return select_pipeline_branch_name(branch_names, branch_names_from_build_definitions(definitions))


def branch_names_from_refs(refs: Iterable[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        name = branch_name_from_ref(str(ref.get("name") or ""))
        key = name.lower()
        if name and key not in seen:
            names.append(name)
            seen.add(key)
    return names


def branch_names_from_build_definitions(definitions: Iterable[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for definition in definitions:
        repository = definition.get("repository") if isinstance(definition.get("repository"), dict) else {}
        names.extend(extract_branch_values([repository.get("defaultBranch")]))
        for trigger in definition.get("triggers") or []:
            if not isinstance(trigger, dict):
                continue
            filters = trigger.get("branchFilters") or []
            names.extend(extract_branch_values([filters] if isinstance(filters, str) else filters))
    return [name for name in names if name]


def extract_branch_values(values: Iterable[Any]) -> list[str]:
    names: list[str] = []
    for value in values:
        raw_value = str(value or "").strip()
        if not raw_value or raw_value.startswith("-") or "*" in raw_value:
            continue
        if raw_value.startswith("+"):
            raw_value = raw_value[1:]
        name = branch_name_from_ref(raw_value)
        if name:
            names.append(name)
    return names


def select_pipeline_branch_name(branch_names: list[str], pipeline_branch_names: Iterable[str]) -> str:
    available = {branch.lower(): branch for branch in branch_names}
    counts: Counter[str] = Counter()
    for candidate in pipeline_branch_names:
        branch_name = available.get(candidate.lower())
        if branch_name:
            counts[branch_name] += 1
    if not counts:
        return ""

    ranked = sorted(
        counts,
        key=lambda branch: (
            -branch_deployment_score(branch),
            -counts[branch],
            branch.count("/"),
            len(branch),
            branch.lower(),
        ),
    )
    selected = ranked[0]
    if branch_deployment_score(selected) or len(counts) == 1:
        return selected
    return ""


def select_fallback_branch_name(branch_names: list[str]) -> str:
    candidates = [branch for branch in branch_names if branch_deployment_score(branch)]
    if not candidates:
        return ""
    return sorted(
        candidates,
        key=lambda branch: (
            -branch_deployment_score(branch),
            -int(is_direct_deployment_branch_name(branch)),
            branch.count("/"),
            len(branch),
            branch.lower(),
        ),
    )[0]


def branch_deployment_score(branch_name: str) -> int:
    direct_keys, token_keys = branch_name_match_keys(branch_name)
    for keyword, score in FALLBACK_BRANCH_PRIORITY:
        if normalized_branch_key(keyword) in direct_keys:
            return score
    for keyword, score in FALLBACK_BRANCH_PRIORITY:
        if normalized_branch_key(keyword) in token_keys:
            return score
    return 0


def is_direct_deployment_branch_name(branch_name: str) -> bool:
    direct_keys, _ = branch_name_match_keys(branch_name)
    return any(
        normalized_branch_key(keyword) in direct_keys
        for keyword, _ in FALLBACK_BRANCH_PRIORITY
    )


def branch_name_match_keys(branch_name: str) -> tuple[set[str], set[str]]:
    lowered = branch_name_from_ref(branch_name).strip().lower()
    last_segment = lowered.rsplit("/", 1)[-1]
    direct_keys = {
        lowered,
        last_segment,
        normalized_branch_key(lowered),
        normalized_branch_key(last_segment),
    }
    token_keys = {
        normalized_branch_key(token)
        for token in re.split(r"[^a-z0-9]+", lowered)
        if token
    }
    return direct_keys, token_keys


def normalized_branch_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def branch_age_bucket(
    last_updated: str,
    branch_age_days: int,
    now: datetime | None = None,
) -> str:
    updated_at = parse_ado_datetime(last_updated)
    if updated_at is None:
        return older_sheet_name(branch_age_days)
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=branch_age_days)
    if updated_at >= cutoff:
        return active_sheet_name(branch_age_days)
    return older_sheet_name(branch_age_days)


def identifier_status(identifier: str) -> str:
    if identifier:
        return "found"
    return "missing_from_scanned_files"


def category_columns(categories: Iterable[str]) -> dict[str, str]:
    category_set = set(categories)
    return {
        f"category_{category}": "TRUE" if category in category_set else "FALSE"
        for category in KNOWN_CATEGORIES
    }


def type_columns(inventory_types: Iterable[str]) -> dict[str, str]:
    type_set = set(inventory_types)
    return {
        f"type_{inventory_type}": "TRUE" if inventory_type in type_set else "FALSE"
        for inventory_type in KNOWN_INVENTORY_TYPES
    }


def inventory_types_from_categories(categories: Iterable[str]) -> list[str]:
    category_set = set(categories)
    types: list[str] = []
    if category_set & {
        "android",
        "ios",
        "flutter",
        "react_native",
        "ionic_capacitor_cordova",
        "xamarin_maui",
        "pipeline_mobile",
    }:
        types.append("mobile_app")
    if category_set & {"web_frontend", "web_backend"}:
        types.append("web_app")
    if "api_service" in category_set:
        types.append("api_service")
    if "microservice" in category_set or "containerized_service" in category_set:
        types.append("microservice")
    if "middleware" in category_set:
        types.append("middleware")
    if "serverless" in category_set:
        types.append("serverless")
    if "android_library" in category_set:
        types.append("library")
    if "infrastructure_as_code" in category_set:
        types.append("infrastructure")
    if category_set & {
        "ai_enabled",
        "ml_enabled",
        "llm_integration",
        "ai_orchestration",
        "ml_inference",
        "vector_search",
        "ai_service_integration",
    }:
        types.append("ai_enabled")
    if category_set & {"ml_enabled", "ml_inference"}:
        types.append("ml_enabled")
    return [inventory_type for inventory_type in KNOWN_INVENTORY_TYPES if inventory_type in types]


def normalize_application_types(application_types: Iterable[str] | None) -> tuple[str, ...]:
    if not application_types:
        return ()
    requested = {str(application_type).strip() for application_type in application_types if str(application_type).strip()}
    unknown = sorted(requested - set(KNOWN_INVENTORY_TYPES))
    if unknown:
        valid = ", ".join(KNOWN_INVENTORY_TYPES)
        raise ValueError(f"Unknown application type {', '.join(unknown)}. Use: {valid}")
    return tuple(application_type for application_type in KNOWN_INVENTORY_TYPES if application_type in requested)


def inventory_type_matches(inventory_types: Iterable[str], application_types: Iterable[str] | None) -> bool:
    normalized_application_types = normalize_application_types(application_types)
    if not normalized_application_types:
        return True
    return bool(set(inventory_types) & set(normalized_application_types))


def store_lookup_allowed(application_types: Iterable[str] | None) -> bool:
    normalized_application_types = normalize_application_types(application_types)
    return not normalized_application_types or "mobile_app" in normalized_application_types


def log_scan_progress(
    repositories_prepared: int,
    repositories_total: int,
    branches_scanned: int,
    branches_total: int,
) -> None:
    LOGGER.info(
        "SCAN_PROGRESS %s",
        json.dumps(
            {
                "repositoriesPrepared": max(0, repositories_prepared),
                "repositoriesTotal": max(0, repositories_total),
                "branchesScanned": max(0, branches_scanned),
                "branchesTotal": max(0, branches_total),
            },
            separators=(",", ":"),
        ),
    )


def repo_source_url(repo: dict[str, Any]) -> str:
    return clean_value(repo.get("remoteUrl")) or clean_value(repo.get("sshUrl")) or clean_value(repo.get("webUrl"))


def scanner_target_ref(source_url: str, branch_name: str) -> str:
    if not source_url:
        return ""
    if not branch_name:
        return source_url
    return f"{source_url}#branch={branch_name}"


def sonar_project_key(project_name: str, repo_name: str, branch_name: str) -> str:
    raw = ":".join(part for part in (project_name, repo_name, branch_name) if part)
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "-", raw).strip(".:-_")
    if not cleaned:
        return "application-inventory"
    if cleaned.isdigit():
        return f"appsec-{cleaned}"
    return cleaned[:400]


def inventory_name_from_metadata(metadata: MobileAppMetadata, contents: dict[str, str], repo_name: str) -> str:
    return first_manifest_value(
        metadata.name,
        package_json_value(contents, "name"),
        pyproject_value(contents, "name"),
        pom_xml_value(contents, "artifactId"),
        csproj_value(contents, "AssemblyName"),
        pubspec_value(contents, "name"),
        repo_name,
    )


def inventory_version_from_metadata(metadata: MobileAppMetadata, contents: dict[str, str]) -> str:
    return first_manifest_value(
        metadata.version,
        clean_version(package_json_value(contents, "version")),
        clean_version(pyproject_value(contents, "version")),
        clean_version(pom_xml_value(contents, "version")),
        clean_version(csproj_value(contents, "Version")),
        clean_version(pubspec_value(contents, "version")),
    )


def primary_language_for_branch(
    contents: dict[str, str],
    paths: Iterable[str],
    categories: Iterable[str],
) -> str:
    lower_paths = [path.lower() for path in paths]
    category_set = set(categories)
    if "flutter" in category_set or any(path.endswith("/pubspec.yaml") for path in lower_paths):
        return "Dart"
    if any(path.endswith(".csproj") for path in lower_paths):
        return "C#"
    if any(path.endswith("/pom.xml") or path.endswith("/build.gradle") or path.endswith("/build.gradle.kts") for path in lower_paths):
        return "Java/Kotlin"
    if any(path.endswith("/requirements.txt") or path.endswith("/pyproject.toml") or path.endswith("/pipfile") for path in lower_paths):
        return "Python"
    if any(path.endswith("/go.mod") for path in lower_paths):
        return "Go"
    if any(path.endswith("/cargo.toml") for path in lower_paths):
        return "Rust"
    if any(path.endswith("/composer.json") for path in lower_paths):
        return "PHP"
    if any(path.endswith("/gemfile") for path in lower_paths):
        return "Ruby"
    if any(path.endswith("/package.json") for path in lower_paths):
        return package_json_language(contents)
    return ""


def package_json_language(contents: dict[str, str]) -> str:
    if any(path.lower().endswith("/tsconfig.json") for path in contents):
        return "TypeScript"
    dependencies = merged_package_dependency_names(contents)
    if dependencies & {"typescript", "ts-node", "@types/node"}:
        return "TypeScript"
    return "JavaScript"


def merged_package_dependency_names(contents: dict[str, str]) -> set[str]:
    for path, content in contents.items():
        if path.lower().endswith("package.json"):
            data = load_json_object(content)
            names: set[str] = set()
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                dependencies = data.get(key)
                if isinstance(dependencies, dict):
                    names.update(str(name) for name in dependencies)
            return names
    return set()


def first_manifest_value(*values: str) -> str:
    for value in values:
        cleaned = clean_value(value)
        if cleaned:
            return cleaned
    return ""


def package_json_value(contents: dict[str, str], key: str) -> str:
    for path, content in contents.items():
        if path.lower().endswith("package.json"):
            return clean_value(load_json_object(content).get(key))
    return ""


def pyproject_value(contents: dict[str, str], key: str) -> str:
    pattern = re.compile(rf"(?m)^\s*{re.escape(key)}\s*=\s*['\"]([^'\"]+)['\"]")
    for path, content in contents.items():
        if path.lower().endswith("pyproject.toml"):
            match = pattern.search(content)
            if match:
                return clean_value(match.group(1))
    return ""


def pom_xml_value(contents: dict[str, str], tag_name: str) -> str:
    for path, content in contents.items():
        if path.lower().endswith("pom.xml"):
            value = xml_text(content, tag_name)
            if value:
                return value
    return ""


def csproj_value(contents: dict[str, str], tag_name: str) -> str:
    for path, content in contents.items():
        if path.lower().endswith(".csproj"):
            value = xml_text(content, tag_name)
            if value:
                return value
    return ""


def pubspec_value(contents: dict[str, str], key: str) -> str:
    for path, content in contents.items():
        if path.lower().endswith("pubspec.yaml"):
            value = yaml_scalar(content, key)
            if value:
                return value
    return ""


def fetch_repo_activity(
    client: AzureDevOpsClient,
    project_name: str,
    repo_id: str,
    branch_name: str,
    max_commits: int,
    activity_mode: str,
) -> RepoActivityMetadata:
    try:
        commit_limit = 1 if activity_mode == "latest" else max_commits
        commits = client.list_commits(
            project_name=project_name,
            repo_id=repo_id,
            max_commits=commit_limit,
            branch_name=branch_name,
        )
    except AzureDevOpsError as exc:
        LOGGER.info("Could not fetch commit activity for %s/%s@%s: %s", project_name, repo_id, branch_name, exc)
        return RepoActivityMetadata()

    activity = extract_repo_activity(commits)
    if activity_mode == "latest":
        return RepoActivityMetadata(last_updated=activity.last_updated)
    return activity


def fetch_contents(
    client: AzureDevOpsClient,
    project_name: str,
    repo_id: str,
    branch_name: str,
    paths: list[str],
    executor: ThreadPoolExecutor,
) -> dict[str, str]:
    if not paths:
        return {}

    contents: dict[str, str] = {}
    futures = {
        executor.submit(client.fetch_file_content, project_name, repo_id, path, branch_name): path
        for path in paths
    }
    for future in as_completed(futures):
        path = futures[future]
        content = future.result()
        if content:
            contents[path] = content
    return contents


def collect_targets(
    client: AzureDevOpsClient | GitHubEnterpriseClient,
    project_name: str | None,
    target_filters: Iterable[SourceTargetFilter] = (),
) -> list[RepoScanTarget]:
    organization = source_organization(client)
    provider = source_provider(client)
    project_names = selected_project_names(organization, project_name, target_filters)
    projects = [{"name": name} for name in project_names] if project_names else client.list_projects()
    targets: list[RepoScanTarget] = []
    seen_repo_ids: set[str] = set()

    for project in projects:
        name = project.get("name")
        if not name:
            continue

        LOGGER.info("Listing repositories in project: %s", name)
        try:
            repos = client.list_repos(name)
        except Exception as exc:
            LOGGER.warning("Failed to list repos for %s: %s", name, exc)
            continue

        for repo in repos:
            repo_id = repo.get("id")
            if not repo_id or repo_id in seen_repo_ids:
                continue
            seen_repo_ids.add(repo_id)
            targets.append(RepoScanTarget(project_name=name, repo=repo, organization=organization, provider=provider))

    return targets


def source_organization(client: AzureDevOpsClient | GitHubEnterpriseClient) -> str:
    return str(getattr(client, "org", "") or getattr(client, "owner", ""))


def source_provider(client: AzureDevOpsClient | GitHubEnterpriseClient) -> str:
    return "github-enterprise" if isinstance(client, GitHubEnterpriseClient) else "azure-devops"


def selected_project_names(
    organization: str,
    project_name: str | None,
    target_filters: Iterable[SourceTargetFilter] = (),
) -> list[str]:
    filters = tuple(target_filters or ())
    if filters:
        return dedupe_values(
            target_filter.project
            for target_filter in filters
            if target_filter_matches_source(target_filter.org, organization)
        )
    return [project_name] if project_name else []


def target_filters_for_source(
    target_filters: Iterable[SourceTargetFilter],
    organization: str,
) -> tuple[SourceTargetFilter, ...]:
    return tuple(
        target_filter
        for target_filter in target_filters
        if target_filter_matches_source(target_filter.org, organization)
    )


def target_filter_matches_source(filter_org: str, organization: str) -> bool:
    return not filter_org or filter_org.lower() == organization.lower()


def dedupe_values(values: Iterable[str]) -> list[str]:
    deduped: dict[str, str] = {}
    for value in values:
        cleaned = clean_value(value)
        if cleaned:
            deduped[cleaned.lower()] = cleaned
    return list(deduped.values())


def iter_completed_branch_target_lists(
    repo_executor: ThreadPoolExecutor,
    client: AzureDevOpsClient,
    targets: list[RepoScanTarget],
    max_in_flight: int,
) -> Iterable[tuple[int, Future[list[BranchScanTarget]]]]:
    target_iter = iter(targets)
    pending: set[Future[list[BranchScanTarget]]] = set()
    submitted = 0
    completed = 0

    def submit_next() -> bool:
        nonlocal submitted
        try:
            target = next(target_iter)
        except StopIteration:
            return False
        pending.add(repo_executor.submit(list_branch_targets, client, target))
        submitted += 1
        return True

    for _ in range(max(1, max_in_flight)):
        if not submit_next():
            break

    while pending:
        done, pending = wait(pending, return_when=FIRST_COMPLETED)
        for future in done:
            completed += 1
            yield completed, future

        while len(pending) < max_in_flight and submitted < len(targets):
            if not submit_next():
                break
