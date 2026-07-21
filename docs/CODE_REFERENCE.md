# Code Reference

This document identifies module ownership and the principal runtime contracts. The source remains authoritative for signatures and edge cases.

## Package Surfaces

| Surface | Entry point | Purpose |
| --- | --- | --- |
| CLI | `application-inventory-service` | Runs a scan and writes reports for shell automation and CI jobs |
| UI | `application-inventory-service-ui` | Hosts authentication, scan operations, schedules, reports, and database exports |
| SDK | `ApplicationInventoryService` | Embeds the inventory engine in another Python process |
| ASPM SDK | `AspmService` | Embeds finding ingestion, posture, workflow, coverage, profile, and export operations |
| ASPM CLI | `application-inventory-aspm` | Imports scanner results and manages posture, findings, coverage, workflow, profiles, and exports |
| Module | `python -m application_inventory_service` | Executes the same CLI used by the console command |

Compatibility packages and commands delegate to the same implementation. New integrations should import `application_inventory_service` or use the current console commands.

## Module Ownership

### Inventory engine

| Module | Responsibility |
| --- | --- |
| `scanner.py` | Coordinates source, repository, branch, manifest, activity, store, report, and database stages |
| `detection.py` | Converts repository structure and manifest evidence into categories, scores, and confidence |
| `domains.py` | Extracts, normalizes, ranks, deduplicates, and serializes web-domain evidence |
| `metadata.py` | Extracts application names, versions, and mobile identifiers from platform manifests |
| `activity.py` | Reduces commit streams into unique contributors and the latest commit timestamp |
| `models.py` | Defines immutable scan configuration, targets, evidence, metadata, and store records |
| `constants.py` | Owns defaults, supported categories, inventory types, content targets, and report field groups |
| `utils.py` | Supplies bounded parsing and normalization helpers used by the detection pipeline |

`scan`, `scan_to_reports`, `scan_reports`, and `ApplicationInventoryService` are the supported programmatic entry points. A scan returns dictionaries whose keys follow `INVENTORY_FIELDNAMES`. `scan_reports` returns a count and output paths without retaining result rows.

### Provider clients

| Module | Responsibility |
| --- | --- |
| `azure.py` | Azure DevOps REST traversal, connection reuse, retry policy, pacing, and commit streaming |
| `github.py` | GitHub App authentication, installation-token refresh, REST traversal, pagination, and commit streaming |
| `source_access.py` | Builds provider clients and validates every selected source before inventory collection |
| `org_tokens.py` | Parses and serializes Azure organization/PAT pairs |
| `target_filters.py` | Parses and matches source-qualified project and repository filters |
| `source_discovery.py` | Loads selectable projects and repositories concurrently for the UI |
| `store_lookup.py` | Queries Apple App Store and Google Play and validates listing identity |

Provider clients expose a common operational shape: validate access, list projects, repositories, branches, repository items, commits, and selected file content. GitHub additionally exposes bounded successful deployment environment URLs for domain attribution. Source preflight completes before report and PostgreSQL writers open, and the scanner does not require a repository clone.

### Output and persistence

| Module | Responsibility |
| --- | --- |
| `reports.py` | Streams Semgrep and SonarQube targets and checkpoints XLSX workbooks |
| `postgres.py` | Creates and migrates schema objects, performs current-state user-scoped upserts, searches and exports inventory, and stores observability events |
| `inventory_query.py` | Validates immutable structured search criteria and local-assistant query plans |
| `inventory_exports.py` | Writes formula-safe XLSX, CSV, and JSON database exports |
| `local_llm.py` | Converts natural-language requests into allowlisted query plans through a local Ollama endpoint |
| `scan_persistence.py` | Stores encrypted run records and reads private worker completion markers |
| `scan_worker.py` | Executes one detached scanner command and atomically records its exit status |
| `secure_store.py` | Atomically reads and writes Fernet-encrypted JSON state |
| `observability.py` | Configures structured console and PostgreSQL logging |

### Application security posture management

| Module | Responsibility |
| --- | --- |
| `aspm_models.py` | Immutable finding, source-location, severity, workflow, and risk contracts |
| `aspm_ingest.py` | Detects and normalizes SARIF, Semgrep, SonarQube, and generic scanner documents |
| `aspm_risk.py` | Produces bounded explainable risk assessments from findings and application context |
| `aspm_postgres.py` | Owns ASPM schema, atomic imports, correlation, deduplication, workflow events, search, exports, profiles, posture, and coverage |
| `aspm_cli.py` | Provides the dedicated automation CLI without changing the inventory scanner argument contract |
| `ui_static/aspm-ui.js` | Drives posture, finding import/search/workflow, asset context, and scanner coverage views |

`FindingDocument` is the canonical ingestion boundary. `AspmRepository.ingest()` first commits an import audit record, then applies every finding, identifier, coverage, and snapshot change in one transaction. Failure rolls back that transaction and marks the import failed. Asset resolution is cached per source scope during an import, so a large repository result set does not repeat the same inventory lookup for every finding.

`RiskEngine` is deterministic and side-effect free. `AspmRepository` stores the score, band, and complete factor list used for that assessment. Application profile changes rerun the engine for linked findings in one transaction.

The report writer creates all output files at scan start. Text targets flush per finding. XLSX checkpoints use bounded adaptive intervals, atomically replace the prior workbook, and save once more at close. PostgreSQL uses short transactions controlled by row and time thresholds, with a background flush for live visibility. Schema changes are versioned and serialized with a PostgreSQL advisory lock; unchanged schemas use a fast readiness path. Inventory keys include the owning user and source identity, so repeated scans update rows instead of creating duplicate findings. Child types, categories, contributors, web domains, domain sources, and store listings are synchronized by value.

### UI operations

| Module | Responsibility |
| --- | --- |
| `auth.py` | OAuth state, sessions, CSRF tokens, test login, and encrypted provider credentials |
| `runtime.py` | Bounded scan process execution, pause/resume/stop, incremental metrics, live and failure-only logs, event listeners, recovery, and report discovery |
| `scheduling.py` | Encrypted user-scoped schedules, recurrence calculation, due-run dispatch, and schedule lifecycle |
| `scan_request.py` | Normalizes UI scan requests and builds redacted commands and restricted child environments |
| `ui.py` | HTTP routes, owner-scoped database search and export, static delivery, SSE, and service startup |
| `ui_static/app.js` | Browser state, scan configuration, live console, controls, schedules, reports, and database search/export actions |
| `ui_static/styles.css` | Responsive dark interface and operational status presentation |

`ScanManager` admits a bounded number of subprocesses. Extra scans remain queued. On POSIX hosts, each scanner starts in a detached process group so pause, resume, and stop apply to the complete process tree. Run configuration is encrypted, output is appended to a private log, and a replacement manager verifies the saved PID and process group before reconnecting to an active worker. `ScanRun.append_log()` classifies and sequences each line once, publishes it over SSE, and appends failures to an owner-only `failures.log`. Recovery rebuilds that file from the durable scan log before monitoring resumes. Browser sessions are stored in the same encrypted state directory, bounded to 1,000 active records, and removed on logout or expiry.

`ScanScheduler` persists encrypted schedule definitions under the configured state directory. It dispatches due work through the same `ScanManager`, so scheduled and interactive scans share concurrency limits and reporting behavior.

## Scan Sequence

1. CLI or UI input is normalized into `ScanConfig`.
2. Source contexts are created for each Azure organization and GitHub owner.
3. Source contexts and project-level repository discovery run concurrently within configured limits.
4. One default or production-like fallback branch is resolved per repository.
5. Repository trees are read and selected manifests enter a bounded content-fetch queue.
6. Detection produces evidence, categories, confidence, and score.
7. Metadata and commit iterators produce names, versions, identifiers, contributors, and timestamps.
8. Deployable types combine provider deployment URLs, repository metadata, and structured source configuration into ranked domain evidence.
9. Mobile findings receive NowSecure routing metadata; optional store validation runs only when lookup is enabled.
10. Findings stream to reports and PostgreSQL. SDK list-returning calls retain rows; CLI and `scan_reports` calls retain only a count.

## Concurrency Controls

| Control | Default | Scope |
| --- | ---: | --- |
| Source workers | `2` | Azure organizations and GitHub owners |
| Repository workers | `8` | Repository and fallback-branch preparation |
| Branch workers | `16` | Branch inventory analysis |
| Content workers | `16` | Manifest and configuration reads |
| Concurrent scans | `2` | UI and scheduled subprocesses combined |

Repository, branch, and content queues are bounded. Increasing a worker count can improve latency-bound workloads, but provider rate limits remain the primary constraint.

## Data Contracts

`ScanConfig` contains provider credentials, filters, concurrency values, detection thresholds, store settings, output paths, PostgreSQL settings, and user scope. It is frozen after construction.

`DetectionEvidence` records category, source, detail, and weight. Confidence is derived from independent evidence and structural signals rather than a single keyword match.

`RepoActivityMetadata` contains a sorted, deduplicated contributor tuple and the latest normalized UTC timestamp. Commit pages are consumed as iterators to avoid retaining complete histories.

`ScanRun.summary()` is the UI contract for run state. It includes status, source, target, timestamps, active runtime, finding and failure counts, current progress counters, report metadata, and bounded console and failure tails. Secrets are not included.

`ScanSchedule.summary()` is the browser-safe schedule contract. Encrypted scan configuration and credentials never appear in the response.

`search_inventory()` accepts a user scope, bounded search text, literal column filters, structured filters, sort order, limit, and offset. Text uses an indexed PostgreSQL search vector. Filters and sort expressions are allowlisted and parameterized. XLSX, CSV, and JSON exports use the same query path and a server-side cursor.

`LocalInventoryAssistant` sends only the user's question and a fixed field schema to Ollama. `InventoryQueryPlan` drops unknown fields and never accepts SQL. The database layer remains responsible for parameterization, authorization, and owner scope.

## Extension Points

- Add a source provider by implementing the provider-client operational shape and adapting `create_source_client`.
- Add detection evidence in `detection.py`, then map its category to an inventory type in `scanner.py`.
- Add manifest metadata in `metadata.py` and include the filename in `CONTENT_FILES_TO_FETCH`.
- Add an output sink through the per-result callback used by `scan_to_reports` and `scan_reports`.
- Embed the scanner with `ApplicationInventoryService` when subprocess control and the web UI are not required.

## Compatibility Policy

The public imports listed in `appsec_scan_router.__all__`, the current console commands, report field names, and normalized PostgreSQL objects are compatibility surfaces. Internal module placement may change without notice. New code should not depend on private names or browser-local storage keys.
