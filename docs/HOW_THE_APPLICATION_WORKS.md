# How AppSec Atlas Works

## Purpose

AppSec Atlas provides one operating view of application ownership, scanner findings, contextual risk, security-tool coverage, and remediation work. It combines data from Azure DevOps, GitHub, PostgreSQL, and security scanners without cloning or executing application source code.

The application answers five questions:

1. What applications and services exist?
2. Who owns them and where are they deployed?
3. What security findings affect them?
4. Which findings should be addressed first?
5. Which applications are missing current scanner coverage?

## The Core Model

The system separates application discovery from security testing.

| Data set | Created by | What it represents |
| --- | --- | --- |
| Inventory | Azure DevOps and GitHub scans | Repositories, branches, application identities, types, languages, owners, contributors, domains, activity, and mobile metadata |
| Findings | Scanner-result imports | Normalized vulnerabilities and security issues from SARIF, Semgrep, SonarQube, and other tools |
| Security profiles | User-managed context | Criticality, internet exposure, data classification, business ownership, technical ownership, and tags |
| Coverage | Scanner-result imports correlated to inventory | Which tools evaluated each application branch and how recently |
| Workflow | User actions and complete scanner snapshots | Finding status, assignment, due date, notes, resolution, and audit history |

Inventory is the application identity layer. Findings are linked to inventory when their provider, organization, project, repository, and branch identify one application unambiguously. Findings remain visible as **unlinked** when the source information is incomplete or ambiguous.

## End-to-End Flow

```mermaid
flowchart LR
    User["Security or platform user"] --> UI["ASPM web application"]
    UI --> InventoryScan["Inventory scan"]
    InventoryScan --> ADO["Azure DevOps"]
    InventoryScan --> GitHub["GitHub"]
    ADO --> NormalizeAssets["Normalize application assets"]
    GitHub --> NormalizeAssets
    NormalizeAssets --> PostgreSQL["PostgreSQL"]
    PostgreSQL --> Inventory["Inventory view"]
    NormalizeAssets --> Targets["Semgrep and SonarQube targets"]
    Targets --> Scanners["Security scanners"]
    Scanners --> Import["SARIF, Semgrep, SonarQube, or generic import"]
    Import --> NormalizeFindings["Normalize and deduplicate findings"]
    NormalizeFindings --> Correlate["Correlate to application branches"]
    Correlate --> Risk["Calculate contextual risk"]
    Risk --> Workflow["Triage and remediation workflow"]
    Correlate --> Coverage["Scanner coverage"]
    Workflow --> PostgreSQL
    Coverage --> PostgreSQL
    PostgreSQL --> Posture["Posture, Findings, and Coverage views"]
```

An inventory scan does not run Semgrep, SonarQube, or another security scanner. It discovers applications and produces scanner target files. Scanner pipelines can return result files, while configured Semgrep Enterprise, Invicti, NowSecure, SonarQube, and OWASP ZAP connectors can pull current findings directly. Semgrep Community output is imported as `semgrep --json`; Trivy, Gitleaks, Nuclei, and OWASP Dependency-Check output is imported as SARIF.

## What Happens During an Inventory Scan

1. The user signs in and chooses Azure DevOps, GitHub, or both providers.
2. The service validates the configured credentials and retrieves accessible projects or repositories.
3. The user can select a smaller scope or leave the filters empty to scan every accessible project and repository. Azure DevOps full scans include hidden repositories visible to the PAT.
4. The scanner selects each repository's default branch. When no default branch is available, it checks configured production-like fallback names.
5. Disabled and branchless repositories remain in the inventory with explicit status values instead of being discarded.
6. The service reads the repository tree and a bounded set of relevant manifests and configuration files through provider APIs.
7. Detection rules classify the application as mobile, web, API, microservice, middleware, serverless, library, infrastructure, AI-enabled, or ML-enabled.
8. Structured manifests provide the application name, version, identifier, language, framework, deployment-domain evidence, and mobile metadata when those values exist.
9. Commit history supplies contributors and the latest branch activity.
10. Optional store validation checks detected mobile identifiers in the selected Apple and Google country stores.
11. Results stream into PostgreSQL and the report writer while the scan is running.

The scanner updates the current record for an unchanged source branch instead of adding a duplicate row. Normalized child tables hold application types, categories, contributors, domains, store listings, and other repeating values.

## What Happens During a Finding Import

The application accepts four input families:

- SARIF 2.1
- Semgrep JSON
- SonarQube issue JSON
- Generic normalized JSON for SAST, SCA, secrets, IaC, DAST, CSPM, and custom tools

For every import, the service:

1. Detects or validates the file format.
2. Normalizes the tool identity, severity, status, source location, rule, package, CWE, CVE, CVSS, EPSS, exploit evidence, and remediation text.
3. Creates a deterministic SHA-256 fingerprint from the tool and finding identity.
4. Inserts a new finding or updates the matching existing finding.
5. Correlates the finding by exact repository identity, mobile package identifier, or web domain, with exact application name as a guarded fallback.
6. Extracts data-interaction evidence from structured scanner metadata, privacy categories, regulations, CWE mappings, and bounded finding text.
7. Recalculates the linked asset's technical, data-sensitivity, and context risk components.
8. Loads the linked application's security profile.
9. Calculates and stores an explainable risk score.
10. Updates scanner coverage for matched application branches.
11. Records the import and workflow history for audit purposes.

File imports are transactional. Direct connectors use bounded page transactions so very large snapshots do not accumulate in memory. Failed connector syncs are audited and never reconcile absent findings from an incomplete pull.

### Complete and Partial Imports

A partial import adds or updates findings but never resolves findings that are absent from the file.

A **complete snapshot** states that the file contains the scanner's complete current result set for the declared targets. Active findings missing from that snapshot are resolved automatically. Accepted-risk and false-positive decisions are preserved. A previously resolved finding reopens if it appears in a later active result set.

Use complete snapshots only for trusted pipeline output with explicit scanned targets.

## Contextual Risk

Every finding receives a score from 0 to 100. The score is intentionally explainable: the finding record stores each factor and the points it contributed.

| Factor | Maximum contribution |
| --- | ---: |
| Scanner severity | 48 |
| CVSS score | 12 |
| EPSS probability | 10 |
| Known exploit | 12 |
| Internet exposure | 10 |
| Application criticality | 15 |
| Data classification | 10 |
| Finding age | 8 |

The combined score is capped at 100 and mapped to these bands:

| Score | Band |
| ---: | --- |
| 85-100 | Critical |
| 65-84 | High |
| 35-64 | Medium |
| 0-34 | Low |

Default due dates are based on normalized severity:

| Severity | Default remediation period |
| --- | ---: |
| Critical | 7 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |
| Informational | 365 days |

Users set per-severity remediation periods in **Configuration** > **Remediation timelines**. Saving a policy recalculates policy-managed due dates without replacing a manually set due date.

Updating an application's criticality, exposure, or data classification recalculates every linked finding in the same database transaction.

## Finding Lifecycle

The remediation workflow supports these states:

```mermaid
stateDiagram-v2
    [*] --> open
    open --> triaged
    open --> in_progress
    triaged --> open
    triaged --> in_progress
    in_progress --> open
    in_progress --> triaged
    open --> resolved
    open --> accepted
    open --> false_positive
    triaged --> resolved
    triaged --> accepted
    triaged --> false_positive
    in_progress --> resolved
    in_progress --> accepted
    in_progress --> false_positive
    resolved --> open
    accepted --> open
    false_positive --> open
```

Open, triaged, and in-progress findings can move among active states or into a terminal state. Resolved, accepted, and false-positive findings can be reopened. Direct transitions between terminal states are rejected so that the audit history remains clear.

Every workflow update can include:

- Assignee or responsible team
- Due date
- Decision or remediation note
- Acting user
- Prior and new status
- Timestamp

## Scanner Coverage

Coverage is calculated per application branch and security tool.

| Status | Meaning |
| --- | --- |
| Current | Scanned within the last 30 days |
| Stale | Last scanned 31 to 90 days ago |
| Expired or untested | Last scanned more than 90 days ago, or never scanned |

Coverage requires enough repository context to link the scanner result or declared scan target to inventory. An unlinked finding remains actionable, but it does not prove that an application received scanner coverage.

## Application Pages

### Dashboard

The Dashboard is the default executive view. It summarizes critical and high findings, affected applications, overdue work, current scanner coverage, and average active risk. Critical, high, and overdue metrics open matching Findings; affected applications opens Inventory; coverage opens Coverage; and average risk opens active Asset risk profiles.

Priority applications open Findings filtered to that exact application branch. Workflow totals, including open, resolved, and triaged, open Findings filtered to the selected status. Tool health shows the latest import or connector sync, not the result of a connection test.

An overdue finding is active and past its configured due date. Configure severity timelines in **Configuration** > **Remediation timelines**; policy updates recalculate policy-managed dates while preserving manual finding due dates.

Use this page for daily risk review and leadership reporting.

### Findings

This is the deduplicated remediation queue. Users can:

- Import scanner results.
- Search by finding, rule, repository, package, CWE, or CVE.
- Filter by severity, status, tool, overdue state, assignment, or linkage.
- Open a finding to review risk factors and technical evidence.
- Assign work, change status, set due dates, and add audit notes.
- Export the active filter as XLSX, CSV, or JSON.

### Inventory

Inventory shows every repository retained by a full scan and separates repository count, inventory-record count, and classified-application count. `inventory_status` identifies classified, candidate, unclassified, empty, disabled, unavailable, branchless, and failed records. The table supports search, structured filters, sorting, pagination, record counts, and exports. Repository names link back to Azure DevOps or GitHub when a provider URL is available.

Opening a record shows ownership, contributors, activity, application types, domains, scanner targets, and mobile metadata when relevant.

### Coverage

Coverage identifies applications with current, stale, expired, or missing scanner evidence. It is designed to answer both "where do we have findings?" and "where have we not tested recently?"

### Scan

This page configures inventory discovery. The normal flow is:

1. Choose Azure DevOps, GitHub, or both.
2. Add the required organizations or owners.
3. Load projects or repositories when a targeted scan is needed.
4. Select application types and relevant options.
5. Run the scan.

Empty project or repository filters mean "scan every accessible target."

### Runs

Runs shows queued, active, paused, completed, stopped, and failed inventory scans. A failed run can be retried with its original configuration. The retry is a separate, linked attempt, so the prior run's exit code, logs, reports, and failure evidence remain intact. Logs stream while a scan is active. Failure messages are separated from normal output and written to durable log files. Detached scan workers continue when the browser closes and reconnect when the UI returns.

### Schedules

Schedules stores encrypted, user-scoped one-time, daily, or weekly inventory scan definitions. Scheduled work enters the same bounded runtime as an interactive scan.

### Reports

Reports provides access to completed inventory outputs and scan logs. Inventory runs produce XLSX reports plus Semgrep and SonarQube target files for downstream automation.

### Configuration

Configuration displays database connectivity and configuration health. PostgreSQL is tested when the service starts, and the UI reports whether inventory, findings, coverage, and observability storage are ready.

It also manages GitHub App status, remediation timelines, scanner connections, and webhooks. Scanner setup values and webhook credentials are encrypted per user and are never returned after saving. **Test connections** makes a lightweight request to remote scanners without importing findings; use **Sync** to collect and correlate findings. SARIF profiles record where Trivy, Gitleaks, Nuclei, or OWASP Dependency-Check output is produced, then their files are uploaded from **Findings**.

## Authentication and Data Isolation

The browser requires a signed-in session. GitHub Enterprise and Google OAuth can be enabled for production; test login is intended only for local development.

User-owned data is scoped by a stable owner identifier in PostgreSQL. Inventory searches, findings, workflow updates, coverage, reports, schedules, saved credentials, and exports use that scope. Browser requests require both the authenticated session and a CSRF token.

Saved credentials, schedules, webhooks, scanner overrides, and remediation timelines are encrypted at rest with the configured Fernet key. Provider secrets and GitHub App private keys are not included in generated scan commands, reports, or browser responses.

## Persistence and Recovery

- PostgreSQL stores current inventory, findings, security profiles, workflow history, coverage, scan records, and observability events.
- The reports directory stores generated files, encrypted run state, encrypted schedules, and scan logs.
- Inventory writes use upserts so repeated scans update current state rather than duplicating unchanged records.
- Scan workers run separately from the browser and UI process.
- The UI can recover and display a verified detached worker after a restart.
- Production deployments must use durable storage for both PostgreSQL and the reports/state directory.

## Automation Interfaces

The same capabilities are available outside the browser:

| Interface | Best use |
| --- | --- |
| Inventory CLI | CI jobs, scheduled discovery, and non-interactive exports |
| ASPM CLI | Finding imports, filtered queries, workflow updates, profiles, and exports |
| Python SDK | Integration with orchestration services and internal platforms |
| Authenticated HTTP API | The first-party browser and approved service integrations |
| Docker dispatcher | Containerized inventory and ASPM commands |

Example ASPM commands:

```bash
export APPLICATION_INVENTORY_POSTGRES_DSN="postgresql://app_user:secret@postgres:5432/appsec"

appsec-atlas-aspm --owner-user-id security-platform posture
appsec-atlas-aspm --owner-user-id security-platform findings --severity critical --status open
appsec-atlas-aspm --owner-user-id security-platform ingest results.sarif --tool-key codeql --complete-snapshot
```

## Recommended Operating Cycle

1. Run inventory discovery daily or weekly, depending on repository change volume.
2. Run security scanners in their existing CI/CD pipelines.
3. Import each tool's complete result set after a successful scanner run.
4. Review Dashboard for critical, high, and overdue risk.
5. Triage unlinked findings and improve pipeline repository context.
6. Assign and track remediation through Findings.
7. Review Coverage for stale and untested applications.
8. Export filtered data for governance, audit, or downstream reporting.

## Important Boundaries

- The application orchestrates inventory and security posture; it does not replace the underlying security scanners.
- Repository detection relies on source metadata and structured files. Missing application names, versions, identifiers, or domains mean the repository did not expose reliable evidence.
- Application-store validation applies only to mobile applications with a detected identifier.
- Finding correlation is intentionally conservative. Ambiguous findings remain unlinked instead of being attached to the wrong application.
- A complete snapshot can resolve findings and should be restricted to trusted automation.
- Local PostgreSQL defaults and test login are development conveniences, not production settings.

For scanner payload contracts and operator commands, see [ASPM Operations Guide](ASPM_OPERATIONS.md). For infrastructure and trust boundaries, see [Architecture](ARCHITECTURE.md). For production deployment, see the [AWS](AWS_DEPLOYMENT.md) and [Azure](AZURE_IMPLEMENTATION.md) guides.
