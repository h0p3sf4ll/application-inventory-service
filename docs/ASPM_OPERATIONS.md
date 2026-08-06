# AppSec Atlas Operations Guide

AppSec Atlas combines branch-level application inventory with normalized scanner findings, contextual risk, scanner coverage, and remediation workflow. Inventory remains the source of application identity. Scanner imports add security state without duplicating application records.

## Operating Model

1. Inventory scans discover repositories, branches, application types, languages, owners, activity, deployment domains, and mobile metadata.
2. Security tools publish files or the service pulls findings through Semgrep Enterprise, Invicti, NowSecure, SonarQube, and OWASP ZAP connectors.
3. The ingestion service normalizes severity, identity, source location, package data, CWE, CVE, CVSS, EPSS, exploit evidence, and remediation metadata.
4. Findings correlate through exact repository identity, mobile package identifier, or web domain. Exact application name is used only when it identifies one asset. Ambiguous matches remain unlinked.
5. A deterministic fingerprint deduplicates findings within a tool. Repeated imports update the existing record and preserve remediation state.
6. The risk engine combines technical severity with application context and records every contributing factor.
7. Teams triage and assign findings through one workflow. Status, assignee, due date, notes, and history remain scoped to the owning account.
8. Coverage records show which applications each scanner evaluated and when.
9. Structured scanner metadata and CWE evidence identify the data categories implicated by a finding.
10. Asset profiles combine technical pressure, data sensitivity, and deployment context without hiding the contributing factors.

## Direct Connectors

| Connector | Collection | Required configuration | Correlation anchors |
| --- | --- | --- | --- |
| Semgrep Enterprise | Deployment findings and projects API | App token | Repository URL, project, repository, branch |
| Semgrep Community | Local `semgrep --json` report | Report location | Upload through **Findings** > **Import findings**; no remote sync |
| Invicti | `/api/1.0/issues/allissues` | User ID and API token; API root is overrideable | Website root domain, website name |
| NowSecure | Platform GraphQL | Platform token | Android package or Apple bundle identifier, application name |
| SonarQube | Issues API | Server URL and user token | Source metadata supplied by the issue |
| OWASP ZAP | Alerts API | API URL and optional API key | Target URL or domain |
| Trivy, Gitleaks, Nuclei, OWASP Dependency-Check | SARIF import profile | Report location | Upload through **Findings** > **Import findings**; no remote sync |

Credentials belong in a deployment secret manager. Do not place them in source control, browser configuration, command output, or scanner metadata. Use **Configuration** > **Scanner connections** to add account-specific values through the setup wizard. Those values are encrypted per user, and secret fields are never returned to the browser. The status API reports only whether a connector is configured and its non-secret endpoint.

Semgrep Enterprise, Invicti, and NowSecure stream bounded API pages into page-sized database commits. Semgrep Enterprise uses zero-based pages of up to 3,000 findings, server-side ref deduplication, and four ordered page-prefetch workers by default. Set `APPLICATION_INVENTORY_SEMGREP_WORKERS` from `1` through `16` to match the vendor rate limit. By default it synchronizes open, reviewing, fixing, and provisionally ignored findings for SAST, SCA, and AI-powered scans. Override `APPLICATION_INVENTORY_SEMGREP_STATUSES` or `APPLICATION_INVENTORY_SEMGREP_ISSUE_TYPES` only when the resulting snapshot semantics are understood. `APPLICATION_INVENTORY_SEMGREP_MAX_FINDINGS` controls the per-sync safety limit and defaults to 5,000,000 for large deployments. Semgrep Community has no hosted connector: run `semgrep --json` and import the generated JSON.

Invicti defaults to `https://www.netsparkercloud.com/api/1.0` and permits an API-root override for private deployments. It prefetches two pages by default to limit tenant throttling, commits ten pages per database batch, and applies a 120-second minimum page timeout. The connector requests `rawDetails=false` to avoid retaining unnecessary request and response content. NowSecure imports affected findings from each application's latest complete assessment and records all assessed applications as coverage targets. SonarQube and OWASP ZAP synchronize remotely; Semgrep Community and SARIF profiles intentionally do not call scanner APIs and must be uploaded from **Findings**.

Use **Test connections** to make a lightweight request to configured remote scanners before synchronization. It does not import findings or update Dashboard tool health. Tool health reflects the latest import or connector sync, so it can retain a historical failure after a successful connection test until a later sync completes.

Remote connector requests retry rate limits and transient upstream errors within each HTTP attempt. DNS, connection, and timeout failures retry the complete request up to `APPLICATION_INVENTORY_CONNECTOR_NETWORK_ATTEMPTS` times with bounded exponential backoff. Retry events are written to application observability logs with redacted endpoints and no credentials.

Vendor references: [Semgrep Enterprise API](https://semgrep.dev/api/v1/docs/), [Invicti API](https://www.netsparkercloud.com/swagger/docs/v1), and [NowSecure findings GraphQL](https://support.nowsecure.com/hc/en-us/articles/21777208143629-Platform-Findings-GraphQL-API).

For implementation and registration guidance, see the [Connector Development Guide](CONNECTOR_DEVELOPMENT.md).

## Supported Inputs

| Format | Detection | Typical source |
| --- | --- | --- |
| SARIF 2.1 | `version` and `runs` | CodeQL, Microsoft security tools, compatible SAST tools |
| Semgrep JSON | `results` | `semgrep --json` |
| SonarQube issues | `issues` | SonarQube Web API issue response |
| Generic | Array or `findings` object | SCA, secrets, DAST, CSPM, custom scanners |

The browser accepts files up to 20 MB. The service rejects JSON requests above the configured import limit, which defaults to 25 MB, and imports above 100,000 findings. Use the SDK from controlled automation when a browser upload is not appropriate.

### Generic finding contract

```json
{
  "format": "generic",
  "tool": {
    "key": "dependency-scanner",
    "name": "Dependency Scanner",
    "type": "sca"
  },
  "context": {
    "provider": "github-enterprise",
    "organization": "example-engineering",
    "repository": "payments-api",
    "branch": "main"
  },
  "completeSnapshot": true,
  "scannedTargets": [
    {
      "provider": "github-enterprise",
      "organization": "example-engineering",
      "repository": "payments-api",
      "branch": "main"
    }
  ],
  "findings": [
    {
      "id": "CVE-2026-1000",
      "title": "Vulnerable dependency",
      "severity": "critical",
      "rule_id": "SCA-1000",
      "path": "requirements.txt",
      "line": 18,
      "cwe": ["CWE-1104"],
      "cve": ["CVE-2026-1000"],
      "package_name": "example-lib",
      "package_version": "1.0.0",
      "fixed_version": "1.0.1",
      "cvss_score": 9.8,
      "epss_score": 0.91,
      "exploit_available": true,
      "scanner_url": "https://scanner.example.test/findings/1000",
      "remediation": "Upgrade example-lib to 1.0.1.",
      "dataInteractions": [
        {
          "dataType": "payment_card_data",
          "confidence": 0.98,
          "source": "scanner",
          "evidence": "PCI classification"
        }
      ]
    }
  ]
}
```

`tool.key` must remain stable across imports. `context` supplies defaults for every finding. Finding-level source fields override those defaults.

## Snapshot Semantics

Set `completeSnapshot` to `true` only when the document contains the complete current result set for the named tool and every entry in `scannedTargets`.

- Findings present in the document are inserted or updated.
- Active findings absent from that complete snapshot are resolved.
- Accepted-risk and false-positive decisions are preserved.
- A finding that reappears after snapshot resolution reopens.
- A partial import never resolves an existing finding.
- Empty complete snapshots are accepted only with at least one scanned target.

File imports are atomic. Large direct-connector synchronizations commit bounded batches so progress is durable and memory remains bounded. Finding upserts and child-table synchronization use PostgreSQL pipeline mode within each batch, while asset correlation uses indexed, sync-wide resolution caching. A failed or interrupted connector sync retains its audit record, does not reconcile absent findings, and leaves previously committed finding updates available for the next retry.

## Risk Model

Finding risk is an explainable score from 0 to 100. The stored factor list records the points contributed by:

- Normalized severity.
- CVSS score.
- EPSS probability.
- Known exploit evidence.
- Internet exposure.
- Application criticality.
- Data classification.
- Finding age.

Risk bands are low, medium, high, and critical. Default remediation due dates are 7 days for critical, 30 days for high, 90 days for medium, 180 days for low, and 365 days for informational findings. A finding is overdue when it remains active after its due date passes. Users can change these timelines in **Configuration** > **Remediation timelines**; saving the policy recalculates policy-managed due dates while retaining manually set due dates. Updating an application's security profile recalculates every linked finding in the same transaction.

Each asset also receives a contextual risk profile with three independently stored components:

- Technical pressure from the highest and top active finding scores plus bounded finding volume.
- Data sensitivity from scanner classifications, privacy categories, regulations, CWE mappings, and lower-confidence textual evidence.
- Context from criticality, internet exposure, and data classification.

Assets without findings receive a low baseline profile derived from their current context. This keeps every inventory record explainable while reserving the posture priority list for assets with active findings.

Supported data categories include credentials, authentication data, secrets, payment card data, financial data, health data, biometric data, personal data, location data, device identifiers, tracking data, confidential business data, and source code. Every observed category retains confidence, finding count, source, and bounded evidence. A data category describes evidence associated with findings; it is not asserted as a complete data-flow inventory.

## Workflow

Supported states are `open`, `triaged`, `in_progress`, `resolved`, `accepted`, and `false_positive`. Terminal findings may return to `open`; unsupported terminal-to-terminal transitions are rejected. Each change creates an event containing actor, prior status, new status, note, assignment, due date, and timestamp.

## Scanner Coverage

Coverage is recorded per application branch and tool when a finding or scanned target resolves to inventory. Status is derived from the most recent import:

| Status | Rule |
| --- | --- |
| Current | Scanned in the last 30 days |
| Stale | Scanned 31 to 90 days ago |
| Expired | Scanned more than 90 days ago |
| Not scanned | No matching scanner import |

Coverage requires source context. Unlinked findings remain actionable but do not establish application coverage.

## Python SDK

```python
from appsec_atlas import AppSecAtlasAspmService

aspm = AppSecAtlasAspmService(
    postgres_dsn="postgresql://app_user:secret@postgres:5432/appsec",
    postgres_schema="application_inventory",
    owner_user_id="security-platform",
    owner_user_login="scanner-automation",
)

import_result = aspm.ingest(payload)
posture = aspm.posture()
findings = aspm.findings(filters={"severities": ["critical", "high"]})
finding = aspm.finding(findings["rows"][0]["finding_id"])
xlsx = aspm.export_findings("xlsx", filters={"statuses": ["open"]})
coverage = aspm.coverage()
connector_status = aspm.connector_status()
sync_result = aspm.sync_connectors(["semgrep", "invicti", "nowsecure"])
asset_risks = aspm.asset_risks(
    risk_bands=["critical", "high"],
    data_types=["payment_card_data", "credentials"],
)
profile = aspm.update_asset_profile(
    branch_inventory_id=42,
    profile={
        "criticality": "mission_critical",
        "internetExposed": True,
        "dataClassification": "restricted",
        "businessOwner": "Payments",
        "technicalOwner": "payments-platform",
        "tags": ["pci", "tier-0"],
    },
)
```

## Command Line

The ASPM command is separate from the inventory scanner command, so existing automation remains compatible.

```bash
export APPLICATION_INVENTORY_POSTGRES_DSN="postgresql://app_user:secret@postgres:5432/appsec"

appsec-atlas-aspm \
  --owner-user-id security-platform \
  --owner-user-login scanner-automation \
  ingest results.sarif \
  --tool-key codeql \
  --tool-name CodeQL \
  --tool-type sast \
  --provider github-enterprise \
  --organization example-engineering \
  --repository payments-api \
  --branch main \
  --complete-snapshot
```

```bash
appsec-atlas-aspm --owner-user-id security-platform posture
appsec-atlas-aspm --owner-user-id security-platform coverage --limit 200
appsec-atlas-aspm --owner-user-id security-platform findings --severity critical --severity high --status open
appsec-atlas-aspm --owner-user-id security-platform findings --overdue --export xlsx --output overdue.xlsx
appsec-atlas-aspm --owner-user-id security-platform update FINDING_ID --status in_progress --assignee payments-platform --note "Remediation started"
appsec-atlas-aspm --owner-user-id security-platform profile 42 --criticality mission_critical --internet-exposure true --data-classification restricted --tag pci
appsec-atlas-aspm --owner-user-id security-platform connectors status
appsec-atlas-aspm --owner-user-id security-platform connectors sync --connector semgrep --connector nowsecure
appsec-atlas-aspm --owner-user-id security-platform connectors history --limit 20
appsec-atlas-aspm --owner-user-id security-platform assets --risk-band critical --data-type payment_card_data
```

Global database and owner options precede the command. The CLI defaults to the local PostgreSQL development credentials and owner scope `cli`; production automation must supply a managed DSN and a stable explicit owner. Export files are created with owner-only permissions. CLI input is bounded to 256 MiB by default through `APPLICATION_INVENTORY_ASPM_CLI_MAX_IMPORT_BYTES`.

The container exposes the same command through its `aspm` dispatcher:

```bash
docker run --rm \
  --env-file .env \
  -v "$PWD/results.sarif:/input/results.sarif:ro" \
  h0p3sf4ll/appsec-atlas:2.0.0 \
  aspm --owner-user-id security-platform ingest /input/results.sarif
```

## Authenticated API

The browser uses session authentication and a CSRF token for every ASPM route. API routes are intentionally user-scoped and accept the configured PostgreSQL fields alongside the operation payload.

| Route | Purpose |
| --- | --- |
| `POST /api/aspm/posture` | Risk, workflow, priority-application, tool, trend, and coverage summary |
| `POST /api/aspm/findings/import` | Normalize and atomically ingest scanner output |
| `POST /api/aspm/findings/search` | Search, filter, sort, facet, and page findings |
| `POST /api/aspm/findings/detail` | Retrieve one finding and its event history |
| `POST /api/aspm/findings/update` | Update status, assignee, due date, and note |
| `POST /api/aspm/findings/export` | Export the active query as XLSX, CSV, or JSON |
| `POST /api/aspm/coverage` | Retrieve application scanner coverage |
| `POST /api/aspm/assets/profile` | Read or update application security context |
| `POST /api/aspm/assets/risks` | Search and page contextual asset risk profiles |
| `POST /api/aspm/connectors/status` | Return redacted connector readiness and recent syncs |
| `POST /api/aspm/connectors/test` | Make a lightweight, non-import connection check for selected remote connectors |
| `POST /api/aspm/connectors/sync` | Pull, normalize, correlate, and persist selected connectors |
| `POST /api/aspm/connectors/history` | Return user-scoped connector sync audit records |

Use `AppSecAtlasAspmService` for service-to-service Python integration. Legacy `AspmService` remains available through the compatibility package. Do not automate browser session cookies as an API credential.

## Production Controls

- Disable test login and require GitHub Enterprise or Google SSO.
- Run behind HTTPS and set secure cookies.
- Use a dedicated PostgreSQL role and managed secret; never deploy the local `postgres/postgres` default.
- Keep database, report, and encrypted service-state storage durable and backed up.
- Restrict scanner automation to a dedicated owner scope.
- Validate tool keys and source context in pipeline templates.
- Treat complete snapshots as privileged destructive reconciliation inputs.
- Limit ingress request size to the configured service limit.
- Monitor failed imports, stale coverage, overdue findings, HTTP errors, database readiness, and scan failures.
- Export scanner files and findings only to approved storage because they may contain source paths, package details, repository names, and contributor identities.
