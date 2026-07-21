# ASPM Operations Guide

Application Security Posture Management combines branch-level application inventory with normalized scanner findings, contextual risk, scanner coverage, and remediation workflow. Inventory remains the source of application identity. Scanner imports add security state without duplicating application records.

## Operating Model

1. Inventory scans discover repositories, branches, application types, languages, owners, activity, deployment domains, and mobile metadata.
2. Security tools publish SARIF, Semgrep JSON, SonarQube issue JSON, or generic findings.
3. The ingestion service normalizes severity, identity, source location, package data, CWE, CVE, CVSS, EPSS, exploit evidence, and remediation metadata.
4. Findings correlate to inventory by signed-in owner, provider, organization, project, repository, and branch. Ambiguous matches remain unlinked instead of being assigned incorrectly.
5. A deterministic fingerprint deduplicates findings within a tool. Repeated imports update the existing record and preserve remediation state.
6. The risk engine combines technical severity with application context and records every contributing factor.
7. Teams triage and assign findings through one workflow. Status, assignee, due date, notes, and history remain scoped to the owning account.
8. Coverage records show which applications each scanner evaluated and when.

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
      "remediation": "Upgrade example-lib to 1.0.1."
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

Each import is atomic. Failed imports retain a failed audit record and do not partially update findings or coverage.

## Risk Model

Risk is an explainable score from 0 to 100. The stored factor list records the points contributed by:

- Normalized severity.
- CVSS score.
- EPSS probability.
- Known exploit evidence.
- Internet exposure.
- Application criticality.
- Data classification.
- Finding age.

Risk bands are low, medium, high, and critical. Default remediation due dates are 7 days for critical, 30 days for high, 90 days for medium, 180 days for low, and 365 days for informational findings. Updating an application's security profile recalculates every linked finding in the same transaction.

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
from application_inventory_service import AspmService

aspm = AspmService(
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

application-inventory-aspm \
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
application-inventory-aspm --owner-user-id security-platform posture
application-inventory-aspm --owner-user-id security-platform coverage --limit 200
application-inventory-aspm --owner-user-id security-platform findings --severity critical --severity high --status open
application-inventory-aspm --owner-user-id security-platform findings --overdue --export xlsx --output overdue.xlsx
application-inventory-aspm --owner-user-id security-platform update FINDING_ID --status in_progress --assignee payments-platform --note "Remediation started"
application-inventory-aspm --owner-user-id security-platform profile 42 --criticality mission_critical --internet-exposure true --data-classification restricted --tag pci
```

Global database and owner options precede the command. The CLI defaults to the local PostgreSQL development credentials and owner scope `cli`; production automation must supply a managed DSN and a stable explicit owner. Export files are created with owner-only permissions. CLI input is bounded to 256 MiB by default through `APPLICATION_INVENTORY_ASPM_CLI_MAX_IMPORT_BYTES`.

The container exposes the same command through its `aspm` dispatcher:

```bash
docker run --rm \
  --env-file .env \
  -v "$PWD/results.sarif:/input/results.sarif:ro" \
  h0p3sf4ll/application-inventory-service:1.7.0 \
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

Use `AspmService` for service-to-service Python integration. Do not automate browser session cookies as an API credential.

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
