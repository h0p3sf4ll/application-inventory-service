# Application Security Posture Management

```text
    _    ____  ____  __  __
   / \  / ___||  _ \|  \/  |   APPLICATION SECURITY POSTURE MANAGEMENT
  / _ \ \___ \| |_) | |\/| |   ------------------------------------------------
 / ___ \ ___) |  __/| |  | |   DISCOVER -> CORRELATE -> PRIORITIZE -> REMEDIATE
/_/   \_\____/|_|   |_|  |_|      ADO + GHE       RISK          WORKFLOW
```

![Application Security Posture Management](docs/assets/application-inventory-service-banner.svg)

[![CI](https://github.com/InfoSec-Actions/application-inventory-service/actions/workflows/ci.yml/badge.svg)](https://github.com/InfoSec-Actions/application-inventory-service/actions/workflows/ci.yml)
[![Security](https://github.com/InfoSec-Actions/application-inventory-service/actions/workflows/security.yml/badge.svg)](https://github.com/InfoSec-Actions/application-inventory-service/actions/workflows/security.yml)
[![Publish](https://github.com/InfoSec-Actions/application-inventory-service/actions/workflows/publish.yml/badge.svg)](https://github.com/InfoSec-Actions/application-inventory-service/actions/workflows/publish.yml)
[![PyPI](https://img.shields.io/pypi/v/application-inventory-service.svg)](https://pypi.org/project/application-inventory-service/)
[![Python](https://img.shields.io/pypi/pyversions/application-inventory-service.svg)](https://pypi.org/project/application-inventory-service/)
[![License](https://img.shields.io/pypi/l/application-inventory-service.svg)](LICENSE)

Application Security Posture Management builds a live software inventory from Azure DevOps and GitHub Enterprise, correlates normalized scanner findings to application branches, prioritizes them with explainable business context, measures scanner coverage, and coordinates remediation. Repository discovery does not require cloning or executing application code.

The package remains `application-inventory-service` to preserve existing integrations. The original `appsec-*`, `ado-mobile-scanner`, and `mobile-app-inventory-tracer` commands remain available as compatibility aliases.

## What It Does

- Normalizes SARIF, Semgrep JSON, SonarQube issue JSON, and generic findings into one deduplicated remediation queue.
- Pulls current findings from Semgrep, Invicti, NowSecure, SonarQube, and OWASP ZAP, and guides SARIF imports from Trivy, Gitleaks, Nuclei, and OWASP Dependency-Check.
- Provides an executive Dashboard with drill-down metrics, workflow totals, and priority applications that open the matching records.
- Stores user-specific webhooks, scanner connection settings, and remediation timelines encrypted in Configuration.
- Correlates findings to the branch-level application inventory and retains unlinked findings for review.
- Correlates by exact repository identity, mobile package identifier, or web domain, with exact application name as a guarded fallback.
- Builds asset risk profiles from technical findings, observed data interactions, internet exposure, application criticality, and data classification.
- Tracks open, triaged, in-progress, resolved, accepted-risk, and false-positive workflows with an immutable event history.
- Measures scanner coverage by application and flags current, stale, expired, and untested assets.
- Exports filtered security findings as XLSX, CSV, or JSON and exposes the same operations through the Python SDK and authenticated API.
- Scans one or more Azure DevOps organizations, each with its own PAT.
- Discovers Azure DevOps repositories organization-wide, including hidden repositories visible to the PAT.
- Scans one or more GitHub owners and repositories.
- Scans Azure DevOps and GitHub Enterprise together in one run when both source types are configured.
- Pulls Azure DevOps projects and GitHub repositories into the UI for targeted scans.
- Scans default branches, with production-like fallback branch resolution when no default branch exists.
- Retains every discovered repository in full scans, including unclassified, disabled, empty, unavailable, and branchless records.
- Captures inventory name, version, type, language, mobile identifiers, contributors, last activity, and evidence.
- Links deployable source branches to web domains using provider deployment records and structured deployment configuration.
- Optionally validates detected mobile identifiers against Apple App Store and Google Play.
- Writes XLSX inventory reports, Semgrep target lists, and SonarQube project manifests labeled by selected application type.
- Streams results into a normalized PostgreSQL schema, scoped by signed-in user when run from the UI.
- Pauses, resumes, and stops active scans, and retries failed runs without overwriting their audit history.
- Runs encrypted, user-scoped one-time, daily, or weekly schedules.

## Documentation

- [How the Application Works](docs/HOW_THE_APPLICATION_WORKS.md)
- [Application Intent](docs/APP_INTENT.md)
- [ASPM Operations Guide](docs/ASPM_OPERATIONS.md)
- [Security Baseline](SECURITY.md)
- [Code Reference](docs/CODE_REFERENCE.md)
- [GitHub SSO Guide](docs/GITHUB_SSO.md)
- [AWS Deployment Guide](docs/AWS_DEPLOYMENT.md)
- [Azure Implementation Guide](docs/AZURE_IMPLEMENTATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Blog Post](docs/BLOG_POST.md)
- [PyPI Release Management](docs/PYPI_RELEASE_MANAGEMENT.md)
- [SBOM Summary](docs/SBOM.md)
- [CycloneDX SBOM](docs/SBOM.cdx.json)

## Install

```bash
python -m pip install application-inventory-service
```

```bash
application-inventory-service --help
application-inventory-service-ui --help
```

For local development:

```bash
git clone https://github.com/InfoSec-Actions/application-inventory-service.git
cd application-inventory-service
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
```

## Quick Start: UI

```bash
application-inventory-service-ui \
  --host 127.0.0.1 \
  --port 48731 \
  --reports-dir reports
```

Open `http://127.0.0.1:48731`.

The local test user is enabled by default for local runs. For shared environments, configure GitHub Enterprise SSO or Google SSO and set `APPLICATION_INVENTORY_SERVICE_TEST_LOGIN_ENABLED=false`.

For Azure DevOps scans, add one or more organization/PAT pairs in the Azure organizations section. The UI does not use a shared organization, project, or standalone PAT field; each organization is always paired with its own PAT. Interactive credentials remain in browser memory for the active session. Scheduled configurations are encrypted in service state.

For GitHub Enterprise scans, the UI uses service-managed GitHub App credentials on every run. The organization list, optional repository defaults, App ID, installation ID, API endpoint, and PEM path are configured through the server environment. The UI does not expose credentials or the API endpoint.

### Run control and scheduling

The Runs page controls the selected subprocess. Pause and resume use POSIX process-group signals, which cover the scanner and any child processes. This is supported on Linux and macOS, including the Docker image. Stop works for queued, running, and paused scans. **Retry failed run** queues the same encrypted, user-scoped configuration as a new attempt with a new run ID and report directory. The original exit code, logs, failures, and reports remain unchanged. Only one retry in a run lineage can be active at a time. The Console retains the complete live stream; the separate Failures console isolates error lines and writes them to a downloadable `failures.log` in the scan report directory. Report and failure logs are created with owner-only permissions.

Closing the browser or signing out does not stop a scan. Each running scan uses a detached worker, a private durable log, and encrypted run state. Authenticated sessions are encrypted in the same service-state vault and remain valid across UI restarts until logout or their 12-hour expiry. When the UI service restarts on the same host, it verifies the original process group, restores the owning user, reconnects log delivery, rebuilds the failure-only log from durable output, and exposes the run to its owner. Keep the reports and service-state directories on durable storage and keep `APPLICATION_INVENTORY_SERVICE_SECRET_KEY` stable. Stopping a container, VM, or host still terminates its operating-system processes.

The Schedules page creates a schedule from the current Scan setup. Schedule definitions and embedded source credentials are encrypted in `schedules.json.enc` under the service state directory. Schedules are scoped to the signed-in user and survive service restarts when the state directory and `APPLICATION_INVENTORY_SERVICE_SECRET_KEY` remain stable.

Available frequencies are once, daily, and weekly. Each schedule can be run immediately, disabled, enabled, or deleted. `APPLICATION_INVENTORY_SERVICE_MAX_CONCURRENT_SCANS` limits aggregate scan pressure from interactive and scheduled runs.

## Quick Start: ASPM

1. Run an inventory scan so source branches exist in PostgreSQL.
2. Open **Dashboard** to review priority applications, coverage, workflow, and scanner health. Click a metric, workflow status, or priority application to open its related view or filtered findings.
3. Open **Findings**, select **Import SARIF**, and upload SARIF, Semgrep JSON, SonarQube issue JSON, or the documented generic format. Add repository context when the scanner file does not identify its source.
4. Set criticality, internet exposure, data classification, and owners from an application's inventory record. Risk scores recalculate in the same transaction.
5. Assign, triage, accept, resolve, or mark findings false positive. Every workflow change is retained in the finding history.

### Direct scanner connections

Store connector credentials in a deployment secret manager and inject them as environment variables. They are read only by the backend and are never returned to the browser.

```bash
export SEMGREP_APP_TOKEN="..."
export APPLICATION_INVENTORY_INVICTI_API_URL="https://www.netsparkercloud.com/api/1.0/"
export APPLICATION_INVENTORY_INVICTI_USER_ID="..."
export APPLICATION_INVENTORY_INVICTI_TOKEN="..."
export APPLICATION_INVENTORY_NOWSECURE_TOKEN="..."

application-inventory-aspm connectors status
application-inventory-aspm connectors sync --connector semgrep --connector invicti --connector nowsecure
application-inventory-aspm assets --risk-band critical
```

Open **Configuration** > **Scanner connections** to configure per-user connections. The setup wizard stores account-specific values encrypted and never returns secret values to the browser. Semgrep, Invicti, and NowSecure can use service-managed settings or account-specific overrides; SonarQube and OWASP ZAP synchronize directly. Trivy, Gitleaks, Nuclei, and OWASP Dependency-Check are SARIF profiles: configure the report location, then upload output from **Findings** > **Import SARIF**. Open **Asset risk** to filter contextual risk profiles and observed data interactions. Invicti defaults to its public cloud API root and supports an environment override for private deployments.

Use **Test connections** to make a lightweight request before synchronizing remote scanners. A test does not import findings or replace historical tool health. Dashboard **Tool health** shows the latest import or connector sync, so it can show a prior failure after a successful test until the next sync completes.

Use **Configuration** > **Remediation timelines** to set the policy due date for each severity. A finding is **overdue** when it remains active after its due date passes. Saving the policy recalculates policy-managed due dates; a manually set finding due date is retained.

Use complete snapshots only when a result file represents every finding produced by that tool for the listed targets. Findings absent from a complete snapshot are resolved automatically. Partial imports never resolve existing findings.

Automation can use the dedicated ASPM CLI without changing existing inventory scan commands:

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

application-inventory-aspm \
  --owner-user-id security-platform \
  findings --severity critical --severity high --status open --export xlsx
```

### Webhook exports

Set a webhook destination to send every inventory row produced by a scan to an external system. Delivery happens before report formatting, so each payload retains all collected fields, including classification evidence, domain evidence, source URLs, scores, mobile metadata, and store validation data.

Use the default `batch` mode when the receiving endpoint accepts an envelope with a `records` array. Use `record` mode for ServiceNow Import Set or Table API endpoints that accept one JSON object per request:

```bash
export APPLICATION_INVENTORY_WEBHOOK_URL="https://instance.service-now.com/api/now/import/u_application_inventory"
export APPLICATION_INVENTORY_WEBHOOK_BEARER_TOKEN="service-account-token"
export APPLICATION_INVENTORY_WEBHOOK_DELIVERY_MODE="record"

application-inventory-service --org example-engineering
```

The webhook accepts any `2xx` response, retries transient network failures and `429`/`5xx` responses, and uses a stable delivery ID for each retry. Configure `APPLICATION_INVENTORY_WEBHOOK_SIGNING_SECRET` to add an `X-Application-Inventory-Signature` HMAC-SHA256 header. Webhook URLs require HTTPS unless they target loopback; credentials, query strings, redirects, and transport header overrides are rejected.

Signed-in users can also manage multiple webhook destinations in **Configuration**. Each destination is encrypted per user, can be enabled independently, and is supplied only to that user's scan subprocesses. The Configuration page supports a connection test without exposing stored tokens or signing secrets back to the browser.

Python services can ingest scanner output without the UI:

```python
import json
from pathlib import Path

from application_inventory_service import AspmService

aspm = AspmService(
    postgres_dsn="postgresql://app_user:secret@postgres:5432/appsec",
    postgres_schema="application_inventory",
    owner_user_id="security-platform",
    owner_user_login="scanner-automation",
)

result = aspm.ingest(
    {
        "format": "sarif",
        "document": json.loads(Path("results.sarif").read_text()),
        "completeSnapshot": True,
        "scannedTargets": [
            {
                "provider": "github-enterprise",
                "organization": "example-engineering",
                "repository": "payments-api",
                "branch": "main",
            }
        ],
    }
)

connector_status = aspm.connector_status()
sync_result = aspm.sync_connectors(["semgrep", "invicti", "nowsecure"])
asset_risks = aspm.asset_risks(risk_bands=["critical", "high"])
```

See the [ASPM Operations Guide](docs/ASPM_OPERATIONS.md) for data contracts, automation patterns, risk factors, lifecycle rules, API routes, and production controls.

## Quick Start: Docker

```bash
mkdir -p reports
cp .env.example .env
docker run --rm \
  -p 48731:48731 \
  --env-file .env \
  -v "$PWD/reports:/reports" \
  h0p3sf4ll/application-inventory-service:1.9.0 \
  ui \
  --host 0.0.0.0 \
  --port 48731 \
  --reports-dir /reports
```

Local `application-inventory-service`, `application-inventory-aspm`, and UI commands load a `.env` file from the current working directory. Set `APPLICATION_INVENTORY_ENV_FILE` to select a different local file. Explicit process environment variables take precedence, so production secret injection continues to override local values.

Build locally when you need to test unpublished changes:

```bash
docker build -t application-inventory-service:local .
```

## Azure DevOps

Scan one organization:

```bash
export ADO_PAT="your-token"

application-inventory-service \
  --provider azure-devops \
  --org FabrikamCloud \
  --out-dir reports
```

Scan selected projects:

```bash
application-inventory-service \
  --provider azure-devops \
  --org FabrikamCloud \
  --project Go_To_Market \
  --project Payments \
  --out-dir reports
```

Scan multiple organizations with separate PATs:

```bash
application-inventory-service \
  --ado-org-pat "FabrikamCloud=$FABRIKAM_PAT" \
  --ado-org-pat "ContosoApps=$CONTOSO_PAT" \
  --target-filter "FabrikamCloud=Go_To_Market" \
  --target-filter "ContosoApps=Payments" \
  --out-dir reports
```

Before opening report or database writers, the scanner validates access to every selected organization. An expired or unauthorized PAT stops the run immediately, identifies the affected organization, and prevents incomplete inventory from being committed. Replace the rejected PAT and rerun the scan.

## GitHub

```bash
export APPLICATION_INVENTORY_GITHUB_API_URL="https://api.github.com"
export APPLICATION_INVENTORY_GITHUB_APP_ID="your-github-app-id"
export APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID="your-installation-id"
export APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE="/run/secrets/github-app.pem"
export APPLICATION_INVENTORY_GITHUB_URLS="your-org-a,your-org-b"
export APPLICATION_INVENTORY_GITHUB_REPOSITORIES="your-org-a=payments-api"

application-inventory-service \
  --provider github-enterprise \
  --github-url your-org-a \
  --github-url https://github.com/your-org-b \
  --target-filter your-org-a=payments-api \
  --out-dir reports
```

Repeat `--github-url` for additional owners. When owner arguments are omitted, the scanner uses `APPLICATION_INVENTORY_GITHUB_URLS`. Set `APPLICATION_INVENTORY_GITHUB_REPOSITORIES` to `OWNER=REPOSITORY` values when the backend should scan a fixed repository set by default; leave it blank to scan all accessible repositories. The public API endpoint defaults to `https://api.github.com` and is intentionally not shown in the UI. Set `APPLICATION_INVENTORY_GITHUB_API_URL` only for a GitHub Enterprise API endpoint.

The GitHub App must be installed on the owner with read-only Metadata, Contents, and Deployments permissions. The service signs a short-lived App JWT, exchanges it for an installation access token, caches that token, and refreshes it before expiry. A `GITHUB_TOKEN` or `GHE_TOKEN` remains supported as a compatibility fallback, but is not required when the App settings are present.

## Web Domain Attribution

Domain attribution runs automatically for web apps, API services, microservices, and serverless workloads. It combines successful GitHub deployment environment URLs, repository homepage and GitHub Pages metadata, and explicit values from deployment-oriented files such as `CNAME`, ingress manifests, Helm values, Terraform domain files, Azure Pipelines, and GitHub Actions workflows.

Each result includes `primary_web_domain`, `web_domains`, `web_urls`, `web_domain_status`, `web_domain_sources`, and JSON evidence. Status values are designed for filtering:

| Status | Meaning |
| --- | --- |
| `confirmed` | A successful provider deployment supplied the environment URL |
| `configured` | Repository metadata or source-controlled deployment configuration declares the domain |
| `inferred` | A recognized hosting convention produced the domain from an explicit app or project name |
| `not_detected` | No acceptable domain evidence was found |

The scanner rejects localhost, IP addresses, reserved placeholders, unresolved variables, credential-bearing URLs, and known provider, package, identity, and schema hosts. It does not probe attributed domains over HTTP or DNS. This avoids scan-time SSRF risk and keeps attribution separate from runtime availability validation.

Store lookup is available for mobile scans. Select countries in the UI or repeat `--store-country` in the CLI, for example `--store-country US --store-country CA --store-country GB`. The default is `US`; validation passes only when every requested store/platform lookup succeeds.

### GitHub Enterprise sign-in

GitHub Enterprise OAuth authenticates people to the UI. The separate GitHub App authenticates repository discovery and scans. Configure both when users must sign in and the service must inventory private repositories.

See [GitHub SSO](docs/GITHUB_SSO.md) for registration, secret management, reverse-proxy settings, verification, organization approval, and troubleshooting.

Create an OAuth App in GitHub Enterprise and set its authorization callback URL to:

```text
https://inventory.example.com/api/auth/github-enterprise/callback
```

Configure the backend and restart the service:

```bash
export APPLICATION_INVENTORY_SERVICE_PUBLIC_URL="https://inventory.example.com"
export APPLICATION_INVENTORY_SERVICE_GHE_BASE_URL="https://github.enterprise.example"
export APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_ID="your-oauth-client-id"
export APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_SECRET="your-oauth-client-secret"
export APPLICATION_INVENTORY_SERVICE_GHE_SCOPE="read:user read:org"
export APPLICATION_INVENTORY_SERVICE_SECRET_KEY="your-fernet-key"
export APPLICATION_INVENTORY_SERVICE_COOKIE_SECURE=true
```

The service derives the authorization, token, and user endpoints from the Enterprise base URL. Use `read:user read:org` unless policy requires a different minimum. Add `repo` only when the user OAuth token itself must access private repository content. Keep the client secret in a secret manager, use HTTPS, and disable test login in shared environments. A configured instance reports `githubEnterpriseLoginEnabled: true` from `/api/config` and shows **GitHub Enterprise** on the login page.

For GitHub Enterprise Cloud, set `APPLICATION_INVENTORY_SERVICE_GHE_BASE_URL=https://github.com`. For GitHub Enterprise Server, use the server origin such as `https://github.enterprise.example`; an `/api/v3` suffix is accepted and normalized automatically.

After sign-in, the OAuth access token is encrypted in the service state directory and scoped to the signed-in user. It is never returned to the browser or written to reports. A signed-in Enterprise token is used for that user's repository discovery and scan; otherwise the configured server-managed GitHub App is used.

### Combined Azure DevOps and GitHub Enterprise scan

Use `mixed` when the inventory must include both providers. Repeat `--github-url` for GitHub owners; Azure DevOps organizations and PATs are supplied separately. The command produces one XLSX file, one Semgrep target file, one SonarQube target file, and one PostgreSQL sync for the complete run.

```bash
export APPLICATION_INVENTORY_ADO_ORG_PATS='[{"org":"FabrikamADO","pat":"ado-read-token"}]'
export APPLICATION_INVENTORY_GITHUB_APP_ID="your-github-app-id"
export APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID="your-installation-id"
export APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE="/run/secrets/github-app.pem"

application-inventory-service \
  --provider mixed \
  --github-url your-github-owner \
  --out-dir reports
```

Use `--target-filter ORG=PROJECT_OR_REPO` to limit either source. The organization prefix identifies the source owner, for example `FabrikamADO=Payments` or `FabrikamGH=payments-api`. Leave filters out to scan all accessible projects and repositories from both configured sources.

Mixed scans use the same source-access preflight. All selected Azure DevOps organizations and GitHub owners must authenticate successfully before collection begins.

## PostgreSQL

PostgreSQL sync is enabled by default in the UI. For CLI scans:

```bash
export APPLICATION_INVENTORY_POSTGRES_DSN="postgresql://postgres:postgres@localhost:5432/postgres"

application-inventory-service \
  --provider azure-devops \
  --org FabrikamCloud \
  --postgres-schema application_inventory \
  --postgres-table application_inventory_assets \
  --out-dir reports
```

The local defaults are host `localhost`, port `5432`, database `postgres`, user `postgres`, and password `postgres`. The password is editable on the **Configuration** page and is not stored in browser storage. Change every default credential outside local development.

At startup, the service tests PostgreSQL and applies versioned, advisory-lock-protected schema migrations before accepting scan work. Unchanged schemas take the fast readiness path. A scan with database sync enabled is rejected if its configured database is unavailable. Findings commit at least once per second while a scan is active, and the **Inventory** table refreshes as those transactions become visible.

The schema separates repositories, branch inventory, application types, categories, contributors, web domains, domain evidence, store listings, scan runs, and observability events. Inventory identity is scoped by signed-in user, provider, organization, project, repository, and branch. Repeated scans update current rows and synchronize child values instead of inserting duplicate records. `inventory_status` distinguishes classified applications from candidates, unclassified repositories, empty repositories, disabled repositories, unavailable branches, branchless repositories, and failed branch analysis. Full-text search uses a PostgreSQL GIN index; common type, owner, activity, domain, and validation filters use selective indexes.

A full scan with no application-type filter inventories every repository visible to the source credential. The **Inventory** page reports repository, inventory-record, and classified-application counts separately. Selecting application types intentionally limits reports and database updates to matching applications at or above the configured confidence threshold.

The **Inventory** page provides sortable columns, per-column filters, multi-select Language and Types filters, full-text search, activity/domain/type quick filters, record details, and XLSX, CSV, or JSON exports. The **Configuration** page contains connection, synchronization, schema, webhook, scanner, and remediation settings. Results and exports use the same filters, sort order, and signed-in user scope. XLSX, CSV, and JSON exports consume a server-side database cursor to bound application memory. Operational scan and observability records remain event-based because each execution and log entry is a distinct audit record.

Structured events include service lifecycle, HTTP request timing, scan lifecycle, provider, user scope, status, and sanitized metadata. The UI exposes database-backed health at `/api/health` and operational counters at `/api/metrics`.

For local development, set `APPLICATION_INVENTORY_OBSERVABILITY_DSN=postgresql://postgres:postgres@localhost:5432/postgres`. In shared environments, use a secret manager or workload identity and grant the service permission to create or migrate tables in the configured schema.

Local development database:

```bash
docker run --name application-inventory-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=postgres \
  -p 5432:5432 \
  -d postgres:16-alpine
```

### Local inventory assistant

The optional inventory assistant converts plain-language requests into allowlisted search filters and export actions. It uses a local Ollama API and never sends inventory rows, credentials, or SQL to the model.

```bash
ollama pull llama3.1
ollama serve
```

The UI detects Ollama at `http://127.0.0.1:11434` and defaults to `llama3.1:latest`. Example requests include `show web apps updated in 90 days without a domain` and `export high-confidence mobile apps to xlsx`. The model produces a bounded query plan; PostgreSQL still applies parameterized SQL and user scoping.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `APPLICATION_INVENTORY_SERVICE_UI_HOST` | UI bind host |
| `APPLICATION_INVENTORY_SERVICE_UI_PORT` | UI bind port |
| `APPLICATION_INVENTORY_ENV_FILE` | Local `.env` path; defaults to `.env` in the working directory |
| `APPLICATION_INVENTORY_SERVICE_REPORTS_DIR` | UI report/state directory |
| `APPLICATION_INVENTORY_SERVICE_PUBLIC_URL` | Public HTTPS base URL used for OAuth callbacks |
| `APPLICATION_INVENTORY_SERVICE_COOKIE_SECURE` | Adds Secure cookies and HSTS when set to `true` |
| `APPLICATION_INVENTORY_SERVICE_ALLOWED_GITHUB_HOSTS` | Comma-separated GitHub Enterprise host allowlist |
| `APPLICATION_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS` | Local-only escape hatch for HTTP provider URLs |
| `APPLICATION_INVENTORY_SERVICE_MAX_JSON_BODY_BYTES` | Maximum UI JSON request size |
| `APPLICATION_INVENTORY_SERVICE_MAX_FINDING_IMPORT_BYTES` | Maximum ASPM scanner import request size; defaults to 24 MiB |
| `APPLICATION_INVENTORY_ASPM_CLI_MAX_IMPORT_BYTES` | Maximum ASPM CLI input file size; defaults to 256 MiB |
| `APPLICATION_INVENTORY_OWNER_USER_ID` | Default stable ASPM CLI owner scope; defaults to `cli` |
| `APPLICATION_INVENTORY_OWNER_USER_LOGIN` | Default ASPM CLI actor recorded in workflow events |
| `APPLICATION_INVENTORY_WEBHOOK_URL` | HTTPS endpoint for complete inventory scan records |
| `APPLICATION_INVENTORY_WEBHOOK_HEADERS` | JSON object of additional endpoint headers, such as a ServiceNow integration header |
| `APPLICATION_INVENTORY_WEBHOOK_BEARER_TOKEN` | Bearer token sent to the webhook endpoint |
| `APPLICATION_INVENTORY_WEBHOOK_SIGNING_SECRET` | Optional HMAC-SHA256 secret for webhook payload signatures |
| `APPLICATION_INVENTORY_WEBHOOK_TIMEOUT_SECONDS` | Per-request timeout; defaults to `30` |
| `APPLICATION_INVENTORY_WEBHOOK_BATCH_SIZE` | Inventory records per batch in `batch` mode; defaults to `100` |
| `APPLICATION_INVENTORY_WEBHOOK_RETRIES` | Additional retries for temporary failures; defaults to `3` |
| `APPLICATION_INVENTORY_WEBHOOK_DELIVERY_MODE` | `batch` envelope or `record` one-row-per-request mode; defaults to `batch` |
| `SEMGREP_APP_TOKEN` | Semgrep App token used by the backend connector |
| `APPLICATION_INVENTORY_SEMGREP_API_URL` | Semgrep API root; defaults to `https://semgrep.dev/api/v1` |
| `APPLICATION_INVENTORY_SEMGREP_ISSUE_TYPES` | Comma-separated Semgrep products; defaults to `sast,sca,ai_sast` |
| `APPLICATION_INVENTORY_SEMGREP_STATUSES` | Comma-separated Semgrep states synchronized as the current snapshot |
| `APPLICATION_INVENTORY_SEMGREP_MAX_FINDINGS` | Per-sync Semgrep safety limit; defaults to `5000000` |
| `APPLICATION_INVENTORY_SEMGREP_WORKERS` | Ordered Semgrep page-prefetch concurrency; defaults to `4`, maximum `16` |
| `APPLICATION_INVENTORY_INVICTI_API_URL` | Invicti API root; defaults to `https://www.netsparkercloud.com/api/1.0` |
| `APPLICATION_INVENTORY_INVICTI_USER_ID` | Invicti API user ID |
| `APPLICATION_INVENTORY_INVICTI_TOKEN` | Invicti API token |
| `APPLICATION_INVENTORY_INVICTI_WORKERS` | Bounded Invicti page-fetch concurrency; defaults to `2`, maximum `16` |
| `APPLICATION_INVENTORY_INVICTI_BATCH_PAGES` | Invicti API pages committed per database batch; defaults to `10`, maximum `25` |
| `APPLICATION_INVENTORY_INVICTI_TIMEOUT_SECONDS` | Minimum Invicti page timeout; defaults to `120` seconds |
| `APPLICATION_INVENTORY_NOWSECURE_API_URL` | NowSecure GraphQL endpoint; defaults to `https://api.nowsecure.com/graphql` |
| `APPLICATION_INVENTORY_NOWSECURE_TOKEN` | NowSecure Platform token |
| `APPLICATION_INVENTORY_CONNECTOR_SYSTEM_TRUST` | Uses the operating-system certificate store; defaults to `true` |
| `APPLICATION_INVENTORY_CONNECTOR_CA_BUNDLE` | Optional CA bundle for private PKI or TLS inspection |
| `APPLICATION_INVENTORY_CONNECTOR_MAX_RETRIES` | Per-attempt retries for throttling and transient HTTP failures; defaults to `5` |
| `APPLICATION_INVENTORY_CONNECTOR_NETWORK_ATTEMPTS` | Whole-request attempts for DNS, connection, and timeout failures; defaults to `5` |
| `APPLICATION_INVENTORY_CONNECTOR_NETWORK_BACKOFF_SECONDS` | Initial network retry delay; defaults to `2` seconds |
| `APPLICATION_INVENTORY_CONNECTOR_NETWORK_BACKOFF_MAX_SECONDS` | Maximum network retry delay; defaults to `15` seconds |
| `APPLICATION_INVENTORY_CONNECTOR_MAX_RESPONSE_BYTES` | Maximum decoded JSON response per connector request; defaults to 64 MiB |
| `APPLICATION_INVENTORY_SERVICE_MAX_CONCURRENT_SCANS` | Concurrent interactive and scheduled scan processes; defaults to `2` |
| `APPLICATION_INVENTORY_SERVICE_GHE_BASE_URL` | GitHub Enterprise base URL used for OAuth sign-in |
| `APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_ID` | GitHub Enterprise OAuth client ID |
| `APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_SECRET` | GitHub Enterprise OAuth client secret |
| `APPLICATION_INVENTORY_SERVICE_GHE_SCOPE` | GitHub Enterprise OAuth scopes; defaults to `read:user read:org` |
| `APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `APPLICATION_INVENTORY_GITHUB_API_URL` | Backend-only GitHub API endpoint; defaults to `https://api.github.com` |
| `APPLICATION_INVENTORY_GITHUB_APP_ID` | GitHub App ID |
| `APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID` | GitHub App installation ID |
| `APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE` | Secret-mounted GitHub App PEM private key path |
| `APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY` | GitHub App PEM private key; use a secret manager or mounted file in shared environments |
| `APPLICATION_INVENTORY_OBSERVABILITY_DSN` | PostgreSQL DSN for structured service logs; falls back to the inventory PostgreSQL DSN |
| `APPLICATION_INVENTORY_OBSERVABILITY_SCHEMA` | PostgreSQL schema for structured service logs; defaults to `application_inventory` |
| `APPLICATION_INVENTORY_SERVICE_VERBOSE` | Enables verbose service logging |
| `APPLICATION_INVENTORY_SERVICE_SECRET_KEY` | Fernet key for encrypted token storage |
| `APPLICATION_INVENTORY_SERVICE_STATE_DIR` | Secure state directory |
| `APPLICATION_INVENTORY_ADO_ORG_PATS` | JSON or `ORG=PAT` list for Azure DevOps multi-org scans |
| `APPLICATION_INVENTORY_GITHUB_URLS` | JSON, comma-separated, or newline-separated GitHub owners/URLs |
| `APPLICATION_INVENTORY_GITHUB_REPOSITORIES` | Optional JSON, comma-separated, or newline-separated `OWNER=REPOSITORY` defaults for GitHub scans |
| `APPLICATION_INVENTORY_TARGET_FILTERS` | JSON or repeated `[ORG=]PROJECT_OR_REPO` filters |
| `APPLICATION_INVENTORY_POSTGRES_DSN` | PostgreSQL DSN |
| `APPLICATION_INVENTORY_POSTGRES_HOST` | PostgreSQL host when a DSN is not supplied; defaults to `localhost` |
| `APPLICATION_INVENTORY_POSTGRES_PASSWORD` | PostgreSQL password; local default is `postgres` |
| `APPLICATION_INVENTORY_POSTGRES_SCHEMA` | PostgreSQL schema |
| `APPLICATION_INVENTORY_POSTGRES_TABLE` | Flat compatibility table |
| `APPLICATION_INVENTORY_LOCAL_LLM_ENABLED` | Enables the local inventory assistant; defaults to `true` |
| `APPLICATION_INVENTORY_LOCAL_LLM_URL` | Ollama origin; defaults to `http://127.0.0.1:11434` |
| `APPLICATION_INVENTORY_LOCAL_LLM_MODEL` | Ollama model; defaults to `llama3.1:latest` |
| `APPLICATION_INVENTORY_LOCAL_LLM_TIMEOUT` | Local model request timeout in seconds; defaults to `30` |
| `APPLICATION_INVENTORY_LOCAL_LLM_ALLOW_REMOTE` | Allows a non-loopback model endpoint; defaults to `false` |
| `APPLICATION_INVENTORY_ADO_REQUESTS_PER_SECOND` | Azure DevOps request pace per scanner process; defaults to `6` |
| `APPLICATION_INVENTORY_ADO_MAX_RETRIES` | Azure DevOps retry count for throttled or transient reads; defaults to `8` |
| `APPLICATION_INVENTORY_ADO_POOL_SIZE` | Azure DevOps per-thread connection pool size; defaults to `4` |
| `APPLICATION_INVENTORY_ADO_LOW_REMAINING_BACKOFF_SECONDS` | Extra pause when Azure DevOps rate-limit remaining reaches zero; defaults to `2` |
| `APPLICATION_INVENTORY_GITHUB_REQUESTS_PER_SECOND` | Shared GitHub request pace per installation or token; defaults to `8` |
| `APPLICATION_INVENTORY_GITHUB_MAX_RETRIES` | GitHub retry count for throttled or transient reads; defaults to `5` |
| `APPLICATION_INVENTORY_GITHUB_POOL_SIZE` | GitHub per-thread connection pool size; defaults to `8` |
| `APPLICATION_INVENTORY_GITHUB_RATE_LIMIT_RESERVE` | GitHub requests held in reserve before reset; defaults to `50` |
| `APPLICATION_INVENTORY_GITHUB_DOMAIN_ENVIRONMENTS` | Maximum recent GitHub deployment environments inspected per deployable repository; defaults to `4` |
| `APPLICATION_INVENTORY_XLSX_CHECKPOINT_ROWS` | Findings between XLSX checkpoints; defaults to `500` |
| `APPLICATION_INVENTORY_XLSX_MAX_CHECKPOINT_ROWS` | Maximum adaptive XLSX checkpoint interval; defaults to `5000` |
| `APPLICATION_INVENTORY_XLSX_CHECKPOINT_SECONDS` | Maximum seconds between XLSX checkpoints while findings arrive; defaults to `30` |
| `APPLICATION_INVENTORY_POSTGRES_COMMIT_ROWS` | Findings per PostgreSQL transaction; defaults to `50` |
| `APPLICATION_INVENTORY_POSTGRES_COMMIT_SECONDS` | Maximum seconds before pending findings become visible; defaults to `1` |

Legacy `APPSEC_INVENTORY_*` and `APPSEC_INVENTORY_SERVICE_*` variables remain supported.

## Outputs

With the default prefix and no application type filter, the service writes:

- `application_inventory_service_all_types.xlsx`
- `application_inventory_service_all_types_semgrep_targets.txt`
- `application_inventory_service_all_types_sonarqube_projects.csv`

When application types are selected, the type label is added to the output name, for example `application_inventory_service_mobile_app_api_service.xlsx`.

XLSX and database exports place source, ownership, activity, and scanner-routing fields first. Application classifications follow those fields. Mobile metadata and app-store validation columns are placed at the far right. Store fields remain empty for non-mobile records.

The target files are intended for downstream orchestration with Semgrep, SonarQube, SCA tools, custom security scanners, or pipeline automation.

Mobile records also include `nowsecure_target`, which identifies the source repository and branch that must produce the mobile binary. Downstream automation combines that target with the detected application identifier, version, and platform, then supplies the compiled Android or iOS binary, NowSecure group ID, and platform token. Those deployment-specific values are not stored in inventory. The official [NowSecure upload action](https://github.com/nowsecure/nowsecure-action/tree/main/upload-app) accepts the binary and group configuration.

## SDK

```python
from pathlib import Path

from application_inventory_service import AzureDevOpsOrgPat, ScanConfig, scan_reports, scan_to_reports

config = ScanConfig(
    provider="mixed",
    base_url="https://api.github.com",
    org="your-github-owner",
    github_urls=("your-github-owner", "another-owner"),
    pat="",
    github_app_id="your-github-app-id",
    github_app_installation_id="your-installation-id",
    github_app_private_key_file="/run/secrets/github-app.pem",
    project=None,
    ado_org_pats=(
        AzureDevOpsOrgPat("FabrikamADO", "ado-read-token"),
    ),
    target_filters=(),
    out_dir=Path("reports"),
    out_prefix="application_inventory_service",
    max_workers=8,
    source_workers=2,
    branch_workers=16,
    content_workers=16,
    max_commits_per_repo=0,
    timeout_seconds=30,
    min_confidence="medium",
)

results, xlsx_path, semgrep_path, sonarqube_path = scan_to_reports(config)

result_count, xlsx_path, semgrep_path, sonarqube_path = scan_reports(config)
```

`scan_to_reports` returns every inventory record for in-process consumers. `scan_reports` writes the same outputs and returns only the record count and paths, which keeps memory bounded for large inventories. The CLI uses the bounded-memory path.

## Performance

The scanner uses four bounded concurrency layers: sources, repository preparation, branch analysis, and manifest retrieval. Defaults are conservative enough for hosted provider APIs. Increase them only after observing provider latency, rate-limit headers, CPU, memory, and PostgreSQL commit time.

```bash
application-inventory-service \
  --source-workers 2 \
  --max-workers 8 \
  --branch-workers 16 \
  --content-workers 16 \
  --provider mixed \
  --out-dir reports
```

For long commit histories, contributor extraction consumes provider pages as an iterator instead of retaining every commit in memory. Azure DevOps full-organization scans use the organization repository endpoint instead of one request per project and request hidden repositories explicitly. Unclassified repositories use one latest-commit request for accurate activity bucketing; full contributor history remains reserved for classified applications. GitHub installation tokens and throttles are shared across owners, manifest work uses bounded backpressure, PostgreSQL commits are batched, database exports use server-side cursors, and CLI inventory records stream without accumulating a result list. Generated dependency directories and unused lockfiles are excluded from content retrieval.

GitHub domain attribution reads at most 30 recent deployments, inspects no more than two deployments per environment, and caps the environment count with `APPLICATION_INVENTORY_GITHUB_DOMAIN_ENVIRONMENTS`. Deployment lookups run only for network-deployable inventory types.

XLSX checkpoints expand adaptively up to the configured maximum, reducing repeated full-workbook serialization while preserving a live report. Each checkpoint is written to a temporary file and atomically replaces the prior workbook. Throughput is normally limited by provider throttling rather than local CPU; increase worker and request-rate settings only from observed provider capacity.

## Release

Build and validate:

```bash
python -m unittest discover -s tests
python -m build
python -m twine check dist/*
```

Publish with the `Publish` GitHub Actions workflow. The workflow uses the `pypi` environment and supports two release paths:

- Preferred: configure PyPI Trusted Publishing for repository `InfoSec-Actions/application-inventory-service`, workflow `.github/workflows/publish.yml`, environment `pypi`.
- Fallback: add a GitHub Actions secret named `PYPI_API_TOKEN` with a PyPI API token.

## Security Notes

- Use read-only source provider tokens.
- Store shared deployment secrets in AWS Secrets Manager, GitHub Actions secrets, or another approved secret manager.
- Rotate any token that has appeared in chat, logs, terminal output, screenshots, or issue trackers.
- Disable test login and set secure cookies in shared environments.
- Do not commit generated reports if they contain internal repository names, URLs, identifiers, or contributor emails.
- The service does not clone repositories; it reads repository trees and selected manifest/configuration files through provider APIs.

## License

MIT. See [LICENSE](LICENSE).
