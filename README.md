# Application Inventory Service

![Application Inventory Service](docs/assets/application-inventory-service-banner.svg)

[![CI](https://github.com/h0p3sf4ll/application-inventory-service/actions/workflows/ci.yml/badge.svg)](https://github.com/h0p3sf4ll/application-inventory-service/actions/workflows/ci.yml)
[![Security](https://github.com/h0p3sf4ll/application-inventory-service/actions/workflows/security.yml/badge.svg)](https://github.com/h0p3sf4ll/application-inventory-service/actions/workflows/security.yml)
[![Publish](https://github.com/h0p3sf4ll/application-inventory-service/actions/workflows/publish.yml/badge.svg)](https://github.com/h0p3sf4ll/application-inventory-service/actions/workflows/publish.yml)
[![PyPI](https://img.shields.io/pypi/v/application-inventory-service.svg)](https://pypi.org/project/application-inventory-service/)
[![Python](https://img.shields.io/pypi/pyversions/application-inventory-service.svg)](https://pypi.org/project/application-inventory-service/)
[![License](https://img.shields.io/pypi/l/application-inventory-service.svg)](LICENSE)

Application Inventory Service discovers software assets across Azure DevOps and GitHub Enterprise without cloning repositories. It identifies mobile apps, web apps, API services, microservices, middleware, serverless workloads, infrastructure code, AI-enabled apps, and ML-enabled apps, then emits reports and scanner-ready target manifests.

The project is published as `application-inventory-service`. The original `appsec-*`, `ado-mobile-scanner`, and `mobile-app-inventory-tracer` commands remain available as compatibility aliases.

## What It Does

- Scans one or more Azure DevOps organizations, each with its own PAT.
- Scans GitHub Enterprise owners and repositories.
- Scans Azure DevOps and GitHub Enterprise together in one run when both source types are configured.
- Pulls Azure DevOps projects and GitHub repositories into the UI for targeted scans.
- Scans default branches, with production-like fallback branch resolution when no default branch exists.
- Captures inventory name, version, type, language, mobile identifiers, contributors, last activity, and evidence.
- Optionally validates detected mobile identifiers against Apple App Store and Google Play.
- Writes XLSX inventory reports, Semgrep target lists, and SonarQube project manifests labeled by selected application type.
- Streams results into a normalized PostgreSQL schema, scoped by signed-in user when run from the UI.

## Documentation

- [Application Intent](docs/APP_INTENT.md)
- [Security Baseline](SECURITY.md)
- [Code Reference](docs/CODE_REFERENCE.md)
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
git clone https://github.com/h0p3sf4ll/application-inventory-service.git
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

The local test user is enabled by default for local runs. For shared environments, configure GitHub SSO or Google SSO and set `APPLICATION_INVENTORY_SERVICE_TEST_LOGIN_ENABLED=false`.

For Azure DevOps scans, add one or more organization/PAT pairs in the Azure organizations section. The UI does not use a shared organization, project, or standalone PAT field; each organization is always paired with its own PAT, and credentials are used only for the current scan.

For GitHub Enterprise scans, the UI accepts the GitHub App PEM private key through file upload. The App ID is fixed to `4255413`; the uploaded file is read in the browser for the current scan and is not saved in UI preferences.

## Quick Start: Docker

```bash
mkdir -p reports
cp .env.example .env
docker run --rm \
  -p 48731:48731 \
  --env-file .env \
  -v "$PWD/reports:/reports" \
  h0p3sf4ll/application-inventory-service:1.6.5 \
  ui \
  --host 0.0.0.0 \
  --port 48731 \
  --reports-dir /reports
```

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

## GitHub Enterprise

```bash
export GITHUB_APP_ID="123456"
export GITHUB_APP_INSTALLATION_ID="98765432"
export GITHUB_APP_PRIVATE_KEY_FILE="/run/secrets/github-app.pem"

application-inventory-service \
  --provider github-enterprise \
  --base-url https://github.fabrikam.example/api/v3 \
  --org FabrikamCloud \
  --repo payments-api \
  --out-dir reports
```

Omit `--repo` to scan all accessible repositories for the owner. Repeat `--repo` for a selected repository set.

The GitHub App must be installed on the owner with read-only Metadata, Contents, and Deployments permissions. The service signs a short-lived App JWT, exchanges it for an installation access token, caches that token, and refreshes it before expiry. A `GITHUB_TOKEN` or `GHE_TOKEN` remains supported as a compatibility fallback, but is not required when the App settings are present.

### Combined Azure DevOps and GitHub Enterprise scan

Use `mixed` when the inventory must include both providers. The `--org` value is the GitHub Enterprise owner; Azure DevOps organizations and PATs are supplied separately. The command produces one XLSX file, one Semgrep target file, one SonarQube target file, and one PostgreSQL sync for the complete run.

```bash
export APPLICATION_INVENTORY_ADO_ORG_PATS='[{"org":"FabrikamADO","pat":"ado-read-token"}]'
export GITHUB_APP_ID="123456"
export GITHUB_APP_INSTALLATION_ID="98765432"
export GITHUB_APP_PRIVATE_KEY_FILE="/run/secrets/github-app.pem"

application-inventory-service \
  --provider mixed \
  --org FabrikamGH \
  --base-url https://github.fabrikam.example/api/v3 \
  --out-dir reports
```

Use `--target-filter ORG=PROJECT_OR_REPO` to limit either source. The organization prefix identifies the source owner, for example `FabrikamADO=Payments` or `FabrikamGH=payments-api`. Leave filters out to scan all accessible projects and repositories from both configured sources.

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

Local development database:

```bash
docker run --name application-inventory-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=postgres \
  -p 5432:5432 \
  -d postgres:16-alpine
```

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `APPLICATION_INVENTORY_SERVICE_UI_HOST` | UI bind host |
| `APPLICATION_INVENTORY_SERVICE_UI_PORT` | UI bind port |
| `APPLICATION_INVENTORY_SERVICE_REPORTS_DIR` | UI report/state directory |
| `APPLICATION_INVENTORY_SERVICE_PUBLIC_URL` | Public HTTPS base URL used for OAuth callbacks |
| `APPLICATION_INVENTORY_SERVICE_COOKIE_SECURE` | Adds Secure cookies and HSTS when set to `true` |
| `APPLICATION_INVENTORY_SERVICE_ALLOWED_GITHUB_HOSTS` | Comma-separated GitHub Enterprise host allowlist |
| `APPLICATION_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS` | Local-only escape hatch for HTTP provider URLs |
| `APPLICATION_INVENTORY_SERVICE_MAX_JSON_BODY_BYTES` | Maximum UI JSON request size |
| `APPLICATION_INVENTORY_SERVICE_GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `APPLICATION_INVENTORY_SERVICE_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `APPLICATION_INVENTORY_GITHUB_APP_ID` | GitHub App ID |
| `APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID` | GitHub App installation ID |
| `APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE` | Secret-mounted GitHub App PEM private key path |
| `APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY` | GitHub App PEM private key; use a secret manager or mounted file in shared environments |
| `APPLICATION_INVENTORY_SERVICE_SECRET_KEY` | Fernet key for encrypted token storage |
| `APPLICATION_INVENTORY_SERVICE_STATE_DIR` | Secure state directory |
| `APPLICATION_INVENTORY_ADO_ORG_PATS` | JSON or `ORG=PAT` list for Azure DevOps multi-org scans |
| `APPLICATION_INVENTORY_TARGET_FILTERS` | JSON or repeated `[ORG=]PROJECT_OR_REPO` filters |
| `APPLICATION_INVENTORY_POSTGRES_DSN` | PostgreSQL DSN |
| `APPLICATION_INVENTORY_POSTGRES_SCHEMA` | PostgreSQL schema |
| `APPLICATION_INVENTORY_POSTGRES_TABLE` | Flat compatibility table |
| `APPLICATION_INVENTORY_ADO_REQUESTS_PER_SECOND` | Azure DevOps request pace per scanner process; defaults to `6` |
| `APPLICATION_INVENTORY_ADO_MAX_RETRIES` | Azure DevOps retry count for throttled or transient reads; defaults to `8` |
| `APPLICATION_INVENTORY_ADO_POOL_SIZE` | Azure DevOps per-thread connection pool size; defaults to `4` |
| `APPLICATION_INVENTORY_ADO_LOW_REMAINING_BACKOFF_SECONDS` | Extra pause when Azure DevOps rate-limit remaining reaches zero; defaults to `2` |

Legacy `APPSEC_INVENTORY_*` and `APPSEC_INVENTORY_SERVICE_*` variables remain supported.

## Outputs

With the default prefix and no application type filter, the service writes:

- `application_inventory_service_all_types.xlsx`
- `application_inventory_service_all_types_semgrep_targets.txt`
- `application_inventory_service_all_types_sonarqube_projects.csv`

When application types are selected, the type label is added to the output name, for example `application_inventory_service_mobile_app_api_service.xlsx`.

The target files are intended for downstream orchestration with Semgrep, SonarQube, SCA tools, custom security scanners, or pipeline automation.

## SDK

```python
from pathlib import Path

from application_inventory_service import AzureDevOpsOrgPat, ScanConfig, scan_to_reports

config = ScanConfig(
    provider="mixed",
    base_url="https://github.fabrikam.example/api/v3",
    org="FabrikamGH",
    pat="",
    github_app_id="123456",
    github_app_installation_id="98765432",
    github_app_private_key_file="/run/secrets/github-app.pem",
    project=None,
    ado_org_pats=(
        AzureDevOpsOrgPat("FabrikamADO", "ado-read-token"),
    ),
    target_filters=(),
    out_dir=Path("reports"),
    out_prefix="application_inventory_service",
    max_workers=8,
    branch_workers=16,
    content_workers=16,
    max_commits_per_repo=0,
    timeout_seconds=30,
    min_confidence="medium",
)

results, xlsx_path, semgrep_path, sonarqube_path = scan_to_reports(config)
```

## Release

Build and validate:

```bash
python -m unittest discover -s tests
python -m build
python -m twine check dist/*
```

Publish with the `Publish` GitHub Actions workflow. The workflow uses the `pypi` environment and supports two release paths:

- Preferred: configure PyPI Trusted Publishing for repository `h0p3sf4ll/application-inventory-service`, workflow `.github/workflows/publish.yml`, environment `pypi`.
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
