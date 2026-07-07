# Application Inventory Service

Application Inventory Service discovers software assets across Azure DevOps and GitHub Enterprise without cloning repositories. It identifies mobile apps, web apps, API services, microservices, middleware, serverless workloads, infrastructure code, AI-enabled apps, and ML-enabled apps, then emits reports and scanner-ready target manifests.

The project is published as `application-inventory-service`. The original `appsec-*`, `ado-mobile-scanner`, and `mobile-app-inventory-tracer` commands remain available as compatibility aliases.

## What It Does

- Scans one or more Azure DevOps organizations, each with its own PAT.
- Scans GitHub Enterprise owners and repositories.
- Pulls Azure DevOps projects and GitHub repositories into the UI for targeted scans.
- Scans default branches, with production-like fallback branch resolution when no default branch exists.
- Captures inventory name, version, type, language, mobile identifiers, contributors, last activity, and evidence.
- Optionally validates detected mobile identifiers against Apple App Store and Google Play.
- Writes CSV, JSON, XLSX, Semgrep target lists, SonarQube project manifests, and generic scanner target manifests.
- Streams results into a normalized PostgreSQL schema, scoped by signed-in user when run from the UI.

## Documentation

- [Application Intent](docs/APP_INTENT.md)
- [AWS Deployment Guide](docs/AWS_DEPLOYMENT.md)
- [Architecture](docs/ARCHITECTURE.md)
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
APPLICATION_INVENTORY_SERVICE_TEST_LOGIN_ENABLED=true \
application-inventory-service-ui \
  --host 127.0.0.1 \
  --port 48731 \
  --reports-dir reports
```

Open `http://127.0.0.1:48731`.

Use the test login only for local development. For shared environments, configure GitHub SSO or Google SSO and disable the test login.

## Quick Start: Docker

```bash
docker build -t application-inventory-service .
mkdir -p reports
cp .env.example .env
docker run --rm \
  -p 48731:48731 \
  --env-file .env \
  -v "$PWD/reports:/reports" \
  application-inventory-service \
  ui \
  --host 0.0.0.0 \
  --port 48731 \
  --reports-dir /reports
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
export GITHUB_TOKEN="your-token"

application-inventory-service \
  --provider github-enterprise \
  --base-url https://github.fabrikam.example/api/v3 \
  --org FabrikamCloud \
  --repo payments-api \
  --out-dir reports
```

Omit `--repo` to scan all accessible repositories for the owner. Repeat `--repo` for a selected repository set.

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
| `APPLICATION_INVENTORY_SERVICE_GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `APPLICATION_INVENTORY_SERVICE_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `APPLICATION_INVENTORY_SERVICE_SECRET_KEY` | Fernet key for encrypted token storage |
| `APPLICATION_INVENTORY_SERVICE_STATE_DIR` | Secure state directory |
| `APPLICATION_INVENTORY_ADO_ORG_PATS` | JSON or `ORG=PAT` list for Azure DevOps multi-org scans |
| `APPLICATION_INVENTORY_TARGET_FILTERS` | JSON or repeated `[ORG=]PROJECT_OR_REPO` filters |
| `APPLICATION_INVENTORY_POSTGRES_DSN` | PostgreSQL DSN |
| `APPLICATION_INVENTORY_POSTGRES_SCHEMA` | PostgreSQL schema |
| `APPLICATION_INVENTORY_POSTGRES_TABLE` | Flat compatibility table |

Legacy `APPSEC_INVENTORY_*` and `APPSEC_INVENTORY_SERVICE_*` variables remain supported.

## Outputs

With the default prefix, the service writes:

- `application_inventory_service.csv`
- `application_inventory_service.json`
- `application_inventory_service.xlsx`
- `application_inventory_service_scanner_targets.csv`
- `application_inventory_service_scanner_targets.json`
- `application_inventory_service_semgrep_targets.txt`
- `application_inventory_service_sonarqube_projects.csv`

The scanner target files are intended for downstream orchestration with Semgrep, SonarQube, SCA tools, custom security scanners, or pipeline automation.

## SDK

```python
from pathlib import Path

from application_inventory_service import ScanConfig, SourceTargetFilter, scan_to_reports

config = ScanConfig(
    provider="github-enterprise",
    base_url="https://github.fabrikam.example/api/v3",
    org="FabrikamCloud",
    pat="your-token",
    project=None,
    target_filters=(SourceTargetFilter("", "payments-api"),),
    out_dir=Path("reports"),
    out_prefix="application_inventory_service",
    max_workers=8,
    branch_workers=16,
    content_workers=16,
    max_commits_per_repo=0,
    timeout_seconds=30,
    min_confidence="medium",
)

results, csv_path, json_path, xlsx_path = scan_to_reports(config)
```

## Release

Build and validate:

```bash
python -m unittest discover -s tests
python -m build
python -m twine check dist/*
```

Publish through GitHub Actions Trusted Publishing using the `pypi` environment, or upload the built distribution with a PyPI API token.

## Security Notes

- Use read-only source provider tokens.
- Store shared deployment secrets in AWS Secrets Manager, GitHub Actions secrets, or another approved secret manager.
- Do not commit generated reports if they contain internal repository names, URLs, identifiers, or contributor emails.
- The service does not clone repositories; it reads repository trees and selected manifest/configuration files through provider APIs.

## License

MIT. See [LICENSE](LICENSE).
