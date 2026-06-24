# AppSec Inventory Service

AppSec Inventory Service builds an application inventory from Azure DevOps and GitHub Enterprise without cloning
repositories. It discovers mobile apps, web applications, API services, microservices, serverless workloads,
containerized services, middleware-oriented workers, and AI-enabled applications from structured source evidence,
then streams reports and scanner target manifests as the scan runs.

The project is published on PyPI as `appsec-scan-router` for package continuity. The primary commands are now
`appsec-inventory-service` and `appsec-inventory-service-ui`; older command names remain available as compatibility
aliases.

## Capabilities

- Scans Azure DevOps or GitHub Enterprise organizations
- Scans the entire organization when Azure DevOps `--project` or GitHub `--repo` is omitted
- Scans one resolved branch per repository: default branch first, then deployment or production-like fallback branches
- Detects Android, iOS, Flutter, React Native, Expo, Ionic, Capacitor, Cordova, Xamarin, and .NET MAUI
- Detects web frontends, web backends, API services, microservices, middleware workers, serverless apps, containers, and deployment descriptors
- Detects AI-enabled applications using LLM SDKs, AI orchestration frameworks, ML inference libraries, vector stores, and cloud AI services
- Extracts inventory name, version, language, categories, mobile bundle/package identifiers, contributors, and last activity
- Splits Excel output into active and older worksheets based on the configured branch age window
- Optionally validates public Apple App Store and Google Play listings from detected mobile identifiers
- Emits CSV, JSON, XLSX, Semgrep target lists, SonarQube project manifests, and generic scanner target manifests
- Runs as a CLI, browser UI, Docker image, SDK, or importable library

## Install

```bash
python -m pip install appsec-scan-router
```

```bash
appsec-inventory-service --help
appsec-inventory-service-ui --help
```

For local development:

```bash
git clone https://github.com/h0p3sf4ll/appsec-inventory-service.git
cd appsec-inventory-service
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
```

## Publishing

Releases publish to PyPI through GitHub Actions Trusted Publishing. Configure the PyPI project publisher with:

| Field | Value |
| --- | --- |
| Repository owner | `h0p3sf4ll` |
| Repository name | `appsec-inventory-service` |
| Workflow filename | `publish.yml` |
| Environment name | `pypi` |

Create the `pypi` environment under GitHub repository settings before publishing. Required reviewers are strongly
recommended for that environment so package publishing is separated from ordinary commit access.

## Azure DevOps

Set a read-only PAT:

```bash
export ADO_PAT="your-token"
```

Scan every project in an organization:

```bash
appsec-inventory-service \
  --provider azure-devops \
  --org FabrikamCloud \
  --application-type mobile_app \
  --application-type ai_enabled \
  --out-dir reports
```

Scan one project:

```bash
appsec-inventory-service \
  --provider azure-devops \
  --org FabrikamCloud \
  --project "Go_To_Market" \
  --out-dir reports
```

`azure-devops` is the default provider, so `--provider azure-devops` can be omitted.

Use `--application-type` to narrow results. It can be repeated and defaults to all supported types when omitted.
Valid values are `mobile_app`, `web_app`, `api_service`, `microservice`, `middleware`, `serverless`, `library`,
`infrastructure`, and `ai_enabled`.

Stream results into a local PostgreSQL table while reports are being written:

```bash
export APPSEC_INVENTORY_POSTGRES_DSN="postgresql://postgres:postgres@localhost:5432/postgres"

appsec-inventory-service \
  --provider azure-devops \
  --org FabrikamCloud \
  --out-dir reports \
  --postgres-table appsec_inventory_assets
```

Those PostgreSQL credentials are for local development only. Use a secret manager or environment-level secret injection
for shared environments.

## GitHub Enterprise

Set a read-only token:

```bash
export GITHUB_TOKEN="your-token"
```

Scan every repository owned by an organization or user:

```bash
appsec-inventory-service \
  --provider github-enterprise \
  --base-url https://github.fabrikam.example/api/v3 \
  --org FabrikamCloud \
  --out-dir reports
```

Scan one repository:

```bash
appsec-inventory-service \
  --provider github-enterprise \
  --base-url https://github.fabrikam.example/api/v3 \
  --org FabrikamCloud \
  --repo payments-api \
  --out-dir reports
```

`--project` is accepted as a GitHub repository alias for teams that use one shared automation template.

## Docker

Build the image:

```bash
docker build -t appsec-inventory-service .
```

Run the browser UI on port `48731`:

```bash
mkdir -p reports
docker run --rm \
  -p 48731:48731 \
  -e ADO_PAT="$ADO_PAT" \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -e APPSEC_INVENTORY_POSTGRES_PASSWORD=postgres \
  -v "$PWD/reports:/reports" \
  appsec-inventory-service \
  ui \
  --host 0.0.0.0 \
  --port 48731 \
  --reports-dir /reports
```

Open `http://localhost:48731`.

PostgreSQL sync is enabled by default in the UI. For local development from Docker, use:

| Field | Local development value |
| --- | --- |
| Host | `host.docker.internal` |
| Port | `5432` |
| Database | `postgres` |
| User | `postgres` |
| Password | `postgres` |
| Table | `appsec_inventory_assets` |

The local password can be supplied as `APPSEC_INVENTORY_POSTGRES_PASSWORD=postgres` so it is not stored in the browser.

Run a CLI scan in the container:

```bash
mkdir -p reports
docker run --rm \
  -e ADO_PAT="$ADO_PAT" \
  -v "$PWD/reports:/reports" \
  appsec-inventory-service \
  --provider azure-devops \
  --org FabrikamCloud \
  --out-dir /reports
```

GitHub Enterprise CLI scan:

```bash
mkdir -p reports
docker run --rm \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -v "$PWD/reports:/reports" \
  appsec-inventory-service \
  --provider github-enterprise \
  --base-url https://github.fabrikam.example/api/v3 \
  --org FabrikamCloud \
  --out-dir /reports
```

The image runs as a non-root user and writes reports to `/reports`.

## Browser UI

```bash
appsec-inventory-service-ui --host 127.0.0.1 --port 48731 --reports-dir reports
```

The UI includes provider selection, GitHub sign-in, secure token saving, whole-organization scans, confidence controls,
activity mode, application type filters, branch age cutoff, worker tuning, mobile-only store lookup, live logs, stop
control, a scan status bar, and a dedicated reports tab. Required and optional fields are labeled, scan defaults are
shown inline, and ETA is calculated from structured scanner progress events.

The report prefix is fixed to `appsec_inventory_service`. It controls generated report names only; it is not an
application type, scan target, or service instance name.

Preferred environment variables:

| Variable | Purpose |
| --- | --- |
| `APPSEC_INVENTORY_SERVICE_UI_HOST` | Default UI host |
| `APPSEC_INVENTORY_SERVICE_UI_PORT` | Default UI port |
| `APPSEC_INVENTORY_SERVICE_REPORTS_DIR` | Default reports directory |
| `APPSEC_INVENTORY_SERVICE_GITHUB_CLIENT_ID` | GitHub OAuth app client ID for UI sign-in |
| `APPSEC_INVENTORY_SERVICE_GITHUB_CLIENT_SECRET` | GitHub OAuth app secret for UI sign-in |
| `APPSEC_INVENTORY_SERVICE_SECRET_KEY` | Optional Fernet key for encrypted token storage |
| `APPSEC_INVENTORY_SERVICE_STATE_DIR` | Optional secure storage directory |
| `APPSEC_INVENTORY_POSTGRES_PASSWORD` | Server-side PostgreSQL password used by the UI DSN builder |

Legacy `APPSEC_SCAN_ROUTER_*` UI variables are still accepted.

For GitHub sign-in, create a GitHub OAuth app and set the callback URL to:

```text
http://localhost:48731/api/auth/github/callback
```

Saved provider tokens are encrypted at rest under the UI state directory and are never returned to the browser. In
shared deployments, set `APPSEC_INVENTORY_SERVICE_SECRET_KEY` from a secret manager instead of relying on the generated
local key file.

## Branch Selection

Each repository contributes one branch to the inventory.

1. If the repository has a default branch, that branch is scanned.
2. If no default branch exists, Azure DevOps build definitions or GitHub deployment refs are inspected.
3. If those are unavailable, the scanner chooses the strongest production or mainline branch name, including
   `production`, `prod`, `preprod`, `release`, `staging`, `main`, `master`, `development`, `develop`, and `dev`.

There is no universal production branch field across source control and delivery platforms. Deployment fallback is
best-effort and depends on token permissions.

## Detection Model

Detection is evidence-based. The scanner fetches only allow-listed files that carry application or service signals,
including:

- Mobile manifests and project files: `AndroidManifest.xml`, `Info.plist`, `project.pbxproj`, `.xcconfig`, `.csproj`,
  `pubspec.yaml`, `capacitor.config.*`, `ionic.config.json`, and `config.xml`
- Build and dependency manifests: `package.json`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `pyproject.toml`,
  `requirements.txt`, `Pipfile`, `go.mod`, `Cargo.toml`, `composer.json`, and `Gemfile`
- Runtime and deployment descriptors: `Dockerfile`, Compose files, Helm charts, Kustomize files, Serverless files,
  Spring application config, Terraform `main.tf`, and Azure pipeline YAML
- AI indicators: OpenAI, Azure AI, Anthropic, Gemini, Bedrock, LangChain, LlamaIndex, Semantic Kernel, Spring AI,
  TensorFlow, PyTorch, ONNX Runtime, Hugging Face, Pinecone, Chroma, Qdrant, Weaviate, and related structured
  dependency or runtime configuration signals

Weak indicators are not enough on their own. A generic `.csproj`, a generic `config.xml`, or a standalone Dockerfile
will not be treated as a strong application match without supporting framework, manifest, or dependency evidence.

## AI Inventory Signals

AI-enabled assets are returned with `type_ai_enabled=TRUE`. More specific filter columns explain why the asset was
classified:

| Column | Meaning |
| --- | --- |
| `category_llm_integration` | Uses an LLM or generative AI SDK |
| `category_ai_orchestration` | Uses an agent or AI orchestration framework |
| `category_ml_inference` | Uses local or hosted model inference libraries |
| `category_vector_search` | Uses vector storage or retrieval dependencies |
| `category_ai_service_integration` | Uses cloud AI APIs such as vision, document intelligence, speech, or language services |

The scanner does not treat README mentions or arbitrary prose as AI evidence. It relies on package manifests,
project files, container descriptors, and runtime configuration that are already part of the allow-listed scan set.

## Mobile Metadata And Store Validation

Mobile fields are populated when source manifests expose them:

| Field | Meaning |
| --- | --- |
| `mobile_name` | App display name |
| `mobile_version` | App version after placeholder filtering |
| `mobile_identifier` | Android package or Apple bundle identifier |
| `mobile_identifier_source` | Source family where the identifier was found |
| `mobile_identifier_status` | `found` or `missing_from_scanned_files` |

The scanner resolves common indirection patterns such as Gradle properties, Xcode build settings, MSBuild props, iOS
plist references, and Android string resources. It does not invent identifiers. Missing identifiers usually mean the
value is generated by CI/CD, stored in private variables, assembled by flavor-specific build logic, or absent from the
scanned branch.

Enable public store lookup:

```bash
appsec-inventory-service \
  --provider azure-devops \
  --org FabrikamCloud \
  --out-dir reports \
  --store-lookup \
  --store-country US
```

Store validation fields return `TRUE` when the requested public store listing is found and `FALSE` when lookup is
disabled, unavailable, missing, or not publicly visible.

## Outputs

Reports are created when the scan starts and updated as matching assets are detected.

Default output names:

- `appsec_inventory_service.csv`
- `appsec_inventory_service.json`
- `appsec_inventory_service.xlsx`
- `appsec_inventory_service_scanner_targets.csv`
- `appsec_inventory_service_scanner_targets.json`
- `appsec_inventory_service_semgrep_targets.txt`
- `appsec_inventory_service_sonarqube_projects.csv`

The workbook contains two worksheets by default:

- `Active 90d`
- `Older 90d`

Changing `--branch-age-days` changes these sheet names, for example `Active 60d` and `Older 60d`.

Core fields:

| Field | Meaning |
| --- | --- |
| `project` | Azure DevOps project or GitHub owner |
| `repo_name` | Repository name |
| `branch_name` | Branch scanned |
| `branch_last_updated` | Latest commit timestamp seen on that branch |
| `branch_age_bucket` | Active or older worksheet bucket |
| `web_url` | Repository browser URL |
| `source_url` | Clone/source URL when available |
| `inventory_name` | Best available application or service name |
| `inventory_version` | Best available application or service version |
| `inventory_types` | Semicolon-separated inventory types |
| `primary_language` | Best-effort primary language |
| `scanner_target` | Source target with branch metadata for downstream scanner orchestration |
| `semgrep_target` | Semgrep-oriented target reference |
| `sonarqube_project_key` | Stable SonarQube project key suggestion |
| `sonarqube_project_name` | SonarQube project display name suggestion |
| `contributing_developers` | Semicolon-separated commit authors |
| `last_updated` | Compatibility alias for `branch_last_updated` |
| `confidence` | Detection confidence |
| `score` | Weighted evidence score |
| `categories` | Semicolon-separated detection categories |
| `type_*` | Excel-filter-friendly inventory type flags |
| `category_*` | Excel-filter-friendly category flags |
| `detection_evidence` | JSON evidence details |

Scanner sidecars:

- `_scanner_targets.csv` and `_scanner_targets.json` are provider-neutral manifests for orchestration jobs.
- `_semgrep_targets.txt` is a line-oriented target list.
- `_sonarqube_projects.csv` contains project key/name suggestions, branch, source URL, and context columns.

These files are intended for pipeline glue code that checks out each target and runs tools such as Semgrep,
SonarQube Scanner, SCA scanners, or custom security checks.

## CLI Reference

| Option | Default | Description |
| --- | --- | --- |
| `--provider` | `azure-devops` | `azure-devops` or `github-enterprise` |
| `--org` | required | Azure DevOps organization or GitHub owner |
| `--project` | all | Azure DevOps project or GitHub repository name |
| `--repo` | all | GitHub repository name; alias for `--project` |
| `--base-url` | env | GitHub Enterprise API URL |
| `--pat` | env | Provider token; prefer `ADO_PAT`, `GITHUB_TOKEN`, or `GHE_TOKEN` |
| `--out-dir` | current directory | Output directory |
| `--out-prefix` | `appsec_inventory_service` | Output filename prefix, not the service name |
| `--application-type` | all | Repeatable inventory type filter |
| `--max-workers` | `8` | Concurrent repository preparation tasks |
| `--branch-workers` | `16` | Concurrent branch scans |
| `--content-workers` | `16` | Concurrent selected-file fetches |
| `--max-commits-per-repo` | `0` | Commit limit per matched branch; `0` means all available history |
| `--timeout` | `30` | Provider HTTP timeout in seconds |
| `--min-confidence` | `low` | `low`, `medium`, or `high` |
| `--branch-age-days` | `90` | Active/older worksheet cutoff |
| `--activity-mode` | `contributors` | `contributors` or `latest` |
| `--store-lookup` | disabled | Enable public app store enrichment |
| `--store-country` | `US` | Two-letter store country code |
| `--store-timeout` | `15` | Store lookup timeout in seconds |
| `--postgres-dsn` | env | PostgreSQL DSN for streaming upserts; prefer `APPSEC_INVENTORY_POSTGRES_DSN` |
| `--postgres-table` | `appsec_inventory_assets` | Target table for inventory upserts |
| `--verbose` | disabled | Debug logging |

When PostgreSQL sync is enabled, the service creates the table if needed and upserts rows by
`provider`, `organization`, `project`, `repo_name`, and `branch_name`. Rows include `owner_user_id` and
`owner_user_login` so UI-driven scans can be filtered by signed-in user. The typed columns cover common reporting and
scanner-routing fields, and the complete scanner row is retained in `row_data` as JSONB.

## Performance Guidance

For first-pass inventory in a large organization:

```bash
appsec-inventory-service \
  --provider github-enterprise \
  --base-url https://github.fabrikam.example/api/v3 \
  --org FabrikamCloud \
  --out-dir reports \
  --min-confidence medium \
  --activity-mode latest \
  --max-workers 12 \
  --branch-workers 32 \
  --content-workers 32
```

Use `--activity-mode latest` when you only need last-update timestamps. Use `--activity-mode contributors` when the
developer column is required. Leave `--store-lookup` off for the fastest scan.

Increase workers only while the source provider is responding cleanly. Reduce concurrency if you see throttling,
timeouts, or repeated transient errors.

## SDK

```python
from pathlib import Path

from appsec_scan_router import ScanConfig, scan_to_reports

config = ScanConfig(
    provider="github-enterprise",
    base_url="https://github.fabrikam.example/api/v3",
    org="FabrikamCloud",
    pat="your-token",
    project=None,
    out_dir=Path("reports"),
    out_prefix="appsec_inventory_service",
    max_workers=8,
    branch_workers=16,
    content_workers=16,
    max_commits_per_repo=2000,
    timeout_seconds=30,
    min_confidence="medium",
    application_types=("mobile_app", "ai_enabled"),
    branch_age_days=90,
    activity_mode="contributors",
    store_lookup=True,
    store_country="US",
    store_timeout_seconds=15,
    postgres_dsn="postgresql://postgres:postgres@localhost:5432/postgres",
    postgres_table="appsec_inventory_assets",
)

results, csv_path, json_path, xlsx_path = scan_to_reports(config)
```

Object-oriented usage:

```python
from appsec_scan_router import AppSecInventoryService

service = AppSecInventoryService(config)
results, csv_path, json_path, xlsx_path = service.scan_to_reports()
```

Stream rows into another process:

```python
from appsec_scan_router import scan

def handle_row(row):
    print(row["project"], row["repo_name"], row["branch_name"], row["inventory_types"])

rows = scan(config, on_result=handle_row)
```

## Compatibility

These commands remain available:

```bash
appsec-scan-router --help
appsec-scan-router-ui --help
mobile-app-inventory-tracer --org FabrikamCloud --out-dir reports
ado-mobile-scanner --org FabrikamCloud --out-dir reports
```

New integrations should import `appsec_scan_router` and prefer the `appsec-inventory-service` command.

## Test

```bash
python -m unittest discover -s tests
python -m compileall ado_mobile_scanner.py mobile_app_inventory_tracer.py appsec_scan_router mobile_scanner tests
```

## Security Notes

- Use read-only tokens
- Scope tokens to the smallest practical organization, project, or repository set
- Prefer environment variables over `--pat`
- Do not commit generated reports if they contain internal names, URLs, identifiers, or contributor emails
- The scanner does not clone repositories
- The scanner fetches only allow-listed source and configuration files
- Docker runs as a non-root user

## License

AppSec Inventory Service is released under the MIT License. See [LICENSE](LICENSE).
