# Architecture

## Logical View

```mermaid
flowchart LR
  User["Security / Platform User"] --> UI["Application Inventory Service UI"]
  Automation["CLI / SDK / Scheduler"] --> Core["Inventory Engine"]
  UI --> Core
  Core --> ADO["Azure DevOps API"]
  Core --> GHE["GitHub Enterprise API"]
  Core --> Stores["Apple / Google Store Lookup"]
  Core --> Reports["XLSX / Semgrep Targets / SonarQube Targets"]
  Core --> DB["PostgreSQL Inventory Schema"]
  Reports --> Scanners["Semgrep / SonarQube / SCA / Custom Scanners"]
  DB --> BI["Dashboards / Data Exports"]
```

## Runtime Components

| Component | Responsibility |
| --- | --- |
| UI service | Login, credential handling, scan configuration, live logs, report download, database export |
| CLI | Non-interactive scans for automation and scheduled inventory jobs |
| SDK | Importable API for other applications and orchestration processes |
| Inventory engine | Provider traversal, branch selection, detection, metadata extraction, activity extraction |
| Report writer | Streaming XLSX inventory, Semgrep target, and SonarQube target outputs |
| PostgreSQL writer | Normalized upserts scoped by owner/user |
| Store lookup client | Optional mobile app store validation |

## Data Flow

1. A user or automation submits source provider credentials and scan options.
2. For a mixed scan, the engine resolves Azure DevOps organizations and the GitHub Enterprise owner as separate source contexts.
3. The service lists accessible projects or repositories for every configured source.
4. The engine resolves one branch per repository.
5. The engine reads repository trees and selected manifest/configuration files.
6. Detection evidence is converted into inventory types, categories, metadata, contributors, timestamps, and a provider value.
7. Results from every source stream through the same report writer and PostgreSQL writer.
8. Scanner manifests are consumed by downstream security tooling.

The service emits structured lifecycle, request, scan, and provider-authentication events to the configured PostgreSQL observability table. The UI exposes health and metrics endpoints without exposing provider secrets.

## Storage Model

The UI writes local reports and encrypted token state under the configured reports/state directory. In production, mount durable storage such as Amazon EFS. Inventory data should be stored in Amazon RDS for PostgreSQL.

## Security Model

- Provider credentials are read-only and scoped as narrowly as practical; GitHub Enterprise uses an installed GitHub App by default.
- GitHub App private keys remain in secret storage or a secret-mounted file and are never placed in generated scan commands.
- Saved UI tokens are encrypted with Fernet.
- PostgreSQL rows are scoped by signed-in user.
- OAuth should be configured with a dedicated callback domain.
- Production secrets should be stored in AWS Secrets Manager and injected into ECS tasks.
