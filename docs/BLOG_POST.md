# Building an Actionable Application Inventory

Security tooling cannot cover assets that the organization cannot identify. The practical problem is establishing a current list of applications, owners, active branches, and scanner targets across source-control platforms.

Application Inventory Service addresses that problem for Azure DevOps and GitHub Enterprise. It reads provider metadata, repository trees, selected manifests, build files, and commit history through supported APIs. It does not clone repositories or execute repository code.

## Operating Model

The service resolves one deployable branch per repository, beginning with the configured default branch and using pipeline or production-oriented fallback signals when necessary. It then classifies the repository from structural and manifest evidence.

The resulting record includes:

- Application type and detection evidence
- Application name, version, and primary language
- Mobile identifiers and optional app-store validation
- Branch contributors and last activity
- Semgrep and SonarQube routing values
- Source organization, project, repository, branch, and URLs

Results are written to XLSX, Semgrep, and SonarQube target files and can be synchronized into normalized PostgreSQL tables.

## Scale and Control

Large organizations require bounded concurrency rather than unrestricted parallel calls. The service separates source, repository, branch, and content worker pools. Azure DevOps requests use connection reuse, adaptive pacing, and retry handling. Commit histories are reduced as streams, avoiding full-history retention in memory.

Operators can pause, resume, or stop scans. One-time, daily, and weekly schedules use the same bounded process manager as interactive work. Schedule definitions and embedded credentials are encrypted and scoped to the signed-in user.

## Security Position

GitHub repository access uses a server-managed GitHub App. Azure DevOps organizations use separately scoped PATs. OAuth authenticates UI users; it is not a substitute for repository-scanning credentials.

Shared deployments should use HTTPS, secure cookies, disabled test login, a stable Fernet key from a secret manager, private database connectivity, durable encrypted state storage, and read-only provider permissions.

## Management Value

The service converts source-control data into an inventory that can drive coverage decisions. Leaders can distinguish active from stale assets, identify ownership gaps, segment work by application type, and route repositories into existing security tools without maintaining a separate manual spreadsheet.

The result is a measurable inventory process: defined inputs, repeatable classification, controlled execution, and outputs suitable for both operators and reporting systems.
