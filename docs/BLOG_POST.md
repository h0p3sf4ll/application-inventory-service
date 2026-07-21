# Building an Evidence-Based Application Security Posture

Security teams cannot manage application risk from separate repository lists, scanner dashboards, spreadsheets, and ticket queues. The operating problem is integration: identify the applications that matter, connect findings to the right source branch, establish business context, and move the highest-risk work to closure.

Application Security Posture Management provides that system of record for Azure DevOps and GitHub Enterprise environments. It combines application discovery, scanner findings, risk prioritization, coverage, and remediation workflow while preserving the existing tools that perform security testing.

## Establish the Application Baseline

The service scans one or more Azure DevOps organizations and GitHub owners in the same run. It starts with each repository's default branch. When no default exists, it uses pipeline associations and production-oriented branch names to select the most credible deployable branch.

Provider metadata, repository structure, manifests, dependencies, deployment configuration, and commit history classify each branch as one or more of the following:

- Mobile application
- Web application
- API service
- Microservice
- Middleware
- Serverless workload
- Library
- Infrastructure
- AI-enabled application
- ML-enabled application

The record includes application name, version, language, identifiers, contributors, last activity, evidence, source location, deployment domains, and scanner-routing values. Collection uses provider APIs; it does not clone repositories or execute application code.

## Correlate Security Findings

Security tools publish SARIF, Semgrep JSON, SonarQube issues, or a generic finding contract. The ingestion service normalizes rule identity, severity, location, package data, CWE, CVE, CVSS, EPSS, exploit evidence, remediation, and source context.

Findings are matched conservatively to the branch inventory. Exact source identity produces a linked application finding. Missing or ambiguous identity remains visible as an unlinked finding rather than creating a false association. Deterministic fingerprints update repeated results instead of duplicating them.

Complete scanner snapshots can resolve active findings that are no longer present for explicitly listed targets. Partial imports never remove prior results. Every import is transactional, and a failed import leaves an audit record without partial finding or coverage changes.

## Prioritize Business Risk

Technical severity alone does not establish business priority. The risk engine combines:

- Severity, CVSS, EPSS, and known exploit evidence
- Finding age
- Internet exposure
- Application criticality
- Data classification

The outcome is a bounded score with a stored explanation of every contributing factor. Product and security teams can update application context without changing scanner evidence. Linked findings are recalculated in the same transaction.

## Operate Remediation

The remediation queue supports open, triaged, in-progress, resolved, accepted-risk, and false-positive states. Teams can assign owners, set due dates, add decision notes, search and filter the queue, and export the current view as XLSX, CSV, or JSON.

Every workflow change creates an audit event. Default service levels provide a consistent starting point: 7 days for critical findings, 30 for high, 90 for medium, 180 for low, and 365 for informational results.

The posture dashboard reports active critical and high findings, affected assets, overdue work, average contextual risk, priority applications, tool health, and scanner coverage. Coverage identifies current, stale, expired, and untested applications by tool and branch.

## Link Source to Runtime Context

For network-deployable assets, the service attributes branches to web domains using successful deployment environments, repository metadata, ingress manifests, Helm values, Terraform, Azure Pipelines, GitHub Actions, and related configuration.

Each association retains its source and confidence tier. The service rejects localhost, private IP addresses, unresolved variables, credential-bearing URLs, and common control-plane hosts. It does not connect to attributed domains, resolve DNS, inspect TLS, or test availability. That boundary limits server-side request forgery risk and leaves runtime validation with authorized systems.

## Scale the Control

Source, repository, branch, and content work use separate bounded concurrency layers. Azure DevOps connections adapt to throttling. GitHub App installation tokens and rate-limit state are shared across owners. Commit pages stream through memory, PostgreSQL writes use short transactions, and scanner imports cache application resolution for all findings in the same source scope.

Interactive and scheduled scans use the same durable runtime. Scans can be paused, resumed, stopped, and reattached after a UI restart on the same host. Credentials, sessions, schedules, and active run state are encrypted and scoped to the signed-in user.

## Management Outcome

The service creates one operating view across software ownership and security risk:

- Security teams gain a prioritized, auditable remediation queue.
- Engineering teams gain application-specific ownership, due dates, and evidence.
- Platform teams gain stable inventory and scanner integration contracts.
- Governance teams gain coverage, risk, and decision records suitable for reporting.

The result is a measurable control cycle: discover applications, ingest evidence, correlate findings, prioritize risk, remediate decisions, and verify scanner coverage.
