# Application Intent

Application Security Posture Management gives security, platform, and engineering teams a current software inventory, a correlated security finding system of record, and an operational remediation workflow without cloning repositories.

## Problem

Most application security programs struggle to answer basic operational questions:

- Which repositories contain deployable applications?
- Which are mobile apps, APIs, microservices, middleware, web apps, infrastructure, AI-enabled apps, or ML-enabled apps?
- Which branch should a scanner target?
- Who recently contributed to each branch?
- Which assets are active and which are stale?
- How should scanner jobs such as Semgrep or SonarQube receive reliable targets?
- Which active findings create the greatest business risk?
- Which applications lack recent scanner coverage?
- Who owns remediation, when is it due, and what decision history exists?

## Approach

The service reads provider metadata, repository trees, selected manifests, dependency files, build files, and deployment configuration through Azure DevOps and GitHub Enterprise APIs. It avoids full clone operations and focuses on high-value evidence already available in normal source repositories.

For network-deployable assets, the service attributes source branches to web domains through successful deployment environment URLs, repository metadata, and structured deployment configuration. Every domain retains its source and confidence tier. Attribution describes available evidence; it does not prove DNS ownership, reachability, or production approval.

Scanner results enter through SARIF, Semgrep JSON, SonarQube issue JSON, or a documented generic contract. The service deduplicates findings, correlates them to inventory, scores technical and business risk, preserves workflow history, and measures coverage by application and scanner.

## Intended Users

- Application security teams building an inventory baseline.
- Platform teams routing scanner jobs across many repositories.
- Engineering leaders tracking active application ownership.
- Governance teams needing exportable evidence for reporting.
- Product security teams coordinating risk acceptance and remediation service levels.

## Non-Goals

- It does not replace the scanners that produce vulnerability findings.
- It does not replace SAST, SCA, secrets scanning, or infrastructure scanning.
- It does not execute code from scanned repositories.
- It does not attempt to infer production truth beyond available branch, pipeline, deployment, and activity signals.
- It does not connect to attributed domains or perform availability, TLS, DNS, or ownership validation.
- It does not infer business criticality or data classification; accountable teams provide that context.

## Primary Outputs

- Human-readable Excel reports.
- Semgrep target lists.
- SonarQube project metadata suggestions.
- Normalized PostgreSQL tables for analytics and reporting.
- Live, user-scoped inventory search with XLSX, CSV, and JSON exports.
- Optional local natural-language query planning without sharing inventory records with the model.
- Encrypted recurring scan definitions for repeatable inventory operations.
- Deduplicated scanner findings with searchable XLSX, CSV, and JSON exports.
- Explainable application risk, scanner coverage, remediation assignments, due dates, and audit history.

## Design Principles

- Read-only provider access.
- No repository cloning.
- Clear evidence fields for every detected inventory category.
- Compatibility with CLI, UI, SDK, Docker, and automation workflows.
- Local defaults with documented hardened deployment settings for AWS and Azure.
- Bounded concurrency and explicit backpressure at every network-intensive stage.
