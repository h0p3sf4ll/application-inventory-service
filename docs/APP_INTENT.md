# Application Intent

Application Inventory Service gives security, platform, and engineering teams a current inventory of software assets across source-control systems without cloning repositories.

## Problem

Most application security programs struggle to answer basic operational questions:

- Which repositories contain deployable applications?
- Which are mobile apps, APIs, microservices, middleware, web apps, infrastructure, AI-enabled apps, or ML-enabled apps?
- Which branch should a scanner target?
- Who recently contributed to each branch?
- Which assets are active and which are stale?
- How should scanner jobs such as Semgrep or SonarQube receive reliable targets?

## Approach

The service reads provider metadata, repository trees, selected manifests, dependency files, build files, and deployment configuration through Azure DevOps and GitHub Enterprise APIs. It avoids full clone operations and focuses on high-value evidence already available in normal source repositories.

## Intended Users

- Application security teams building an inventory baseline.
- Platform teams routing scanner jobs across many repositories.
- Engineering leaders tracking active application ownership.
- Governance teams needing exportable evidence for reporting.

## Non-Goals

- It is not a vulnerability scanner.
- It does not replace SAST, SCA, secrets scanning, or infrastructure scanning.
- It does not execute code from scanned repositories.
- It does not attempt to infer production truth beyond available branch, pipeline, deployment, and activity signals.

## Primary Outputs

- Human-readable CSV, JSON, and Excel reports.
- Scanner target manifests for orchestration.
- Semgrep target lists.
- SonarQube project metadata suggestions.
- Normalized PostgreSQL tables for analytics and reporting.

## Design Principles

- Read-only provider access.
- No repository cloning.
- Clear evidence fields for every detected inventory category.
- Compatibility with CLI, UI, SDK, Docker, and automation workflows.
- Defaults that work locally but can be hardened for AWS deployment.
