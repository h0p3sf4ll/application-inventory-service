# Application Inventory Service: Practical Inventory for Modern AppSec

Security programs rarely fail because teams lack scanners. They fail because the organization does not have a reliable view of what should be scanned, who owns it, when it changed, and how to route it into the right control.

Application Inventory Service addresses that operating gap.

## What It Is

Application Inventory Service discovers applications across Azure DevOps and GitHub Enterprise without cloning repositories. It inventories mobile apps, web apps, API services, microservices, middleware, serverless workloads, infrastructure code, libraries, AI-enabled applications, and ML-enabled applications.

The service produces practical outputs: CSV, JSON, XLSX, PostgreSQL records, Semgrep target lists, SonarQube project manifests, and generic scanner manifests. It also provides a CLI, SDK, Docker container, and browser UI for teams that need both automation and an operator-facing workflow.

## Why It Matters

Most AppSec teams know their scanner coverage is incomplete. The hard part is not only scanning. It is building a trustworthy routing layer between source platforms and security tooling.

Application Inventory Service gives teams that routing layer. It detects application type, branch activity, contributors, app identifiers, versions, store validation status, last update time, and evidence. That context lets security teams prioritize active systems, reduce wasted scanning, and build clearer accountability with engineering.

## What It Does Well

- Finds active software assets across large Azure DevOps and GitHub Enterprise estates.
- Supports multiple Azure DevOps organizations with separate PATs.
- Lets users select target projects and repositories from the UI.
- Stores normalized inventory in PostgreSQL by signed-in user.
- Produces scanner-ready outputs for downstream AppSec workflows.
- Supports GitHub, Google, and local development login flows.
- Handles mobile store validation when mobile identifiers are available.
- Detects AI and ML usage signals alongside traditional application categories.

## Security Posture

The service is designed for controlled enterprise deployment. It supports encrypted token storage, secure cookies, CSRF checks, constrained provider hostnames, PostgreSQL-backed reporting, non-root container execution, and cloud deployment patterns that place compute and data services behind private network boundaries.

Deployment guidance is included for AWS and Azure with emphasis on encryption, least privilege, private networking, secret rotation, immutable image tags, scanner-safe output, and audit-friendly operations.

## Executive Takeaway

Application Inventory Service is not another scanner. It is the connective tissue between source control, ownership, inventory, and security execution. It gives AppSec leaders a clearer asset base, gives engineers a more predictable path into security tooling, and gives platform teams a deployable service that can scale from local analysis to enterprise operations.

The result is a stronger inventory foundation with less manual tracking and better routing into the security controls teams already use.
