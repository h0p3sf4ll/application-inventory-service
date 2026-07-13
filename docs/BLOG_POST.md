# From Source Code to an Actionable Application Inventory

Security programs cannot protect applications they cannot identify. In a large organization, the challenge is not producing another repository list. It is determining which repositories contain deployable applications, which branches matter, who owns the work, where those applications run, and how each asset should enter the security-testing pipeline.

Application Inventory Service turns Azure DevOps and GitHub source-control evidence into a branch-aware application inventory. It uses provider APIs to inspect metadata, repository trees, selected manifests, deployment configuration, and commit history. It does not clone repositories, execute repository code, or connect to detected application endpoints.

## Establishing the Inventory

The service scans one or more Azure DevOps organizations and GitHub owners in the same run. It can cover every accessible project and repository or a user-selected scope.

For each repository, the service begins with the default branch. If no default exists, it uses pipeline associations and production-oriented branch names to select the most credible deployable branch. Activity and contributor data are calculated for that branch rather than assumed from the repository as a whole.

Structural evidence then classifies the asset as one or more of the following:

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

The resulting record includes the application name, version, language, application identifiers, contributors, last activity, evidence, source location, and scanner-routing values. Mobile scans can validate identifiers across selected Apple App Store and Google Play countries.

## Linking Source Code to Web Domains

A repository URL identifies source code, not the application endpoint that users or systems reach. The service closes that gap by attributing network-deployable branches to web domains.

Domain evidence is collected from successful GitHub deployment environments, repository homepages, GitHub Pages, ingress manifests, Helm values, Terraform, Azure Pipelines, GitHub Actions, nginx, Caddy, Firebase, Fly.io, and related deployment configuration. Each association retains the repository, branch, normalized domain, URL, environment, evidence source, and confidence tier.

The confidence model is deliberately explicit:

- `confirmed`: a provider reports a successful deployment with an environment URL.
- `configured`: source-controlled deployment configuration or repository metadata declares the endpoint.
- `inferred`: a platform convention supports a credible domain, but the repository does not declare the complete endpoint directly.

The highest-quality association becomes the primary domain while all supported domains remain available for review. Localhost, private IP addresses, unresolved variables, credential-bearing URLs, provider control-plane hosts, and common infrastructure endpoints are rejected to reduce false attribution.

Attribution is evidence, not proof of production ownership. The service does not make outbound requests to detected domains, resolve DNS, inspect TLS, or test availability. This boundary avoids server-side request forgery risk and keeps endpoint validation with the systems authorized to perform it.

## Operational Scale

Inventory collection must respect provider limits. The service uses separate bounded worker pools for source discovery, repositories, branches, and content. Azure DevOps connections are reused and adapt to throttling signals. GitHub App installation tokens and rate-limit state are shared across owners. Commit histories are processed as streams instead of retained in memory.

Domain discovery is similarly bounded. It runs only for network-deployable application types, limits recent deployment inspection, prioritizes production-like environments, and caps status lookups per environment.

Operators can run scans interactively or on one-time, daily, and weekly schedules. Active scans can be paused, resumed, or stopped. Scheduled configurations and embedded credentials are encrypted, scoped to the signed-in user, and processed through the same concurrency controls as interactive scans.

## Durable, Searchable Results

The service writes XLSX inventory reports, Semgrep target lists, and SonarQube project manifests. Results can also be synchronized to a normalized PostgreSQL schema for search, analytics, and export.

Repositories, branch inventory, contributors, application types, categories, mobile store listings, web domains, domain evidence sources, scan runs, and observability events are stored separately. Stable records are updated when their values change instead of duplicated on every scan. Stale associations are removed when the latest scan no longer supports them.

This model supports questions that flat repository lists cannot answer:

- Which active web applications lack an attributed domain?
- Which domains are supported only by inferred evidence?
- Which source branch is associated with a production endpoint?
- Which applications have not changed within the defined activity window?
- Which teams contribute to each deployable branch?
- Which assets have not entered Semgrep or SonarQube workflows?

## Security and Governance

GitHub repository access uses a server-managed GitHub App. Azure DevOps organizations use independently scoped PATs. UI authentication uses GitHub or Google OAuth and remains separate from provider-scanning credentials.

Production deployments should use read-only provider permissions, HTTPS, secure cookies, disabled test login, private database connectivity, encrypted durable state, and a stable encryption key from an approved secret manager. Reports and logs should be treated as sensitive because they can contain internal repository names, application identifiers, domains, and contributor details.

## Management Outcome

Application Inventory Service converts distributed source-control signals into an operating inventory. Security teams gain scanner-ready targets. Platform teams gain a normalized integration point. Engineering leaders gain branch-level ownership and activity data. Governance teams gain exportable evidence with documented confidence and provenance.

The result is a repeatable control: defined sources, bounded collection, evidence-based classification, source-to-domain attribution, durable records, and outputs that integrate with existing security tools.
