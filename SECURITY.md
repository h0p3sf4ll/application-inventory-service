# Security

Application Security Posture Management is designed for internal software inventory, finding correlation, risk prioritization, and AppSec orchestration. It reads source-provider metadata and selected manifest files without cloning repositories or executing scanned code.

## Security Baseline

The service is aligned to the OWASP Top 10 2025 risk model:

| OWASP area | Control |
| --- | --- |
| Broken Access Control | UI scan, report, inventory, finding, workflow, coverage, profile, and target-discovery APIs require a signed-in session. Queries and exports are scoped by user in SQL. |
| Security Misconfiguration | Production deployments should run behind HTTPS, disable test login, set secure cookies, and use the documented security headers. |
| Software Supply Chain Failures | Runtime dependency floors are set to audited versions. CI runs Bandit and `pip-audit`. SBOM files are maintained in `docs/`. |
| Cryptographic Failures | Saved provider tokens and scheduled scan definitions are encrypted with Fernet. Operators should supply `APPLICATION_INVENTORY_SERVICE_SECRET_KEY` from a secret manager. |
| Injection | Database writes use psycopg parameters and identifiers. Shell execution is avoided for scans; child process commands are argument arrays. |
| Insecure Design | The app minimizes repository access, avoids code execution, applies conservative finding-to-asset correlation, preserves ambiguous findings as unlinked, and limits destructive reconciliation to explicit complete snapshots. |
| Authentication Failures | GitHub and Google OAuth flows use high-entropy state values, session cookies are HttpOnly and SameSite, and CSRF tokens protect state-changing APIs. |
| Software or Data Integrity Failures | XML manifest parsing uses `defusedxml`. Finding imports are bounded, normalized, deduplicated, and transactional. Public package publishing is handled by GitHub Actions with a protected `pypi` environment. |
| Security Logging and Alerting Failures | Scan activity is logged for operators without intentionally logging provider tokens or database DSNs. Production logs should be routed to a SIEM. |
| Mishandling Exceptional Conditions | UI database exports, scanner imports, and OAuth failures return sanitized messages rather than raw secret-bearing exception details. Failed imports retain a bounded audit message while partial finding changes roll back. |

## Required Production Settings

Set these values for shared or production deployments:

```bash
APPLICATION_INVENTORY_SERVICE_COOKIE_SECURE=true
APPLICATION_INVENTORY_SERVICE_TEST_LOGIN_ENABLED=false
APPLICATION_INVENTORY_SERVICE_PUBLIC_URL=https://inventory.example.com
APPLICATION_INVENTORY_SERVICE_SECRET_KEY=<fernet-key-from-secret-manager>
APPLICATION_INVENTORY_SERVICE_ALLOWED_GITHUB_HOSTS=github.example.com
APPLICATION_INVENTORY_POSTGRES_DSN=<dsn-from-secret-manager>
```

Use read-only Azure DevOps and GitHub tokens. Do not reuse personal administrative tokens.

## Secret Handling

- Store production secrets in AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, or an approved enterprise secret manager.
- Rotate provider tokens and OAuth client secrets on a defined cadence.
- Do not pass provider tokens in command history. Prefer environment variables, secret manager injection, or encrypted UI token storage.
- Treat any token pasted into chat, terminal output, logs, screenshots, or issue trackers as exposed and rotate it.
- Use a stable Fernet key in production. If the key changes, saved UI provider tokens and schedules cannot be decrypted.

## HTTP Security

The UI sends:

- Content Security Policy with `default-src 'self'` and `frame-ancestors 'none'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` denying sensitive browser capabilities
- HSTS when secure cookies are enabled

State-changing API calls require the session CSRF token.

## Scanner Finding Controls

- The UI limits scanner files to 20 MB; the API limit defaults to 25 MB and can only be changed server-side.
- A single import is limited to 100,000 normalized findings.
- Scanner JSON is treated as data. The service does not execute rules, fixes, repository content, markup, or links from scanner output.
- Browser output escapes finding, tool, repository, path, assignee, and event values before insertion into HTML.
- Tool keys and deterministic fingerprints define deduplication scope. Pipelines should keep tool keys stable.
- Complete snapshots may resolve findings and should be restricted to trusted scanner automation.
- Finding imports, identifiers, events, and coverage updates commit atomically. Failed imports are auditable.
- Scanner URLs are displayed as data unless a trusted integration explicitly uses them; credentials must not be embedded in scanner URLs.

## Provider URL Controls

GitHub Enterprise URLs must use HTTPS by default. HTTP can only be enabled with:

```bash
APPLICATION_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS=true
```

Use that only for isolated local testing. In production, set:

```bash
APPLICATION_INVENTORY_SERVICE_ALLOWED_GITHUB_HOSTS=github.example.com
```

## Verification

Run these checks before release:

```bash
python -m unittest discover -s tests
python -m compileall appsec_scan_router application_inventory_service tests
node --check appsec_scan_router/ui_static/app.js
bandit -r appsec_scan_router application_inventory_service ado_mobile_scanner.py mobile_app_inventory_tracer.py -x tests -ll
pip-audit -r requirements.txt
python -m json.tool docs/SBOM.cdx.json >/dev/null
```

## Vulnerability Reporting

Open a private security advisory in GitHub if the repository is hosted there. Include affected version, impact, reproduction steps, and recommended remediation when known.
