# Security

Application Inventory Service is designed for internal inventory and AppSec orchestration. It reads source-provider metadata and selected manifest files without cloning repositories or executing scanned code.

## Security Baseline

The service is aligned to the OWASP Top 10 2025 risk model:

| OWASP area | Control |
| --- | --- |
| Broken Access Control | UI scan, report, database, and target-discovery APIs require a signed-in session. Reports and database exports are scoped by user. |
| Security Misconfiguration | Production deployments should run behind HTTPS, disable test login, set secure cookies, and use the documented security headers. |
| Software Supply Chain Failures | Runtime dependency floors are set to audited versions. CI runs Bandit and `pip-audit`. SBOM files are maintained in `docs/`. |
| Cryptographic Failures | Saved provider tokens are encrypted with Fernet. Operators should supply `APPLICATION_INVENTORY_SERVICE_SECRET_KEY` from a secret manager. |
| Injection | Database writes use psycopg parameters and identifiers. Shell execution is avoided for scans; child process commands are argument arrays. |
| Insecure Design | The app minimizes repository access, avoids code execution, and emits scanner target manifests for downstream security tooling. |
| Authentication Failures | GitHub and Google OAuth flows use high-entropy state values, session cookies are HttpOnly and SameSite, and CSRF tokens protect state-changing APIs. |
| Software or Data Integrity Failures | XML manifest parsing uses `defusedxml`. Public package publishing is handled by GitHub Actions with a protected `pypi` environment. |
| Security Logging and Alerting Failures | Scan activity is logged for operators without intentionally logging provider tokens or database DSNs. Production logs should be routed to a SIEM. |
| Mishandling Exceptional Conditions | UI database exports and OAuth failures return sanitized messages rather than raw secret-bearing exception details. |

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
- Use a stable Fernet key in production. If the key changes, saved UI provider tokens cannot be decrypted.

## HTTP Security

The UI sends:

- Content Security Policy with `default-src 'self'` and `frame-ancestors 'none'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` denying sensitive browser capabilities
- HSTS when secure cookies are enabled

State-changing API calls require the session CSRF token.

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
