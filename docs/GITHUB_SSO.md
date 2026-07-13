# GitHub SSO

GitHub OAuth authenticates people to the Application Inventory Service UI. Repository discovery and scanning use separate GitHub App credentials. Configure both capabilities when the service must protect the UI and scan private repositories.

## Prerequisites

- A stable HTTPS hostname for the service
- Permission to create or manage a GitHub OAuth App
- A secret manager for the OAuth client secret and service encryption key
- Secure cookies enabled in shared environments

Use `https://github.com` for GitHub Enterprise Cloud. For GitHub Enterprise Server, use the server origin, such as `https://github.example.com`.

## 1. Register the OAuth App

In GitHub, open **Settings**, **Developer settings**, **OAuth Apps**, and select **New OAuth App**.

Set these values:

| Field | Value |
| --- | --- |
| Application name | `Application Inventory Service` |
| Homepage URL | `https://inventory.example.com` |
| Authorization callback URL | `https://inventory.example.com/api/auth/github-enterprise/callback` |

The callback URL must exactly match the public service URL, scheme, host, path, and port. Generate a client secret and place it in the deployment secret manager.

## 2. Generate the Service Encryption Key

Generate one Fernet key and retain it across restarts and deployments:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store the result in a secret manager. Changing the key makes previously encrypted sessions, credentials, and schedules unreadable.

## 3. Configure the Service

```bash
export APPLICATION_INVENTORY_SERVICE_PUBLIC_URL="https://inventory.example.com"
export APPLICATION_INVENTORY_SERVICE_GHE_BASE_URL="https://github.com"
export APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_ID="your-oauth-client-id"
export APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_SECRET="your-oauth-client-secret"
export APPLICATION_INVENTORY_SERVICE_GHE_SCOPE="read:user read:org"
export APPLICATION_INVENTORY_SERVICE_SECRET_KEY="your-fernet-key"
export APPLICATION_INVENTORY_SERVICE_COOKIE_SECURE=true
export APPLICATION_INVENTORY_SERVICE_TEST_LOGIN_ENABLED=false
```

For GitHub Enterprise Server, replace `https://github.com` with the Enterprise server origin. Do not include a repository path. An `/api/v3` suffix is accepted and normalized by the service.

The default `read:user read:org` scopes support user identity and organization membership. Add broader scopes only when an approved use case requires them.

## 4. Configure the Reverse Proxy

Terminate TLS at the load balancer or reverse proxy and forward the original host and scheme:

```text
X-Forwarded-Host: inventory.example.com
X-Forwarded-Proto: https
```

Keep the application listener private. Restrict inbound traffic to the reverse proxy and restrict outbound traffic to GitHub, PostgreSQL, and approved identity endpoints.

## 5. Start and Verify

Restart the UI service after setting the environment variables:

```bash
application-inventory-service-ui --host 0.0.0.0 --port 48731 --reports-dir reports
```

Verify the backend configuration without exposing secrets:

```bash
curl -s https://inventory.example.com/api/config
```

The response should contain:

```json
{"auth":{"githubEnterpriseLoginEnabled":true}}
```

Open the service and select **GitHub Enterprise**. After authorization, GitHub redirects to the configured callback and the application creates an encrypted, user-scoped session.

## Organization SSO Approval

An organization may require an owner to approve the OAuth App or authorize it for SAML SSO. Complete that approval in GitHub before testing with organization members. Keep the OAuth App limited to the organizations and users authorized to access inventory data.

GitHub OAuth authenticates a GitHub identity; it does not automatically make every deployment employee-only. For GitHub Enterprise Managed Users, own the OAuth App inside the managed enterprise. For other account models, place the service behind an organization-aware access proxy or equivalent membership policy. OAuth App access restrictions control access to organization resources but should not be treated as the only UI authorization boundary.

## Repository Scanning Credentials

UI login does not replace the GitHub App used by the scanner. Configure these server-side values separately:

```bash
export APPLICATION_INVENTORY_GITHUB_APP_ID="your-github-app-id"
export APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID="your-installation-id"
export APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE="/run/secrets/github-app.pem"
export APPLICATION_INVENTORY_GITHUB_URLS="organization-a,organization-b"
```

Mount the PEM file read-only, grant the GitHub App only the required read permissions, and never place the private key or OAuth client secret in the browser.

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| Login option is disabled | Confirm all `GHE_BASE_URL`, `GHE_CLIENT_ID`, and `GHE_CLIENT_SECRET` values are set, then restart the service. |
| Callback returns an error | Compare the registered callback URL with `APPLICATION_INVENTORY_SERVICE_PUBLIC_URL` and confirm the proxy forwards the HTTPS scheme and public host. |
| User can log in but cannot see organization resources | Confirm organization OAuth approval, SAML authorization, and the requested scopes. |
| Login works until restart | Keep `APPLICATION_INVENTORY_SERVICE_SECRET_KEY` stable and mount the reports/state directory on durable encrypted storage. |
| Repositories cannot be loaded | Validate the separate GitHub App installation, permissions, installation ID, and mounted PEM file. |

## GitHub References

- [Creating an OAuth App](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app)
- [Authorizing OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [OAuth App access restrictions](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions)
- [OAuth App security practices](https://docs.github.com/en/enterprise-cloud@latest/apps/oauth-apps/building-oauth-apps/best-practices-for-creating-an-oauth-app)
