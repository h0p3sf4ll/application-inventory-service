# Azure Implementation Guide

This guide describes a production Azure implementation for Application Inventory Service. It covers the application runtime, Azure-hosted persistence, secrets, networking, and Azure DevOps scanning configuration.

## Recommended Architecture

Use Azure Container Apps for the UI and scanner process, Azure Database for PostgreSQL Flexible Server for normalized inventory, Azure Files for report/state persistence, Azure Key Vault for secrets, Azure Container Registry for images, and Azure Monitor for logs and alerts.

```mermaid
flowchart TB
  Users["Users / SSO"] --> FrontDoor["Azure Front Door or Application Gateway\noptional edge control"]
  FrontDoor --> Ingress["Container Apps Ingress\nHTTPS / custom domain"]
  Ingress --> ACA["Azure Container Apps\nApplication Inventory Service"]

  ACA --> Files["Azure Files\n/reports and encrypted UI state"]
  ACA --> Postgres["Azure Database for PostgreSQL Flexible Server\napplication_inventory schema"]
  ACA --> KeyVault["Azure Key Vault\nOAuth, provider tokens, DB DSN, Fernet key"]
  ACA --> Monitor["Azure Monitor / Log Analytics"]
  ACA --> ACR["Azure Container Registry"]

  ACA --> NAT["NAT Gateway / Firewall / Private Egress"]
  NAT --> ADO["Azure DevOps REST APIs"]
  NAT --> GHE["GitHub Enterprise"]
  NAT --> Stores["Apple App Store / Google Play"]

  Pipelines["Azure Pipelines / GitHub Actions"] --> ACR
  Reports["Semgrep / SonarQube / SCA Orchestrators"] --> ACA
  Reports --> Postgres
```

## Service Map

| Capability | Azure service |
| --- | --- |
| Container runtime | Azure Container Apps |
| Image registry | Azure Container Registry |
| Secrets | Azure Key Vault referenced by Container Apps secrets |
| Database | Azure Database for PostgreSQL Flexible Server |
| Persistent reports and encrypted UI state | Azure Files mounted at `/reports` |
| Logs and metrics | Log Analytics workspace and Azure Monitor |
| TLS and ingress | Container Apps ingress with custom domain certificate |
| Optional perimeter | Azure Front Door, Application Gateway, WAF, IP restrictions |
| Private network access | VNet integration, Private Link, NAT Gateway, Azure Firewall |

## Security Defaults

Use these controls as the default production posture:

- Run Container Apps inside a managed environment connected to a VNet.
- Prefer internal ingress when access is limited to corporate networks or private security tooling.
- If external ingress is required, front it with Azure Front Door, Application Gateway, WAF, IP restrictions, or identity-aware access.
- Use managed identity for Azure resource access.
- Store secrets in Key Vault and reference them from Container Apps secrets.
- Keep Azure Container Registry admin access disabled.
- Deploy immutable image tags and record the image digest for production changes.
- Enable Defender for Cloud container and database recommendations where available.
- Use Private Link or restricted firewall rules for PostgreSQL, Key Vault, Storage, and private GitHub Enterprise endpoints where supported.
- Disable local test login in every shared environment.
- Rotate any token that has appeared in chat, logs, screenshots, terminal output, or issue trackers.

## Baseline Settings

Use these environment values for shared environments:

```bash
APPLICATION_INVENTORY_SERVICE_UI_HOST=0.0.0.0
APPLICATION_INVENTORY_SERVICE_UI_PORT=48731
APPLICATION_INVENTORY_SERVICE_REPORTS_DIR=/reports
APPLICATION_INVENTORY_SERVICE_COOKIE_SECURE=true
APPLICATION_INVENTORY_SERVICE_TEST_LOGIN_ENABLED=false
APPLICATION_INVENTORY_SERVICE_PUBLIC_URL=https://inventory.example.com
APPLICATION_INVENTORY_SERVICE_GHE_BASE_URL=https://github.enterprise.example
APPLICATION_INVENTORY_SERVICE_ALLOWED_GITHUB_HOSTS=github.example.com
APPLICATION_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS=false
APPLICATION_INVENTORY_SERVICE_MAX_JSON_BODY_BYTES=1048576
APPLICATION_INVENTORY_SERVICE_MAX_CONCURRENT_SCANS=2
APPLICATION_INVENTORY_GITHUB_REQUESTS_PER_SECOND=8
APPLICATION_INVENTORY_GITHUB_RATE_LIMIT_RESERVE=50
APPLICATION_INVENTORY_XLSX_CHECKPOINT_ROWS=500
APPLICATION_INVENTORY_XLSX_MAX_CHECKPOINT_ROWS=5000
APPLICATION_INVENTORY_XLSX_CHECKPOINT_SECONDS=30
APPLICATION_INVENTORY_POSTGRES_COMMIT_ROWS=50
APPLICATION_INVENTORY_POSTGRES_COMMIT_SECONDS=1
APPLICATION_INVENTORY_POSTGRES_SCHEMA=application_inventory
APPLICATION_INVENTORY_POSTGRES_TABLE=application_inventory_assets
APPLICATION_INVENTORY_OBSERVABILITY_DSN=postgresql://user:password@host:5432/postgres
APPLICATION_INVENTORY_OBSERVABILITY_SCHEMA=application_inventory
```

Store these in Key Vault:

```text
APPLICATION_INVENTORY_SERVICE_SECRET_KEY
APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_SECRET
APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_SECRET
APPLICATION_INVENTORY_POSTGRES_DSN
APPLICATION_INVENTORY_OBSERVABILITY_DSN
ADO_PAT or APPLICATION_INVENTORY_ADO_ORG_PATS when automation needs server-side tokens
APPLICATION_INVENTORY_GITHUB_API_URL, APPLICATION_INVENTORY_GITHUB_URLS, APPLICATION_INVENTORY_GITHUB_REPOSITORIES, APPLICATION_INVENTORY_GITHUB_APP_ID, APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID, and APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE for GitHub access
```

## Build and Push the Image

```bash
AZURE_LOCATION=eastus
RESOURCE_GROUP=rg-application-inventory-prod
ACR_NAME=appinventoryprodacr
IMAGE_NAME=application-inventory-service
IMAGE_TAG=1.6.12

az group create \
  --name "$RESOURCE_GROUP" \
  --location "$AZURE_LOCATION"

az acr create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ACR_NAME" \
  --sku Premium \
  --admin-enabled false

az acr login --name "$ACR_NAME"

docker build -t "$IMAGE_NAME:$IMAGE_TAG" .
docker tag "$IMAGE_NAME:$IMAGE_TAG" "$ACR_NAME.azurecr.io/$IMAGE_NAME:$IMAGE_TAG"
docker push "$ACR_NAME.azurecr.io/$IMAGE_NAME:$IMAGE_TAG"
```

Use immutable tags for production. Avoid deploying `latest`. Record the pushed digest and use it in release evidence:

```bash
az acr manifest list-metadata \
  --registry "$ACR_NAME" \
  --name "$IMAGE_NAME" \
  --query "[?tags[?@=='$IMAGE_TAG']].digest | [0]" \
  --output tsv
```

## Create Core Azure Resources

```bash
LOG_WORKSPACE=law-application-inventory-prod
ACA_ENV=cae-application-inventory-prod
APP_NAME=ca-application-inventory-prod
STORAGE_ACCOUNT=appinventoryprodfs
FILE_SHARE=reports
KEY_VAULT=kv-appinventory-prod
POSTGRES_NAME=pg-appinventory-prod
POSTGRES_DB=postgres
```

```bash
az monitor log-analytics workspace create \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$LOG_WORKSPACE" \
  --location "$AZURE_LOCATION"

WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$LOG_WORKSPACE" \
  --query customerId \
  --output tsv)

WORKSPACE_KEY=$(az monitor log-analytics workspace get-shared-keys \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$LOG_WORKSPACE" \
  --query primarySharedKey \
  --output tsv)

az containerapp env create \
  --name "$ACA_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$AZURE_LOCATION" \
  --logs-workspace-id "$WORKSPACE_ID" \
  --logs-workspace-key "$WORKSPACE_KEY"
```

Create PostgreSQL Flexible Server with private networking for production. At minimum, disable broad public access and restrict firewall rules to approved administrative paths.

```bash
az postgres flexible-server create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$POSTGRES_NAME" \
  --location "$AZURE_LOCATION" \
  --database-name "$POSTGRES_DB" \
  --sku-name Standard_D2ds_v5 \
  --tier GeneralPurpose \
  --storage-size 128 \
  --version 16
```

Harden the database after creation:

```bash
az postgres flexible-server parameter set \
  --resource-group "$RESOURCE_GROUP" \
  --server-name "$POSTGRES_NAME" \
  --name require_secure_transport \
  --value ON

az postgres flexible-server update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$POSTGRES_NAME" \
  --backup-retention 35
```

For production, use private access or Private Link, disable broad public firewall rules, and use a dedicated database user with only the privileges required by the `application_inventory` schema.

Create Azure Files:

```bash
az storage account create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$STORAGE_ACCOUNT" \
  --location "$AZURE_LOCATION" \
  --sku Standard_ZRS \
  --https-only true \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false

STORAGE_KEY=$(az storage account keys list \
  --resource-group "$RESOURCE_GROUP" \
  --account-name "$STORAGE_ACCOUNT" \
  --query '[0].value' \
  --output tsv)

az storage share-rm create \
  --resource-group "$RESOURCE_GROUP" \
  --storage-account "$STORAGE_ACCOUNT" \
  --name "$FILE_SHARE" \
  --quota 100

az containerapp env storage set \
  --name "$ACA_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --storage-name reports \
  --storage-type AzureFile \
  --azure-file-account-name "$STORAGE_ACCOUNT" \
  --azure-file-account-key "$STORAGE_KEY" \
  --azure-file-share-name "$FILE_SHARE" \
  --access-mode ReadWrite
```

## Configure Key Vault and Secrets

```bash
az keyvault create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$KEY_VAULT" \
  --location "$AZURE_LOCATION" \
  --enable-rbac-authorization true \
  --enable-purge-protection true
```

Generate the Fernet key:

```bash
python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
```

Set required secrets:

```bash
az keyvault secret set --vault-name "$KEY_VAULT" --name app-fernet-key --value "<fernet-key>"
az keyvault secret set --vault-name "$KEY_VAULT" --name postgres-dsn --value "postgresql://app_user:<password>@<postgres-host>:5432/postgres?sslmode=require"
az keyvault secret set --vault-name "$KEY_VAULT" --name github-client-secret --value "<github-oauth-secret>"
az keyvault secret set --vault-name "$KEY_VAULT" --name google-client-secret --value "<google-oauth-secret>"
```

Use secret expiration dates and owner metadata. Rotate OAuth secrets, PATs, database passwords, and storage account keys on a defined cadence.

## Deploy the Container App

Create the app with managed identity, ingress, and the Azure Files mount:

```bash
az containerapp create \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$ACA_ENV" \
  --image "$ACR_NAME.azurecr.io/$IMAGE_NAME:$IMAGE_TAG" \
  --target-port 48731 \
  --ingress external \
  --registry-server "$ACR_NAME.azurecr.io" \
  --system-assigned \
  --cpu 1.0 \
  --memory 2Gi \
  --min-replicas 1 \
  --max-replicas 1 \
  --command application-inventory-service-container \
  --args ui --host 0.0.0.0 --port 48731 --reports-dir /reports
```

Grant the app identity access to Key Vault and ACR:

```bash
PRINCIPAL_ID=$(az containerapp identity show \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query principalId \
  --output tsv)

KEY_VAULT_ID=$(az keyvault show --name "$KEY_VAULT" --query id --output tsv)
ACR_ID=$(az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --query id --output tsv)

az role assignment create \
  --assignee "$PRINCIPAL_ID" \
  --role "Key Vault Secrets User" \
  --scope "$KEY_VAULT_ID"

az role assignment create \
  --assignee "$PRINCIPAL_ID" \
  --role AcrPull \
  --scope "$ACR_ID"
```

Reference Key Vault secrets from Container Apps and mount reports:

```bash
FERNET_SECRET_ID=$(az keyvault secret show --vault-name "$KEY_VAULT" --name app-fernet-key --query id --output tsv)
POSTGRES_SECRET_ID=$(az keyvault secret show --vault-name "$KEY_VAULT" --name postgres-dsn --query id --output tsv)
GITHUB_SECRET_ID=$(az keyvault secret show --vault-name "$KEY_VAULT" --name github-client-secret --query id --output tsv)
GOOGLE_SECRET_ID=$(az keyvault secret show --vault-name "$KEY_VAULT" --name google-client-secret --query id --output tsv)

az containerapp secret set \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --secrets \
    app-fernet-key=keyvaultref:"$FERNET_SECRET_ID",identityref:system \
    postgres-dsn=keyvaultref:"$POSTGRES_SECRET_ID",identityref:system \
    github-client-secret=keyvaultref:"$GITHUB_SECRET_ID",identityref:system \
    google-client-secret=keyvaultref:"$GOOGLE_SECRET_ID",identityref:system
```

Export the app definition, add the Azure Files volume mount, and apply it:

```bash
az containerapp show \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --output yaml > app.yaml
```

In `app.yaml`, add:

```yaml
template:
  containers:
    - name: application-inventory-service
      volumeMounts:
        - volumeName: reports
          mountPath: /reports
      env:
        - name: APPLICATION_INVENTORY_SERVICE_SECRET_KEY
          secretRef: app-fernet-key
        - name: APPLICATION_INVENTORY_POSTGRES_DSN
          secretRef: postgres-dsn
        - name: APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_SECRET
          secretRef: github-enterprise-client-secret
        - name: APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_SECRET
          secretRef: google-client-secret
  volumes:
    - name: reports
      storageType: AzureFile
      storageName: reports
```

Then:

```bash
az containerapp update \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --yaml app.yaml
```

## Configure Runtime Environment

```bash
az containerapp update \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --set-env-vars \
    APPLICATION_INVENTORY_SERVICE_UI_HOST=0.0.0.0 \
    APPLICATION_INVENTORY_SERVICE_UI_PORT=48731 \
    APPLICATION_INVENTORY_SERVICE_REPORTS_DIR=/reports \
    APPLICATION_INVENTORY_SERVICE_COOKIE_SECURE=true \
    APPLICATION_INVENTORY_SERVICE_TEST_LOGIN_ENABLED=false \
    APPLICATION_INVENTORY_SERVICE_PUBLIC_URL=https://inventory.example.com \
    APPLICATION_INVENTORY_SERVICE_GHE_BASE_URL=https://github.enterprise.example \
    APPLICATION_INVENTORY_SERVICE_ALLOWED_GITHUB_HOSTS=github.example.com \
    APPLICATION_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS=false \
    APPLICATION_INVENTORY_SERVICE_MAX_JSON_BODY_BYTES=1048576 \
    APPLICATION_INVENTORY_POSTGRES_SCHEMA=application_inventory \
    APPLICATION_INVENTORY_POSTGRES_TABLE=application_inventory_assets
```

## Custom Domain and TLS

Bind a custom domain to the Container App and use a managed or uploaded certificate. Configure OAuth callback URLs with the same public hostname:

```text
https://inventory.example.com/api/auth/github-enterprise/callback
https://inventory.example.com/api/auth/google/callback
```

Use [GitHub SSO](GITHUB_SSO.md) for the complete GitHub OAuth registration, secret, scope, proxy, and verification procedure.

Use Container Apps IP restrictions, Azure Front Door, Application Gateway, WAF, private ingress, or identity-aware access when the UI should not be publicly reachable.

Runtime hardening:

- Keep `APPLICATION_INVENTORY_SERVICE_COOKIE_SECURE=true`.
- Keep `APPLICATION_INVENTORY_SERVICE_TEST_LOGIN_ENABLED=false`.
- Set `APPLICATION_INVENTORY_SERVICE_ALLOWED_GITHUB_HOSTS` to explicit hostnames.
- Keep `APPLICATION_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS=false`.
- Grant the managed identity only `AcrPull` and Key Vault secret-read permissions required by this app.
- Do not store GitHub App private keys, PATs, or OAuth secrets in Container App plain environment variables.
- Keep a single replica until active scan coordination is moved to a durable queue or worker service.
- Review scan worker increases because high concurrency can trigger provider throttling or expose more metadata than intended.

## Azure DevOps Scanning Configuration

The scanner calls Azure DevOps REST APIs to list projects, repositories, branches, build definitions, commits, and selected repository files. Use least-privilege credentials.

Preferred token strategy:

- Use one PAT per Azure DevOps organization.
- Scope tokens to the organization that will be scanned.
- Use short expirations and rotate on a defined schedule.
- Store tokens in Key Vault or enter them through the UI only when needed.

Recommended PAT scopes:

- Code: Read
- Build: Read
- Project and Team: Read, when available in your tenant

CLI examples:

```bash
application-inventory-service \
  --provider azure-devops \
  --ado-org-pat "ContosoApps=$CONTOSO_PAT" \
  --ado-org-pat "FabrikamCloud=$FABRIKAM_PAT" \
  --target-filter "ContosoApps=Payments" \
  --target-filter "FabrikamCloud=Go_To_Market" \
  --out-dir reports
```

For full-organization scans, omit `--target-filter`.

## PostgreSQL Validation

The application creates the `application_inventory` schema and normalized tables automatically when database sync is enabled.

Validate from the UI:

1. Sign in.
2. Open **Database**.
3. Confirm the startup status is **Ready**.
4. Run a small scan and confirm records appear while it runs.
5. Export XLSX, CSV, and JSON from the database page.

Validate from SQL:

```sql
select count(*) from application_inventory.branch_inventory;
select provider, organization, project, repo_name, branch_name
from application_inventory.inventory_export
order by synced_at desc
limit 20;
```

## Operations

Monitoring:

- Container App replica restarts
- HTTP 5xx responses
- PostgreSQL CPU, storage, connections, and backup status
- Azure Files capacity and throttling
- Key Vault denied operations
- Provider API rate limits in application logs

Backup:

- Enable PostgreSQL backups and define retention by policy.
- Protect the Azure Files share with Azure Backup where reports/state are business records.
- Export the SBOM and deployment manifest with each production release.

Scaling:

- Start with one replica because active scan processes and event listeners are held in process memory. Azure Files preserves reports, encrypted credentials, and encrypted schedules across revisions.
- Keep `APPLICATION_INVENTORY_SERVICE_SECRET_KEY` stable across revisions or existing encrypted state becomes unreadable.
- Pause and resume use Linux process-group signals. Revision replacement terminates active or paused scans; schedules reload on the replacement replica.
- Scale vertically first for large organizations.
- Increase scan worker settings cautiously to avoid provider throttling.
- For horizontal scale, move active scan coordination to a durable queue and worker service.

Audit:

- Send Container Apps logs to Log Analytics with retention aligned to inventory sensitivity.
- Monitor denied Key Vault reads, PostgreSQL failed logins, provider API errors, and unexpected outbound destinations.
- Keep release evidence: image digest, SBOM, GitHub release, PyPI version, and deployment manifest.

## References

- [Azure Container Apps security overview](https://learn.microsoft.com/en-us/azure/container-apps/security)
- [Azure Container Apps secrets and Key Vault references](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets)
- [Azure Container Apps ingress](https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview)
- [Azure Container Apps custom domains and certificates](https://learn.microsoft.com/en-us/azure/container-apps/custom-domains-certificates)
- [Azure Container Apps storage mounts](https://learn.microsoft.com/en-us/azure/container-apps/storage-mounts)
- [Azure Database for PostgreSQL Flexible Server networking](https://learn.microsoft.com/en-us/azure/postgresql/network/concepts-networking-private-link)
- [Azure Database for PostgreSQL encryption](https://learn.microsoft.com/en-us/azure/postgresql/security/security-data-encryption)
- [Azure DevOps personal access tokens](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate)
