# Governed Agent Infrastructure — Azure Example

Terraform example that provisions the complete Azure infrastructure required to run
AGT-governed agents in production. All AGT governance config values are stored in
App Configuration so agents read them at runtime — no governance config is baked
into container images.

## What Gets Provisioned

| Resource | Purpose |
|---|---|
| Resource Group | Container for all governed agent resources |
| VNet + private subnet + NSG | Agents run in private subnet; all inbound denied |
| User-Assigned Managed Identity | Passwordless agent authentication — no credentials in images |
| Key Vault (Premium) | Stores the Ed25519 signing key; purge-protected in prod |
| Storage Account + Blob container | Immutable audit log storage with lifecycle tiers and TLS-only |
| App Configuration | All `AGT_*` governance config values agents read at startup |
| Log Analytics Workspace | Governance event ingestion and retention |

## Quick Start

```bash
cd examples/terraform-azure
az login
terraform init
terraform plan -var="project=myagent"
terraform apply -var="project=myagent"
```

## Governance Config Variables

All variables mirror `GovernanceConfig` in `agent-runtime/deploy.py` and the
`AGT_*` env vars injected by `DockerDeployer` / `KubernetesDeployer`.

| Variable | Default | `AGT_*` env var |
|---|---|---|
| `trust_level` | `standard` | `AGT_TRUST_LEVEL` |
| `max_tool_calls` | `100` | `AGT_MAX_TOOL_CALLS` |
| `rate_limit_rpm` | `60` | `AGT_RATE_LIMIT_RPM` |
| `audit_enabled` | `true` | `AGT_AUDIT_ENABLED` |
| `kill_switch_enabled` | `true` | `AGT_KILL_SWITCH` |
| `retention_days` | `180` | `AGT_RETENTION_DAYS` |

`trust_level` accepts: `unclassified`, `basic`, `standard`, `elevated`, `critical` —
matching the `GovernanceTier` enum in `github_enterprise.py`.

## Example: Production Deployment

```hcl
module "governed_agent" {
  source = "../../infra/terraform/modules/governed-agent-azure"

  project     = "customer-support-agent"
  environment = "prod"
  location    = "eastus"

  trust_level         = "elevated"
  max_tool_calls      = 50
  rate_limit_rpm      = 30
  retention_days      = 365
  kill_switch_enabled = true

  tags = {
    team    = "ai-platform"
    contact = "ai-platform@example.com"
  }
}
```

## How Agents Read Config at Runtime

Agents fetch governance config from App Configuration at startup:

```bash
# List all AGT keys for this environment
az appconfig kv list \
  --name myagent-prod-appconfig \
  --label prod
```

In Python (e.g., inside a `DockerDeployer` entrypoint):

```python
from azure.appconfiguration import AzureAppConfigurationClient
from azure.identity import ManagedIdentityCredential

credential = ManagedIdentityCredential(client_id="<managed-identity-client-id>")
client = AzureAppConfigurationClient(
    base_url="https://myagent-prod-appconfig.azconfig.io",
    credential=credential,
)

settings = {s.key: s.value for s in client.list_configuration_settings(label_filter="prod")}
# settings["agt:trust-level"]        → "elevated"
# settings["agt:max-tool-calls"]     → "50"
# settings["agt:audit-enabled"]      → "true"
# settings["agt:audit-container"]    → "myagentprodsa123456/agt-audit-logs"
```

## Populating the Ed25519 Signing Key

The Key Vault secret is created with a placeholder value. Populate it after
`terraform apply` via your CI pipeline or a bootstrap script:

```bash
# Generate a key (requires cryptography library)
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
key = Ed25519PrivateKey.generate()
print(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())
" > signing_key.pem

# Upload to Key Vault
az keyvault secret set \
  --vault-name <keyvault-name> \
  --name agt-signing-key \
  --file signing_key.pem

rm signing_key.pem  # never store the PEM on disk in production
```

The `ignore_changes = [value]` lifecycle rule on the Key Vault secret ensures
subsequent `terraform apply` runs do not overwrite the real key with the placeholder.

## Prod vs Dev Differences

This example adjusts several settings automatically based on `environment`:

| Setting | `dev` | `prod` |
|---|---|---|
| Key Vault purge protection | Disabled | Enabled |
| Key Vault soft-delete retention | 7 days | 90 days |
| Storage replication | LRS | GRS |
| App Configuration SKU | free | standard |

## Known Limitations

- `AGT_POLICY_PATH` (the Cedar/YAML policy file) is a runtime container mount and
  is not provisioned here. A follow-up could add a Blob prefix for policy file
  storage and wire its path into App Configuration.
- No AKS Helm chart or Container Apps definition is included — this example
  provisions the supporting infrastructure; the compute layer is left to the caller.

## Requirements

| Tool | Version |
|---|---|
| Terraform / OpenTofu | >= 1.5.0 |
| AzureRM provider | >= 3.85 |
| Azure CLI | >= 2.x (for `az login` and runtime config reads) |
