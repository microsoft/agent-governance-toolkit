# Governed Agent Infrastructure — Azure Example

Terraform example that provisions the complete Azure infrastructure required to run
AGT-governed agents in production. All AGT governance config values are stored in
App Configuration so agents read them at runtime — no governance config is baked
into container images.

The Standard App Configuration SKU is used in both environments so production can
use private endpoints; account for its cost when deploying the dev example.

## What Gets Provisioned

| Resource | Purpose |
|---|---|
| Resource Group | Container for all governed agent resources |
| VNet + private subnet + NSG | Agents run in private subnet; all inbound denied |
| User-Assigned Managed Identity | Passwordless agent authentication — no credentials in images |
| Key Vault (Premium) | Stores the Ed25519 signing key; purge-protected in prod |
| Storage Account + Blob container | Versioned audit storage with lifecycle tiers, TLS-only, and shared-key auth disabled |
| App Configuration (Standard) | Entra-only `AGT_*` settings; private endpoint in prod |
| Log Analytics Workspace | Governance event ingestion and retention |

## Quick Start

```bash
cd examples/terraform-azure
az login
terraform init
terraform plan -var="project=myagent"
terraform apply -var="project=myagent"
```

The default `dev` environment keeps the data-plane endpoints reachable for the
initial apply while requiring Azure AD authentication. The example uses local
Terraform state by default. Before team or production use, configure an encrypted
remote backend with access controls and locking; state contains infrastructure
metadata and should be treated as sensitive.

The identity running Terraform needs permission to create role assignments
(typically Owner or User Access Administrator) and the App Configuration / Storage
data-plane roles declared below. For production, pass the runner's public IPv4
addresses in `deployment_ip_ranges` for Key Vault and Storage, and run Terraform
from a host with network access and DNS resolution for the App Configuration
private endpoint. The `privatelink.azconfig.io` DNS zone is linked only to the agent
VNet; a runner outside that VNet needs connected DNS forwarding or an Azure DNS
Private Resolver configured for the private zone. `deployment_ip_ranges` accepts
CIDRs for Key Vault, but Storage requires individual IPv4 addresses (no CIDR
prefixes).

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
| `retention_days` | `180` (`180` or `365`) | `AGT_RETENTION_DAYS` |

`trust_level` accepts: `unclassified`, `basic`, `standard`, `elevated`, `critical` —
matching the `GovernanceTier` enum in `github_enterprise.py`.

## Production Configuration

Run this example as a root Terraform configuration (it is not a published child
module). Production Key Vault and Storage firewall rules deny traffic by default;
add the Terraform runner's IPv4 addresses to an ignored `prod.tfvars` file:

```hcl
project              = "customer-support-agent"
environment          = "prod"
location             = "eastus"
trust_level          = "elevated"
max_tool_calls       = 50
rate_limit_rpm       = 30
retention_days       = 365
kill_switch_enabled  = true
deployment_ip_ranges = ["203.0.113.10"] # Replace with the runner's public IPv4 address.
```

App Configuration public access is disabled in production and a private endpoint
is created in the agent VNet. Run `terraform apply` from that VNet or a connected
network so Terraform can write the App Configuration keys over the private link.
The Terraform identity is granted `App Configuration Data Owner`,
`Storage Blob Data Contributor`, and `Key Vault Secrets Officer` at the narrow
resource scopes needed to manage data-plane settings and bootstrap the signing key.
The configuration waits 120 seconds after creating data-plane role assignments
for RBAC propagation. If Azure still returns a 403, wait a few minutes and rerun
the full apply.

For a first production rollout, bootstrap the VNet and private link before running
the full apply from a connected Terraform runner:

```bash
terraform apply -var-file=prod.tfvars \
  -target=azurerm_private_endpoint.app_configuration \
  -target=azurerm_private_dns_zone_virtual_network_link.app_configuration
```

Use this targeted apply only for that initial network bootstrap; run the complete
configuration on subsequent applies.

## How Agents Read Config at Runtime

Agents fetch governance config from App Configuration at startup:

```bash
# List all AGT keys for this environment
az appconfig kv list \
  --name "$(terraform output -raw app_configuration_name)" \
  --label prod
```

In Python (e.g., inside a `DockerDeployer` entrypoint):

```python
from azure.appconfiguration import AzureAppConfigurationClient
from azure.identity import ManagedIdentityCredential

credential = ManagedIdentityCredential(client_id="<managed-identity-client-id>")
client = AzureAppConfigurationClient(
    base_url="<app_configuration_endpoint output>",
    credential=credential,
)

settings = {s.key: s.value for s in client.list_configuration_settings(label_filter="prod")}
# settings["agt:trust-level"]        → "elevated"
# settings["agt:max-tool-calls"]     → "50"
# settings["agt:audit-enabled"]      → "true"
# settings["agt:audit-container"]    → "myagentprodsa123456/agt-audit-logs"
```

## Populating the Ed25519 Signing Key

Terraform intentionally does not create or read the secret value: that would put
the private key in Terraform state. After `terraform apply`, add the key from a
network location allowed by the Key Vault firewall using the Terraform identity
or another identity with `Key Vault Secrets Officer`:

```bash
# Generate a key (requires cryptography library)
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
key = Ed25519PrivateKey.generate()
print(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())
" > signing_key.pem

# Upload to Key Vault; the private key value is not managed by Terraform.
az keyvault secret set \
  --vault-name <keyvault-name> \
  --name agt-signing-key \
  --file signing_key.pem

rm signing_key.pem  # never store the PEM on disk in production
```

## Prod vs Dev Differences

This example adjusts several settings automatically based on `environment`:

| Setting | `dev` | `prod` |
|---|---|---|
| Key Vault purge protection | Disabled | Enabled |
| Key Vault soft-delete retention | 7 days | 90 days |
| Storage replication | LRS | GRS |
| Key Vault and Storage firewall | Allow (RBAC required) | Deny by default; allow configured runner IPs and agent subnet |
| App Configuration endpoint | Public; Entra auth only | Private endpoint; public access disabled |

## Cost and Teardown

The Standard App Configuration store is billable in both `dev` and `prod`.
Production also uses Premium Key Vault and GRS storage; App Configuration private
endpoints, storage transactions, and Log Analytics ingestion add further charges.
Review current regional prices and your expected log volume before applying.

After retention and audit-export requirements are satisfied, run
`terraform destroy` from a network with access to production data-plane endpoints.
Production Key Vault has purge protection and remains soft-deleted for its
configured retention period; its randomized name avoids blocking a later
re-creation. Remove any separately managed data before deleting its storage.

## Known Limitations

- `AGT_POLICY_PATH` (the Cedar/YAML policy file) is a runtime container mount and
  is not provisioned here. A follow-up could add a Blob prefix for policy file
  storage and wire its path into App Configuration.
- No AKS Helm chart or Container Apps definition is included — this example
  provisions the supporting infrastructure; the compute layer is left to the caller.
- Blob versioning, soft-delete retention, and lifecycle management are configured,
  but Azure immutable storage policies (WORM) are not; add them separately when
  required by a compliance regime.

## Requirements

| Tool | Version |
|---|---|
| Terraform / OpenTofu | >= 1.5.0 |
| AzureRM provider | 4.81.0 |
| Random provider | 3.9.1 |
| Time provider | 0.14.2 |
| Azure CLI | >= 2.x (for `az login` and runtime config reads) |

## Structural Tests

From the repository root, install the pinned test dependencies and run the example tests:

```bash
python -m pip install -r examples/terraform-test-requirements.txt
python -m pytest examples/terraform-azure/test_terraform_azure.py
```
