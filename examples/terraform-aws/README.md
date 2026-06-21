# Governed Agent Infrastructure — AWS Example

Terraform example that provisions the complete AWS infrastructure required to run
AGT-governed agents in production. All AGT governance config values are stored as
SSM parameters so agents read them at runtime — no governance config is baked into
container images.

## What Gets Provisioned

| Resource | Purpose |
|---|---|
| VPC + private/public subnets + NAT | Agents run in private subnets with no inbound access |
| Security group (egress-only) | HTTPS-out only; blocks all inbound |
| KMS key (auto-rotating) | Signs Ed25519 governance receipts; encrypts audit logs |
| S3 bucket | Immutable audit log storage with lifecycle tiers and TLS enforcement |
| IAM role + instance profile | Least-privilege access to SSM, S3, Secrets Manager, KMS, CloudWatch |
| Secrets Manager secret | Holds the Ed25519 signing key PEM |
| SSM parameters | All `AGT_*` governance config values agents read at startup |
| CloudWatch Log Group | Structured governance event ingestion |

## Quick Start

```bash
cd examples/terraform-aws
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
  source = "../../infra/terraform/modules/governed-agent-aws"

  project     = "customer-support-agent"
  environment = "prod"

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

Agents fetch governance config from SSM at startup:

```bash
# List all AGT parameters for this deployment
aws ssm get-parameters-by-path \
  --path "/myagent-prod/agt/" \
  --region us-east-1
```

In Python (e.g., inside a `DockerDeployer` entrypoint):

```python
import boto3

ssm = boto3.client("ssm", region_name="us-east-1")
params = ssm.get_parameters_by_path(Path="/myagent-prod/agt/", WithDecryption=False)

config = {p["Name"].split("/")[-1]: p["Value"] for p in params["Parameters"]}
# config["trust-level"]        → "elevated"
# config["max-tool-calls"]     → "50"
# config["audit-enabled"]      → "true"
# config["audit-bucket"]       → "myagent-prod-audit-a1b2c3d4"
```

## Populating the Ed25519 Signing Key

The Secrets Manager secret is created as a placeholder. Populate it via your CI
pipeline or a one-time bootstrap script after `terraform apply`:

```bash
# Generate a key (requires PyNaCl or cryptography)
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
key = Ed25519PrivateKey.generate()
print(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())
" > signing_key.pem

# Upload to Secrets Manager
aws secretsmanager put-secret-value \
  --secret-id "myagent-prod/agt/signing-key" \
  --secret-string file://signing_key.pem

rm signing_key.pem  # never store the PEM on disk in production
```

## Known Limitations

- `AGT_POLICY_PATH` (the Cedar/YAML policy file) is a runtime container mount and
  is not provisioned here. A follow-up could add an S3 prefix for policy file
  storage and wire its path into SSM.
- No ECS task definition or Kubernetes manifest is included — this example
  provisions the supporting infrastructure; the compute layer is left to the caller.

## Requirements

| Tool | Version |
|---|---|
| Terraform / OpenTofu | >= 1.5.0 |
| AWS provider | >= 5.0 |
| AWS CLI | >= 2.x (for runtime config reads) |
