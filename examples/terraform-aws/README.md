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
| Ed25519 KMS key | Signs governance receipts without exporting private key material |
| Symmetric KMS key (auto-rotating) | Encrypts S3 audit objects and CloudWatch log data |
| S3 bucket | Versioned audit log storage with lifecycle tiers and TLS enforcement |
| IAM role + instance profile | Least-privilege access to SSM, S3, KMS, and CloudWatch |
| SSM parameters | All `AGT_*` governance config values agents read at startup |
| CloudWatch Log Group | Structured governance event ingestion |

## Quick Start

```bash
cd examples/terraform-aws
terraform init
terraform plan -var="project=myagent"
terraform apply -var="project=myagent"
```

The example uses local Terraform state by default. Before team or production use,
configure an encrypted remote backend with access controls and locking; state contains
infrastructure metadata and should be treated as sensitive.

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
module). Set the production values in a local, ignored `.tfvars` file and pass it
to `terraform plan` / `terraform apply`, for example:

```hcl
project             = "customer-support-agent"
environment         = "prod"
trust_level         = "elevated"
max_tool_calls      = 50
rate_limit_rpm      = 30
retention_days      = 365
kill_switch_enabled = true
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
# config["retention-days"]     → "365"
# config["audit-bucket"]       → "myagent-prod-audit-a1b2c3d4"
```

## Signing Receipts

The Ed25519 private key is generated and retained by AWS KMS; it is never placed in
Terraform state or exported as PEM. The agent role can call KMS `Sign` and
`GetPublicKey`. For example, a caller using boto3 can sign a receipt payload with:

```python
import boto3

kms = boto3.client("kms")
result = kms.sign(
    KeyId="<kms_key_arn output>",
    Message=receipt_bytes,
    MessageType="RAW",
    SigningAlgorithm="ED25519_SHA_512",
)
signature = result["Signature"]
```

AWS KMS does not automatically rotate asymmetric signing keys. Rotate them through
a reviewed key-versioning procedure and retain the old public keys for verification
of previously signed receipts. The separate symmetric encryption key rotates
automatically.

## Known Limitations

- `AGT_POLICY_PATH` (the Cedar/YAML policy file) is a runtime container mount and
  is not provisioned here. A follow-up could add an S3 prefix for policy file
  storage and wire its path into SSM.
- No ECS task definition or Kubernetes manifest is included — this example
  provisions the supporting infrastructure; the compute layer is left to the caller.
- S3 versioning and retention are configured, but S3 Object Lock (WORM) is not;
  add it separately if a regulatory requirement mandates immutable retention.

## Cost and Teardown

The default network provisions two NAT gateways and two Elastic IPs, which incur
hourly and data-processing charges even when agent traffic is low. KMS keys,
CloudWatch ingestion/retention, and S3 storage and requests add usage-based costs.
Review current regional pricing and expected traffic/log volume before applying.

After retention and audit-export obligations are met, empty the S3 audit bucket,
including all object versions and delete markers, before running
`terraform destroy`. Production sets `force_destroy = false` intentionally so
Terraform cannot silently erase a non-empty audit bucket.

## Requirements

| Tool | Version |
|---|---|
| Terraform / OpenTofu | >= 1.5.0 |
| AWS provider | 6.64.0 |
| Random provider | 3.9.1 |
| AWS CLI | >= 2.x (for runtime config reads) |

## Structural Tests

From the repository root, install the pinned test dependencies and run the example tests:

```bash
python -m pip install -r examples/terraform-test-requirements.txt
python -m pytest examples/terraform-aws/test_terraform_aws.py
```
