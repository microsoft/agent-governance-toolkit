# GitHub Actions Governance Gate — Example

This example shows how to wire the AGT governance gate into a deployment
workflow so that every agent deployment is policy-checked and receipted
before it reaches production.

## Files

```
.agents/security.yaml        # Agent governance policy
agents.yaml                  # Agent manifest (versions, tools, models)
```

## Quick start

```bash
pip install pyyaml cryptography
python ../../scripts/governance_gate.py \
  --policy .agents/security.yaml \
  --manifest agents.yaml \
  --commit abc1234 \
  --deployer octocat
```

## Using the reusable workflow

In your own repository's deployment workflow:

```yaml
jobs:
  governance:
    uses: microsoft/agent-governance-toolkit/.github/workflows/agent-governance-gate.yml@main
    with:
      policy_file: .agents/security.yaml
      agent_manifest: agents.yaml
      require_receipt: true
    secrets:
      signing_key: ${{ secrets.GOVERNANCE_SIGNING_KEY }}

  deploy:
    needs: governance
    if: needs.governance.outputs.gate_result == 'passed'
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying with receipt ${{ needs.governance.outputs.receipt_id }}"
```

## Generating a signing keypair

```bash
python - <<'EOF'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
key = Ed25519PrivateKey.generate()
print(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())
print(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode())
EOF
```

Store the private key as the `GOVERNANCE_SIGNING_KEY` secret in your repository.

## Policy fields checked

| Field | Required value |
|---|---|
| `audit.enabled` | `true` |
| `pii_scanning.enabled` | `true` |
| `allowed_tools` | a non-empty list |
| `max_tool_calls` | an integer |
