# sb-runtime + AgentMesh Governance Skill

**Public Preview.** Governance skill that evaluates policy and emits Ed25519-signed decision receipts in the [Veritas Acta receipt format](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/). Parallel to `openshell-skill`: same policy contract, drop-in replacement at the governance layer, with receipts added.

> sb-runtime is one implementation of the Veritas Acta receipt format. This skill is its AgentMesh integration point. See [docs/integrations/sb-runtime.md](../../../docs/integrations/sb-runtime.md) for the architecture overview and for guidance on composing with [nono](https://github.com/always-further/nono) as the Linux sandbox primitive.

## Install

```bash
pip install sb-runtime-agentmesh
```

## What the skill adds over `openshell-skill`

| Capability | openshell-skill | sb-runtime-skill |
|---|:---:|:---:|
| YAML policy loading | yes | yes (same schema) |
| Trust score tracking | yes | yes |
| Audit log | yes | yes |
| Ed25519-signed decision receipts | no | yes |
| Receipt chain linkage (`previousReceiptHash`) | no | yes |
| Policy digest pinned into receipts | no | yes (`sha256:...`) |
| Sandbox backend recorded in receipt | no | yes (`nono` \| `openshell` \| `sb_runtime_builtin` \| `none`) |
| Offline verification (`@veritasacta/verify`) | no | yes |

## Usage

### As a library

```python
from pathlib import Path
from sb_runtime_agentmesh import GovernanceSkill, SandboxBackend

skill = GovernanceSkill(
    policy_dir=Path("./policies"),
    sandbox_backend=SandboxBackend.NONO,  # wrap the agent in a nono sandbox
    ring=2,                               # sb-runtime does policy + receipts; nono does the sandbox
)

decision = skill.check_policy(
    action="shell:curl https://api.github.com/repos/org/repo/issues",
    context={"agent_did": "did:agent:researcher-1"},
)

if decision.allowed:
    # Ring 2: execute inside the nono capability set
    ...

# The signed receipt is on decision.receipt - Veritas Acta format.
import json
print(json.dumps(decision.receipt, indent=2))
```

### As a CLI

```bash
# Generate an operator key once
python -c "from sb_runtime_agentmesh import Signer; print(Signer.generate().private_pem().decode())" > operator.pem

# Evaluate policy, sign receipt, write to disk
sb-runtime-governance check-policy \
    --action shell:python \
    --policy-dir ./policies \
    --sandbox-backend nono \
    --ring 2 \
    --key operator.pem \
    --receipts-dir ./receipts

# Verify a written receipt
sb-runtime-governance verify ./receipts/20260419T133001123456Z.json \
    --public-key operator-public.pem
```

## Deployment modes

### Standalone sb-runtime (Ring 3)

One binary owns everything: Cedar evaluation, Landlock + seccomp sandbox, receipt signing. Set `sandbox_backend=SandboxBackend.SB_RUNTIME_BUILTIN` and `ring=3`.

### sb-runtime + nono composition (recommended on Linux)

nono owns the sandbox layer; this skill contributes only Cedar + signed receipts. Set `sandbox_backend=SandboxBackend.NONO` and `ring=2`. Wrap your agent process in nono externally:

```bash
nono run --policy ./nono-capabilities.yaml -- \
    python -m your_agent  # calls the skill in-process
```

The receipt's `payload.sandbox_backend == "nono"` field makes the composition visible to auditors.

### sb-runtime + OpenShell composition

OpenShell owns the container boundary; this skill contributes Cedar + receipts. Set `sandbox_backend=SandboxBackend.OPENSHELL` and `ring=2`.

## Receipt format

Every decision produces an envelope of the form:

```json
{
  "payload": {
    "type": "sb-runtime:decision",
    "agent_id": "did:agent:researcher-1",
    "action": "shell:python",
    "decision": "allow",
    "ring": 2,
    "sandbox_backend": "nono",
    "policy_id": "allow-shell",
    "policy_digest": "sha256:...",
    "trust_score": 1.0,
    "issuer_id": "sb:issuer:...",
    "issued_at": "2026-04-19T13:30:01.123Z",
    "previousReceiptHash": "..."
  },
  "signature": {
    "alg": "EdDSA",
    "kid": "...",
    "sig": "..."
  }
}
```

The canonical form is JCS-RFC 8785 with ASCII-only keys per [AIP-0001](https://github.com/VeritasActa/Acta/blob/main/specs/aip/AIP-0001.md). Verification does not depend on this skill, sb-runtime, or AgentMesh:

```bash
npx @veritasacta/verify receipt.json --key operator-public.pem
```

## Spec alignment

- [draft-farley-acta-signed-receipts-02](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
- [AIP-0001](https://github.com/VeritasActa/Acta) (receipt format, ASCII-only JCS)
- [VeritasActa/agt-integration-profile](https://github.com/VeritasActa/agt-integration-profile) (AGT to Veritas Acta normative field mapping)

## License

MIT. See `LICENSE` at the repo root.
