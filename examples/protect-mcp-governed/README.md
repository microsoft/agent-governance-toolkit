# protect-mcp + Governance Toolkit — Governed MCP with Signed Receipts

> MCP tool calls governed by **Cedar policies** with **Ed25519 signed receipts**.
> Every allow/deny decision produces a cryptographic receipt that can be verified
> independently, offline, forever. Integrates AGT policy evaluation, trust
> scoring, and tamper-proof audit alongside ScopeBlind's receipt signing layer.

## Quick Start (< 2 minutes)

```bash
pip install agent-governance-toolkit[full]
python examples/protect-mcp-governed/getting_started.py
```

`getting_started.py` is a **~180-line** copy-paste-friendly example showing
the core integration pattern:

```python
from agent_os.policies.evaluator import PolicyEvaluator
from agentmesh.governance.audit import AuditLog

# ScopeBlind protect-mcp integration
from scopeblind_protect_mcp.adapter import (
    CedarPolicyBridge,
    CedarDecision,
    ReceiptVerifier,
    SpendingGate,
    scopeblind_context,
)

# 1. Load YAML policies + set up Cedar bridge
evaluator = PolicyEvaluator()
evaluator.load_policies(Path("./policies"))
cedar_bridge = CedarPolicyBridge()
receipt_verifier = ReceiptVerifier()
spending_gate = SpendingGate(max_amount=1000.0)
audit_log = AuditLog()

# 2. Evaluate a tool call with Cedar + AGT policies
decision = CedarDecision(
    decision="allow",
    policy_id="autoresearch-safe",
    tool_name="file_system:read_file",
    trust_tier="evidenced",
)

# 3. Bridge Cedar decision into AGT scoring
agt_result = cedar_bridge.evaluate(decision, agent_id="research-bot")
# Cedar deny is authoritative — overrides any trust score

# 4. Verify the signed receipt
receipt = decision.to_receipt()  # Ed25519 signed
is_valid = receipt_verifier.validate(receipt)
# True = signature valid, structure intact, not replayed

# 5. Check spending authority
spending_ok = spending_gate.check(amount=50.0, category="compute")

# 6. Build AGT-compatible context for audit
ctx = scopeblind_context(decision, receipt, spending_gate)
audit_log.append(ctx)

# 7. Verify the tamper-proof audit trail
valid, err = audit_log.verify_integrity()
```

For the full **8-scenario showcase**, run:

```bash
python examples/protect-mcp-governed/protect_mcp_governance_demo.py
```

## What This Shows

| Scenario | Governance Layer | What Happens |
|----------|-----------------|--------------|
| **1. Cedar Policy Evaluation** | `CedarPolicyBridge` | Tool calls evaluated against Cedar policies (principal/action/resource/context). Cedar deny is authoritative and overrides trust scores. |
| **2. Receipt Signing & Verification** | `ReceiptVerifier` | Every decision produces an Ed25519 signed receipt. Tampered receipts are detected. Replayed receipts are rejected within the bounded window. |
| **3. Spending Authority** | `SpendingGate` | Tool calls with financial impact checked against amount limits, category blocks, and utilization bands. High-value actions require receipts. |
| **4. Trust Tier Mapping** | `CedarPolicyBridge` | Cedar trust tiers (anonymous/attested/evidenced/institutional) map to AGT trust score bonuses (0/+10/+20/+30). |
| **5. Receipt Chain Integrity** | `ReceiptVerifier` + `AuditLog` | Receipts are hash-chained (each references previous receipt hash). Chain verification detects insertions, deletions, and modifications. |
| **6. Concurrent Access Safety** | `CedarPolicyBridge` + `SpendingGate` | Thread-safe evaluation under concurrent tool calls. Trust updates and spending checks are atomic. |
| **7. Cedar + AGT Composition** | All layers | Cedar policy deny overrides AGT trust=999. AGT rate limiting composes with Cedar spending authority. Both produce audit entries. |
| **8. Offline Verification** | `ReceiptVerifier` | Receipts verified without any network call. Ed25519 signature check + JCS canonical form. Works air-gapped. |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MCP Tool Call                                │
│                     (file_system:read_file)                         │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   AGT Policy Evaluator                              │
│              (YAML policies, rate limits,                            │
│               content filters, allow-lists)                          │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Cedar Policy Bridge                                │
│           (principal / action / resource / context)                  │
│                                                                     │
│  Cedar DENY is authoritative — overrides trust scores.              │
│  Cedar ALLOW earns trust bonus based on trust tier.                 │
│  Every evaluation produces a signed receipt.                        │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Spending Gate                                     │
│         (amount limits, category blocks,                             │
│          utilization bands, receipt requirements)                     │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│               Ed25519 Receipt Signing                               │
│                                                                     │
│  JCS canonicalization (RFC 8785) → SHA-256 → Ed25519 signature      │
│  Receipt is hash-chained to previous receipt                        │
│  Verifiable offline with: npx @veritasacta/verify receipt.json      │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Tamper-Proof Audit Log                                  │
│         (Merkle-chained entries + receipt chain)                     │
│                                                                     │
│  Two independent integrity guarantees:                               │
│  1. AGT AuditLog Merkle chain (operator-side)                        │
│  2. Ed25519 receipt chain (independently verifiable)                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Differentiator: Two Integrity Layers

AGT's `AuditLog` provides a Merkle-chained audit trail maintained by the
operator. This is excellent for internal governance but is only as trustworthy
as the operator.

protect-mcp adds a second layer: Ed25519 signed receipts that are
independently verifiable by any party without trusting the operator. The
receipt chain is verifiable offline using open-source tools:

```bash
npx @veritasacta/verify receipt.json
# exit 0 = valid, exit 1 = tampered, exit 2 = malformed
```

Both layers are needed:
- **AuditLog** catches internal process failures (missed evaluations, dropped entries)
- **Receipt chain** provides external accountability (third-party audit, regulatory evidence)

## Cedar Policy Example

```cedar
// Allow read-only tools for evidenced-tier agents
permit(
    principal,
    action in [Action::"file_system:read_file", Action::"web_search"],
    resource
) when {
    context.trust_tier == "evidenced"
};

// Block destructive tools unless institutional tier
forbid(
    principal,
    action in [Action::"shell_exec", Action::"delete_file"],
    resource
) unless {
    context.trust_tier == "institutional"
};
```

## Standards

- **Ed25519** (RFC 8032) for receipt signatures
- **JCS** (RFC 8785) for deterministic canonicalization before signing
- **Cedar** (AWS) for declarative, formally verifiable policy evaluation
- **IETF Internet-Draft** ([draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)) for receipt format

## Related

- [protect-mcp](https://www.npmjs.com/package/protect-mcp) — MCP gateway with Cedar policies + receipt signing
- [@veritasacta/verify](https://www.npmjs.com/package/@veritasacta/verify) — Offline receipt verification CLI
- [cedar-policy/cedar-for-agents](https://github.com/cedar-policy/cedar-for-agents) — WASM bindings for Cedar MCP schema generation
- [Veritas Acta](https://veritasacta.com) — Open protocol for verifiable machine decisions
