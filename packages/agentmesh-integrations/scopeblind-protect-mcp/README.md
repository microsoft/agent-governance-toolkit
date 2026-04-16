# ScopeBlind protect-mcp Integration

AgentMesh integration for [protect-mcp](https://www.npmjs.com/package/protect-mcp) — Cedar policy enforcement and verifiable decision receipts for MCP tool calls.

## What protect-mcp does

protect-mcp is a security gateway that wraps any MCP server with:

- **Cedar policy evaluation** (AWS Cedar via WASM, sub-ms latency)
- **Ed25519 decision receipts** (signed proof of every allow/deny decision)
- **Issuer-blind verification** (verifier can confirm receipt validity without learning who issued it)
- **Spending authority** (prove an agent's purchase is authorized without revealing org details)

Published on npm: `npx protect-mcp@latest` | [GitHub](https://github.com/ScopeBlind/scopeblind-gateway) | [Docs](https://scopeblind.com/docs/protect-mcp)

## How it complements AGT

| Layer | AGT | protect-mcp |
|-------|-----|-------------|
| Analysis | MCP Security Scanner (static) | Cedar WASM (runtime) |
| Identity | DID + trust scores | Ed25519 passports + VOPRF |
| Decisions | PolicyEngine evaluate() | Cedar allow/deny + signed receipts |
| Proof | Audit log | Cryptographic receipts (offline-verifiable) |
| Privacy | Trust scores are visible | Issuer-blind (verifier learns nothing about issuer) |

They compose naturally: Cedar is the hard constraint, AGT trust is the soft signal.

## Components

| Component | Purpose |
|-----------|---------|
| `CedarPolicyBridge` | Maps Cedar allow/deny into AGT `evaluate()` — Cedar deny is authoritative |
| `ReceiptVerifier` | Validates receipt structure, extracts AGT-compatible metadata |
| `SpendingGate` | Enforces issuer-blind spending authority with trust-score gating |
| `scopeblind_context()` | Builds AGT-compatible context dict from protect-mcp artifacts |

## Quick Start

```python
from scopeblind_protect_mcp import CedarDecision, CedarPolicyBridge, scopeblind_context

# Cedar denied this tool call (e.g., clinejection policy blocked shell_exec)
decision = CedarDecision(
    effect="deny",
    tool_name="shell_exec",
    policy_ids=["sb-clinejection-004"],
)

# Bridge into AGT — Cedar deny is authoritative regardless of trust score
bridge = CedarPolicyBridge(trust_floor=300)
result = bridge.evaluate(
    cedar_decision=decision,
    agent_trust_score=900,  # high trust doesn't override Cedar deny
    agent_did="did:mesh:agent-1",
)
assert not result["allowed"]  # Cedar deny is final

# Build AGT-compatible context for policy engine
ctx = scopeblind_context(cedar_decision=decision)
# Pass to AGT: policy_engine.evaluate(action="tool_call", context=ctx)
```

## Spending Authority

```python
from scopeblind_protect_mcp import SpendingGate

gate = SpendingGate(
    max_single_amount=5000.0,
    high_util_trust_floor=500,
    blocked_categories=["gambling"],
)

# Low-value spend: auto-approved
result = gate.evaluate_spend(amount=50.0, category="cloud_compute", agent_trust_score=300)
assert result["allowed"]

# High utilization + low trust: denied
result = gate.evaluate_spend(
    amount=50.0,
    utilization_band="high",
    agent_trust_score=200,
)
assert not result["allowed"]
```

## Receipt Verification

```python
from scopeblind_protect_mcp import ReceiptVerifier

verifier = ReceiptVerifier()

receipt = {
    "type": "scopeblind:decision",
    "payload": {"effect": "allow", "tool": "web_search", "timestamp": 1711929600},
    "signature": "base64_ed25519_signature",
    "publicKey": "base64_ed25519_public_key",
}

result = verifier.validate_structure_only(receipt)
assert result["valid"]

# Convert to AGT context
ctx = verifier.to_agt_context(receipt)
assert ctx["issuer_blind"] is True
```

## Design Principles

1. **Cedar deny is authoritative.** No trust score, no override. Formal policy beats behavioral signal.
2. **Receipts are issuer-blind.** The verifier confirms validity without learning which organization issued the receipt. This prevents supply-chain surveillance.
3. **Composable, not competing.** protect-mcp handles the tool-call boundary. AGT handles the agent lifecycle. This adapter maps between them.
4. **Offline-verifiable.** Receipts can be verified without contacting the issuer, using `@veritasacta/verify`.

## Protocol

protect-mcp receipts follow the [Veritas Acta signed receipt format](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/), an IETF Internet-Draft for portable, verifiable decision artifacts.
