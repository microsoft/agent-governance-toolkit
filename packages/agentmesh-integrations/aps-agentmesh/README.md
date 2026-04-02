# APS-AgentMesh Integration

AgentMesh adapter for the [Agent Passport System](https://github.com/aeoess/agent-passport-system) (APS). Bridges APS structural authorization into AGT's PolicyEngine as external trust signals.

## Architecture

APS governs **between** processes: cryptographic proof of authorization scope via Ed25519 delegation chains with monotonic narrowing.

AGT governs **inside** the process: policy evaluation, trust scoring, execution rings.

Together: APS structural authorization is a **hard constraint** (gate). AGT behavioral trust scoring is a **soft signal**.

## Components

| Component | Purpose |
|-----------|---------|
| `APSPolicyGate` | Injects APS PolicyDecision into AGT evaluation context |
| `APSTrustBridge` | Maps APS passport grades (0-3) to AGT trust scores (0-1000) |
| `APSScopeVerifier` | Validates APS delegation scope chains for task assignment |
| `aps_context()` | Builds AGT-compatible context dict from APS artifacts |
| `verify_aps_signature()` | Ed25519 signature verification for APS artifacts |

## Passport Grades → Trust Scores

| Grade | Label | Trust Score | Meaning |
|-------|-------|-------------|---------|
| 0 | self_signed | 100 | Bare Ed25519 keypair |
| 1 | issuer_countersigned | 400 | AEOESS processed the request |
| 2 | runtime_bound | 700 | Challenge-response + infrastructure attestation |
| 3 | principal_bound | 900 | Runtime + verified human/org principal |

## Usage

### As AGT PolicyEngine context

```python
from aps_agentmesh import APSPolicyGate

gate = APSPolicyGate()

# APS PolicyDecision (from APS gateway or MCP server)
aps_decision = {
    "verdict": "permit",
    "scopeUsed": "deploy.staging",
    "agentId": "claude-operator",
    "delegationId": "del-abc123",
}

# Build AGT-compatible context
context = gate.build_context(aps_decision, passport_grade=2)

# Pass to AGT PolicyEngine
decision = policy_engine.evaluate("deploy.staging", context)
```

### AGT policy rule consuming APS

```yaml
- name: require-aps-authorization
  type: capability
  conditions:
    aps_decision.verdict: "permit"
  allowed_actions:
    - "deploy.*"
```

### Trust bridging

```python
from aps_agentmesh import APSTrustBridge

bridge = APSTrustBridge()

# Grade 2 (runtime-bound) → 700 trust score
score = bridge.grade_to_score(passport_grade=2)

# Check minimum threshold
if bridge.meets_threshold(passport_grade=1, min_score=500):
    print("Insufficient attestation for this action")
```

### Scope verification

```python
from aps_agentmesh import APSScopeVerifier

verifier = APSScopeVerifier()
ok, reason = verifier.verify(
    scope_chain=delegation_json,
    required_scope="commerce:checkout",
    required_spend=49.99,
)
if not ok:
    print(f"Denied: {reason}")
```

## Links

- [Agent Passport System](https://github.com/aeoess/agent-passport-system) — APS SDK
- [APS Python SDK](https://pypi.org/project/agent-passport-system/) — Python bindings
