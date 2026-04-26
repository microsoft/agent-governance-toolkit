# APS-AgentMesh Integration

AgentMesh adapter for the [Agent Passport System](https://github.com/aeoess/agent-passport-system) (APS). Consumes APS policy decisions, passport grades, and delegation scope chains as external trust signals in AGT's PolicyEngine.

## Install

```bash
pip install aps-agentmesh
```

For Ed25519 signature verification, install PyNaCl:

```bash
pip install aps-agentmesh[aps]
```

## Components

| Component | Purpose |
|-----------|---------|
| `APSPolicyGate` | Injects APS PolicyDecision into AGT evaluation context |
| `APSTrustBridge` | Maps APS passport grades (0-3) to AGT trust scores (0-1000) |
| `APSScopeVerifier` | Validates APS delegation scope chains for task assignment |
| `aps_context()` | Builds AGT-compatible context dict from APS artifacts |
| `verify_aps_signature()` | Ed25519 signature verification (requires PyNaCl) |

## Grade-to-score mapping

| Grade | Label | Score | Description |
|-------|-------|-------|-------------|
| 0 | self_signed | 100 | Bare Ed25519 keypair |
| 1 | issuer_countersigned | 400 | Issuer countersigned |
| 2 | runtime_bound | 700 | Infrastructure-attested |
| 3 | principal_bound | 900 | Verified human/org principal |

## Usage

### Policy gate

```python
from aps_agentmesh import APSPolicyGate

gate = APSPolicyGate()

aps_decision = {
    "verdict": "permit",
    "scopeUsed": "deploy.staging",
    "agentId": "claude-operator",
    "delegationId": "del-abc123",
}

context = gate.build_context(aps_decision, passport_grade=2)
# Pass to AGT: policy_engine.evaluate("deploy.staging", context)
```

### AGT policy rule

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
score = bridge.grade_to_score(passport_grade=2)  # 700
bridge.meets_threshold(passport_grade=1, min_score=500)  # False
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
```

## Links

- [Agent Passport System](https://github.com/aeoess/agent-passport-system)
- [APS Python SDK](https://pypi.org/project/agent-passport-system/)
