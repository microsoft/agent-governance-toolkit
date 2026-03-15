# OpenAI Swarm — Trust-Verified Handoffs

**Submission:** [openai/swarm#65](https://github.com/openai/swarm/pull/65)
**Status:** Open PR — awaiting review
**Type:** Contrib module (`swarm.contrib.agentmesh`)
**Date Submitted:** March 2, 2026

---

## Summary

Trust-verified handoffs for OpenAI Swarm using Agent-Mesh's CMVK identity layer. Ensures only trusted agents can receive handoffs, prevents context exfiltration, and maintains a full audit trail of handoff chains.

## Problem

Swarm enables multi-agent orchestration through handoffs, but has no built-in way to:
- Verify the receiving agent is trusted
- Prevent handoffs to malicious/compromised agents
- Audit handoff chains for compliance
- Protect sensitive context during handoffs

In multi-agent systems, handoffs create attack vectors — a compromised agent could intercept sensitive data flowing through the handoff chain.

## Solution

### TrustedSwarm
Wrapper around Swarm with trust-verified handoffs:
```python
from swarm.contrib.agentmesh import TrustedSwarm, TrustPolicy

policy = TrustPolicy(min_trust_score=0.5, audit_logging=True)
swarm = TrustedSwarm(policy=policy)

swarm.register_agent(triage, trust_score=0.8)
swarm.register_agent(sales, trust_score=0.7)

response = swarm.run(triage, messages)  # Handoffs verified
```

### Key Components

| Component | Purpose |
|-----------|---------|
| **TrustedSwarm** | Wrapper with trust-verified handoffs |
| **TrustPolicy** | Configurable trust requirements |
| **HandoffVerifier** | Validates trust before allowing handoffs |
| **AgentIdentity** | DID-based agent identification (`did:swarm:xxx`) |

### Trust Verification Rules

Handoffs are blocked when:
- Target agent is not registered
- Target agent is in blocked list
- Target agent's trust score is below threshold
- Sensitive context present + insufficient trust level

### Features

| Feature | Description |
|---------|-------------|
| Trust scores | 0.0–1.0 score per agent |
| Blocked agents | Prevent handoffs to specific agents |
| Allowed list | Only allow handoffs to approved agents |
| Sensitive context | Higher trust required for sensitive data |
| Audit logging | Full handoff history with timestamps |
| Violation callbacks | Custom handling for blocked handoffs |

## Files Added

```
swarm/contrib/agentmesh/
├── __init__.py              # Module exports
├── trusted_handoff.py       # Core implementation
├── README.md                # Documentation
└── test_trusted_handoff.py  # Tests
```

## Links

- [OpenAI Swarm](https://github.com/openai/swarm)
- [Agent Mesh](https://github.com/microsoft/agent-governance-toolkit)
- [CMVK Model](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/cmvk.md)
