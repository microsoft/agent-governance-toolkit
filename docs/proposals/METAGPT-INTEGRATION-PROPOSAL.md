# MetaGPT — Trust Layer Integration

**Submission:** [FoundationAgents/MetaGPT#1936](https://github.com/FoundationAgents/MetaGPT/pull/1936)
**Status:** Open PR — awaiting review
**Type:** Extension module (`metagpt.ext.agentmesh`)
**Date Submitted:** March 2, 2026

---

## Summary

Inter-agent trust verification for MetaGPT multi-agent teams using Agent-Mesh. Adds cryptographic identity (DIDs), trust scoring, capability-based access control, and audit logging to MetaGPT's role-based architecture.

## Problem

MetaGPT enables powerful multi-agent collaboration through specialized roles, but agents interact without verifying trust:
- ProductManager sends requirements → Is PM authorized?
- Architect designs system → Can we trust the design?
- Engineer writes code → Should we execute untrusted code?

Without trust verification, a compromised role in the pipeline can inject malicious instructions that propagate through the entire team.

## Solution

### TrustedTeam
```python
from metagpt.ext.agentmesh import TrustedTeam, TrustPolicy, TrustLevel

policy = TrustPolicy(
    min_trust_level=TrustLevel.MEDIUM,
    sensitive_actions={"WriteCode", "ExecuteCode"},
    sensitive_action_trust=TrustLevel.HIGH,
)

team = TrustedTeam(policy=policy)
team.add_role(ProductManager(), trust_level=TrustLevel.HIGH)
team.add_role(Engineer(), trust_level=TrustLevel.MEDIUM)

# Verifies trust before interaction
team.verify_message("ProductManager", "Engineer", "AssignTask")
```

### Key Components

| Component | Purpose |
|-----------|---------|
| **TrustedRole** | Wraps MetaGPT roles with cryptographic identity |
| **TrustPolicy** | Configurable trust requirements per team |
| **TrustVerifier** | Verifies interactions between agents |
| **TrustedTeam** | Team wrapper with enforcement |

### Trust Levels

| Level | Score | Use Case |
|-------|-------|----------|
| LOW | 0.0–0.3 | Read-only roles, observers |
| MEDIUM | 0.3–0.7 | Standard collaboration roles |
| HIGH | 0.7–1.0 | Code execution, system modifications |

## Value Proposition

| Feature | Without Trust | With Agent-Mesh |
|---------|--------------|-----------------|
| Agent Identity | None | Cryptographic DIDs |
| Interaction Control | None | Policy-based |
| Sensitive Actions | Unrestricted | Trust-gated |
| Audit Trail | None | Full logging |

## Files Added

```
metagpt/ext/agentmesh/
├── __init__.py      # Public exports
├── trust_layer.py   # Core trust primitives
└── README.md        # Documentation
```

## Links

- [MetaGPT](https://github.com/FoundationAgents/MetaGPT)
- [Agent Mesh](https://github.com/microsoft/agent-governance-toolkit)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
