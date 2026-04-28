# Template AgentMesh Integration

Starter template for building an AgentMesh trust layer for any agent framework.
Copy this package and rename it for your target framework.

See [Tutorial 28 — Building Custom Governance Integrations](../../../docs/tutorials/28-build-custom-integration.md) for the full walkthrough.

## Quick Start

```python
from template_agentmesh import AgentProfile, ActionGuard, TrustTracker

# Define agents with trust scores and capabilities
agent = AgentProfile(
    did="did:mesh:researcher",
    name="Researcher",
    capabilities=["search", "analyze"],
    trust_score=700,
)

# Gate actions by trust score and capabilities
guard = ActionGuard(
    min_trust_score=500,
    sensitive_actions={"delete": 800},
    blocked_actions=["drop_database"],
)

result = guard.check(agent, "search", required_capabilities=["search"])
assert result.allowed

# Track outcomes to adjust trust over time
tracker = TrustTracker(reward=10, penalty=50)
tracker.record_success(agent, "search")
assert agent.trust_score == 710
```

## How to Use This Template

1. Copy `template-agentmesh/` to `yourframework-agentmesh/`
2. Rename `template_agentmesh/` to `yourframework_agentmesh/`
3. Update `pyproject.toml`: package name, description, keywords
4. Extend `AgentProfile` with framework-specific fields
5. Customize `ActionGuard` with framework-specific action types
6. Add framework-specific validation logic to `ActionGuard.check()`
7. Run `pytest tests/ -x -q --tb=short`

## Components

| Component | Purpose |
|-----------|---------|
| `AgentProfile` | Agent identity with DID, capabilities, and trust score |
| `ActionResult` | Outcome of a trust-gated action check |
| `ActionGuard` | Trust score and capability verification before actions |
| `TrustTracker` | Records outcomes and adjusts trust scores over time |

## Design Decisions

- **Zero dependencies** — no hard dep on the target framework or AgentMesh
- **Duck typing** — tests run without the framework SDK installed
- **did:mesh: format** — compatible with AgentMesh identity system
- **0-1000 trust scale** — matches the toolkit convention
- **Asymmetric reward/penalty** — small reward (+10), large penalty (-50)
