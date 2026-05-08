# Cost Governance Example

Demonstrates AGT's cost governance: tiered budget enforcement, per-agent and
organization-wide caps, auto-throttle, kill switches, and anomaly detection.

## Quick Start

```bash
pip install agent-sre
python cost_governance_demo.py
```

## What This Demo Shows

1. **Budget Setup**: Per-task, per-agent, and org-wide limits
2. **Pre-Task Checks**: Validate cost before execution
3. **Alert Escalation**: Warnings at 50/75/90%, throttle at 85%, kill at 95%
4. **Organization Budget**: Global cap across all agents
5. **Anomaly Detection**: Flag unusual spending patterns

## Learn More

- [Tutorial 51: Cost Governance](../../docs/tutorials/51-cost-governance.md)
- [ADR-0012: Cost Governance](../../docs/adr/0012-cost-governance-observability-policies.md)
- [API: cost/guard.py](../../agent-governance-python/agent-sre/src/agent_sre/cost/guard.py)
