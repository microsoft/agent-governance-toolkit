# Cost Governance Example

Demonstrates AGT's cost governance: tiered budget enforcement, per-agent and
organization-wide caps, auto-throttle, kill switches, and anomaly detection.

## Prerequisites

- Python 3.10+
- No API keys required

```bash
pip install agent-sre
```

## How to Run

```bash
python examples/cost-governance/cost_governance_demo.py
```

## Expected Output

```
  Budget Setup: per-task $2.00, daily $20.00, org $100.00
  Pre-task checks: $1.50 allowed, $5.00 blocked (over limit)
  Alert escalation: WARNING at 50%, THROTTLE at 85%, KILL at 95%
  Org budget: cross-agent spending tracked, kill switch applied
  Anomaly detection: $50.00 flagged against $1.00-$1.40 baseline
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
