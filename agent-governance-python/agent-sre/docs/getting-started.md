# Getting Started

Install agent-sre and define your first SLO in 5 minutes.

## Install

```bash
pip install agent-sre
```

## Define SLOs for Your Agent

Every production agent needs reliability targets. Agent-SRE gives you three primitives:

- **SLI** (Service Level Indicator) — What you measure (success rate, cost, hallucination rate)
- **SLO** (Service Level Objective) — Your target for that measurement (≥95% success)
- **Error Budget** — How much failure is acceptable before you freeze deploys

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate, CostPerTask, HallucinationRate

# Define indicators
success = TaskSuccessRate(target=0.95, window="24h")
cost = CostPerTask(target_usd=0.50, window="24h")
hallucination = HallucinationRate(target=0.05, window="24h")

# Combine into an SLO with error budget
slo = SLO(
    name="my-agent",
    indicators=[success, cost, hallucination],
    error_budget=ErrorBudget(total=0.05),  # 5% error budget
)
```

## Instrument Your Agent

Add recording calls wherever your agent does work:

```python
# After each task
success.record_task(success=True)
cost.record_cost(cost_usd=0.25)
hallucination.record_evaluation(hallucinated=False)
slo.record_event(good=True)

# Check SLO health
status = slo.evaluate()  # HEALTHY, WARNING, CRITICAL, or EXHAUSTED
print(f"Status: {status.value}")
print(f"Budget remaining: {slo.error_budget.remaining_percent:.1f}%")
```

## Add Cost Guardrails

Prevent runaway spending:

```python
from agent_sre.cost.guard import CostGuard

guard = CostGuard(
    per_task_limit=2.00,           # Block tasks > $2
    per_agent_daily_limit=50.0,    # $50/day per agent
    org_monthly_budget=1000.0,     # $1000/month total
)

# Before each task
allowed, reason = guard.check_task("my-agent", estimated_cost=0.50)
if not allowed:
    print(f"Blocked: {reason}")
```

## Next Steps

- [Concepts](concepts.md) — How agent SLIs differ from infrastructure metrics
- [Examples](../examples/) — Quickstart, cost guard, canary, chaos testing
- [Integration Guide](integration-guide.md) — Use with Agent-OS and AgentMesh
