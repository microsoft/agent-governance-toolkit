# Tutorial 51: Cost Governance and Budget Enforcement

AI agents spend real money on every LLM call, tool invocation, and external API.
This tutorial shows how to enforce per-agent and organization-wide budgets with
tiered alerts, auto-throttling, and kill switches.

**Prerequisites:** Install AGT with the SRE package:

```bash
pip install agent-sre
```

## Why Cost Governance?

Without cost governance, a single runaway agent can consume your entire monthly
LLM budget in hours. Multi-agent orchestration makes this worse: cascading calls
across agents multiply costs unpredictably.

AGT's `CostGuard` provides:

| Capability | What It Does |
|------------|-------------|
| Per-agent budgets | Daily spending limits per agent |
| Per-task limits | Maximum cost per single task |
| Organization budget | Global monthly cap across all agents |
| Tiered alerts | Warnings at 50%, 75%, 90%, 95% utilization |
| Auto-throttle | Slow down agents at 85% budget |
| Kill switch | Stop agents at 95% budget |
| Cost anomaly detection | Flag unusual spending patterns |

## Core Concepts

### Post-Action Enforcement

CostGuard uses post-action enforcement: after each action completes, it records
the actual cost and checks budget status. This is more accurate than pre-action
prediction because:

- LLM token counts vary per request
- Tool costs depend on parameters
- Actual costs come from billing APIs, not estimates

```
Action executed -> CostGuard.record_cost() -> Budget check
                                                  |
                                          Under soft cap: log only
                                          Over soft cap: alert
                                          Over hard cap: kill agent
```

### Tiered Budget Model

```
0%        50%       75%       85%      90%      95%     100%
|----------|---------|---------|--------|--------|--------|
   OK       WARN     WARN    THROTTLE  CRIT    KILL    BLOCKED
```

## Step 1: Basic Budget Setup

```python
from agent_sre.cost import CostGuard

# Create a cost guard with budget limits
guard = CostGuard(
    per_task_limit=2.00,          # Max $2 per task
    per_agent_daily_limit=50.00,  # Max $50/day per agent
    org_monthly_budget=1000.00,   # Max $1000/month total
    auto_throttle=True,           # Auto-throttle at 85%, kill at 95%
)

print(f"Per-task limit:    ${guard.per_task_limit:.2f}")
print(f"Daily agent limit: ${guard.per_agent_daily_limit:.2f}")
print(f"Org monthly:       ${guard.org_monthly_budget:.2f}")
```

## Step 2: Pre-Task Budget Check

Before running an expensive task, check if the budget allows it:

```python
# Check if a task can proceed
allowed, reason = guard.check_task("analyst-agent", estimated_cost=1.50)
print(f"Task allowed: {allowed} ({reason})")
# Output: Task allowed: True (ok)

# Check a task that exceeds per-task limit
allowed, reason = guard.check_task("analyst-agent", estimated_cost=5.00)
print(f"Expensive task: {allowed} ({reason})")
# Output: Expensive task: False (Estimated cost $5.00 exceeds per-task limit $2.00)
```

## Step 3: Record Costs and Get Alerts

After each task, record the actual cost:

```python
# Record a normal task
alerts = guard.record_cost("analyst-agent", "task-001", cost_usd=0.50)
print(f"Task 001: $0.50, alerts: {len(alerts)}")

# Record with cost breakdown
alerts = guard.record_cost(
    "analyst-agent",
    "task-002",
    cost_usd=1.20,
    breakdown={"gpt-4": 1.00, "web-search": 0.20},
)
print(f"Task 002: $1.20, alerts: {len(alerts)}")

# Check budget status
budget = guard.get_budget("analyst-agent")
print(f"Spent today:  ${budget.spent_today_usd:.2f}")
print(f"Remaining:    ${budget.remaining_today_usd:.2f}")
print(f"Utilization:  {budget.utilization_percent:.1f}%")
```

## Step 4: Watch Alerts Escalate

As spending increases, alerts escalate through the tiers:

```python
# Simulate spending that triggers alerts
for i in range(20):
    task_id = f"task-{i + 10:03d}"
    alerts = guard.record_cost("analyst-agent", task_id, cost_usd=2.00)
    if alerts:
        for alert in alerts:
            print(f"  [{alert.severity.value.upper()}] {alert.message}")
            if alert.action.value != "alert":
                print(f"    Action: {alert.action.value}")

# Check final budget status
budget = guard.get_budget("analyst-agent")
print(f"\nFinal status:")
print(f"  Spent:     ${budget.spent_today_usd:.2f}")
print(f"  Throttled: {budget.throttled}")
print(f"  Killed:    {budget.killed}")
```

Once an agent is killed, all subsequent tasks are blocked:

```python
allowed, reason = guard.check_task("analyst-agent", estimated_cost=0.01)
print(f"After kill: allowed={allowed}, reason={reason}")
# Output: After kill: allowed=False, reason=Agent killed — budget exhausted
```

## Step 5: Organization-Wide Budget

The global budget tracks spending across ALL agents:

```python
guard = CostGuard(
    per_agent_daily_limit=100.00,
    org_monthly_budget=200.00,  # Low for demo
    kill_switch_threshold=0.95,
)

# Multiple agents spending
for agent in ["agent-a", "agent-b", "agent-c"]:
    alerts = guard.record_cost(agent, "task-1", cost_usd=60.00)
    if alerts:
        for alert in alerts:
            print(f"  [{alert.severity.value.upper()}] {alert.message}")

# Once org budget is killed, ALL agents are blocked
for agent in ["agent-a", "agent-b", "agent-c"]:
    allowed, reason = guard.check_task(agent, estimated_cost=0.01)
    print(f"  {agent}: allowed={allowed}")
```

## Step 6: Cost Anomaly Detection

CostGuard includes built-in anomaly detection for unusual spending:

```python
from agent_sre.cost import CostAnomalyDetector

detector = CostAnomalyDetector()

# Feed normal cost history
for i in range(20):
    detector.ingest(1.0 + (i % 3) * 0.2, agent_id="data-agent")

# Check an anomalous cost - returns AnomalyResult if anomaly detected
result = detector.ingest(50.0, agent_id="data-agent")
if result:
    print(f"Anomaly detected!")
    print(f"Severity: {result.severity.value}")
```

## Step 7: Cost Optimization Suggestions

The cost optimizer suggests cheaper alternatives:

```python
from agent_sre.cost import CostOptimizer, ModelConfig, TaskProfile

optimizer = CostOptimizer()

# Register model options
optimizer.add_model(ModelConfig(
    name="gpt-4",
    cost_per_1k_tokens=0.03,
    quality_score=0.95,
))
optimizer.add_model(ModelConfig(
    name="gpt-3.5-turbo",
    cost_per_1k_tokens=0.002,
    quality_score=0.80,
))

# Get optimization for a task
result = optimizer.optimize(TaskProfile(
    task_type="summarization",
    estimated_tokens=2000,
    quality_requirement=0.75,
))
print(f"Recommended: {result.recommended_model}")
print(f"Estimated cost: ${result.estimated_cost:.4f}")
print(f"Savings vs default: {result.savings_percent:.0f}%")
```

## Budget Configuration Reference

```python
CostGuard(
    per_task_limit=2.0,          # Max cost per single task
    per_agent_daily_limit=100.0, # Max daily spend per agent
    org_monthly_budget=5000.0,   # Global monthly cap
    anomaly_detection=True,      # Enable anomaly detection
    auto_throttle=True,          # Auto-throttle and kill
    kill_switch_threshold=0.95,  # Kill at 95% utilization
    alert_thresholds=[           # Alert at these percentages
        0.50, 0.75, 0.90, 0.95
    ],
)
```

## API Reference

### CostGuard

| Method | Description |
|--------|-------------|
| `check_task(agent_id, estimated_cost)` | Pre-check if task is within budget |
| `record_cost(agent_id, task_id, cost_usd)` | Record actual cost, returns alerts |
| `get_budget(agent_id)` | Get agent's budget status |
| `get_all_budgets()` | Get all agents' budgets |
| `get_alerts()` | Get all triggered alerts |
| `get_summary()` | Get org-wide cost summary |

### AgentBudget

| Field | Type | Description |
|-------|------|-------------|
| `spent_today_usd` | `float` | Total spent today |
| `remaining_today_usd` | `float` | Budget remaining |
| `utilization_percent` | `float` | 0-100% of daily limit |
| `throttled` | `bool` | Auto-throttled at 85% |
| `killed` | `bool` | Killed at 95% |

## What's Next

- [Tutorial 05 - Agent Reliability (SRE)](05-agent-reliability.md): Cost
  governance alongside SLOs and error budgets
- [Tutorial 49 - Multi-Agent Policies](49-multi-agent-policies.md): Combine
  cost limits with collective rate limiting
- [Tutorial 13 - Observability & Tracing](13-observability-and-tracing.md):
  Correlate cost events with OTel traces
