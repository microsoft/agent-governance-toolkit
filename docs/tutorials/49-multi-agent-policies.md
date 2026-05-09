# Tutorial 49: Multi-Agent Collective Policies

> **Package:** `agentmesh-platform` · **Time:** 20 minutes · **Level:** Advanced

---

## What You'll Learn

- Enforcing aggregate rate limits and concurrent caps across agent meshes
- Detecting coordinated multi-agent activity with collective policies
- Alert-only monitoring mode for observing before enforcing
- Combining per-agent and collective policy rules

**Prerequisites:** Install AGT with the mesh package:

```bash
pip install agentmesh-platform
```

## Why Multi-Agent Policies?

Per-agent policies answer: "Is this agent allowed to do this action?"
Multi-agent policies answer: "Given what ALL agents are doing collectively,
should this action proceed?"

| Per-Agent Policy | Multi-Agent Policy |
|------------------|--------------------|
| "Agent X can transfer up to $1000" | "No more than 3 transfers across all agents per minute" |
| "Agent Y can write to database" | "At most 2 distinct agents writing to DB simultaneously" |
| "Agent Z can send emails" | "Alert if total email volume exceeds 50/hour" |

The `MultiAgentPolicyEvaluator` runs as a **separate evaluation pass** at the
mesh router level, watching all agents collectively.

## Core Concepts

### Collective Constraints

A collective constraint aggregates behavior across all agents in a time window:

```yaml
name: rate-limit-transfers
scope: multi-agent
condition:
  aggregate: count           # COUNT, SUM, MAX, or DISTINCT_AGENTS
  filter_tool: transfer_funds
  window_seconds: 60         # sliding 60-second window
  threshold: 3               # max 3 transfers per minute
action: deny                 # DENY, ALERT, or THROTTLE
```

### Aggregate Functions

| Function | What It Counts |
|----------|---------------|
| `COUNT` | Total number of matching actions in the window |
| `SUM` | Sum of a numeric metadata field across actions |
| `MAX` | Maximum value of a metadata field |
| `DISTINCT_AGENTS` | Number of unique agents that performed the action |

### Policy Actions

| Action | Behavior |
|--------|----------|
| `DENY` | Block the action |
| `ALERT` | Allow but log a violation (non-blocking) |
| `THROTTLE` | Rate-limit (future, currently treated as deny) |

## Step 1: Create a Basic Rate Limit

```python
from agentmesh.governance.multi_agent_policy import (
    ActionRecord,
    AggregateFunction,
    CollectiveCondition,
    MultiAgentAction,
    MultiAgentPolicy,
    MultiAgentPolicyEvaluator,
)

# Create evaluator
evaluator = MultiAgentPolicyEvaluator()

# Add a rate-limit policy: max 3 transfers per 60 seconds
evaluator.add_policy(MultiAgentPolicy(
    name="rate-limit-transfers",
    condition=CollectiveCondition(
        aggregate=AggregateFunction.COUNT,
        filter_tool="transfer_funds",
        window_seconds=60.0,
        threshold=3.0,
    ),
    action=MultiAgentAction.DENY,
))
```

## Step 2: Record Actions and Evaluate

As agents perform actions, the governance pipeline records them. Before
each new action, the evaluator checks collective constraints:

```python
# Agent 1 transfers funds
evaluator.record_action(ActionRecord(
    agent_id="agent-1", action="transfer", tool_name="transfer_funds",
))
result = evaluator.evaluate("agent-1", "transfer", "transfer_funds")
print(f"Transfer 1: allowed={result.allowed}")
# Output: Transfer 1: allowed=True

# Agent 2 transfers funds
evaluator.record_action(ActionRecord(
    agent_id="agent-2", action="transfer", tool_name="transfer_funds",
))
result = evaluator.evaluate("agent-2", "transfer", "transfer_funds")
print(f"Transfer 2: allowed={result.allowed}")
# Output: Transfer 2: allowed=True

# Agent 3 tries to transfer - hits the threshold!
result = evaluator.evaluate("agent-3", "transfer", "transfer_funds")
print(f"Transfer 3: allowed={result.allowed}")
print(f"  violated: {result.violated_policies}")
# Output: Transfer 3: allowed=False
#   violated: ['rate-limit-transfers']
```

## Step 3: Limit Concurrent Agents

Restrict how many distinct agents can perform a sensitive operation:

```python
evaluator.add_policy(MultiAgentPolicy(
    name="max-db-writers",
    condition=CollectiveCondition(
        aggregate=AggregateFunction.DISTINCT_AGENTS,
        filter_action="database_write",
        window_seconds=30.0,
        threshold=2.0,  # max 2 different agents writing
    ),
    action=MultiAgentAction.DENY,
))

# Agent 1 writes
evaluator.record_action(ActionRecord(
    agent_id="agent-1", action="database_write", tool_name="db",
))

# Agent 1 writes again - same agent, still 1 distinct
result = evaluator.evaluate("agent-1", "database_write", "db")
print(f"Agent-1 again: allowed={result.allowed}")  # True

# Agent 2 writes - now 2 distinct agents, at threshold
evaluator.record_action(ActionRecord(
    agent_id="agent-2", action="database_write", tool_name="db",
))

# Agent 3 tries - would be 3 distinct agents, DENIED
result = evaluator.evaluate("agent-3", "database_write", "db")
print(f"Agent-3: allowed={result.allowed}")  # False
```

## Step 4: Alert Without Blocking

Use `ALERT` for monitoring policies that log violations without blocking:

```python
evaluator.add_policy(MultiAgentPolicy(
    name="high-volume-alert",
    condition=CollectiveCondition(
        aggregate=AggregateFunction.COUNT,
        window_seconds=300.0,
        threshold=20.0,  # alert if more than 20 actions in 5 minutes
    ),
    action=MultiAgentAction.ALERT,  # non-blocking
))

# Even when threshold is exceeded, action proceeds
result = evaluator.evaluate("agent-1", "some_action")
print(f"allowed={result.allowed}")  # True (alert, not deny)
if result.violated_policies:
    print(f"  alerts: {result.violated_policies}")
```

## Step 5: Load Policies from Configuration

Load policies from dictionaries (e.g., parsed from YAML/JSON config):

```python
policy_configs = [
    {
        "name": "global-transfer-limit",
        "condition": {
            "aggregate": "count",
            "filter_tool": "transfer_funds",
            "window_seconds": 60,
            "threshold": 5,
        },
        "action": "deny",
    },
    {
        "name": "email-volume-alert",
        "condition": {
            "aggregate": "count",
            "filter_tool": "send_email",
            "window_seconds": 3600,
            "threshold": 100,
        },
        "action": "alert",
    },
]

evaluator = MultiAgentPolicyEvaluator()
count = evaluator.load_policies_from_dicts(policy_configs)
print(f"Loaded {count} policies")
```

## Step 6: Monitor with Window Stats

Get a snapshot of collective activity:

```python
stats = evaluator.get_window_stats(window_seconds=60.0)
print(f"Actions in last 60s: {stats['total_actions']}")
print(f"Unique agents:       {stats['unique_agents']}")
print(f"Active agents:       {stats['agent_ids']}")
```

## How It Fits in the Governance Pipeline

The multi-agent evaluator sits at the mesh router level, above per-agent
policy evaluation:

```
Agent Request
    |
    v
Per-Agent PolicyEngine  -->  DENY/ALLOW per agent rules
    |
    v
MultiAgentPolicyEvaluator  -->  DENY/ALLOW collective rules
    |
    v
Action Execution
    |
    v
Record action in evaluator  (for future window checks)
```

Per-agent and multi-agent policies are evaluated independently. Both must
allow for the action to proceed.

## API Reference

### MultiAgentPolicyEvaluator

| Method | Description |
|--------|-------------|
| `add_policy(policy)` | Add or update a policy |
| `remove_policy(name)` | Remove a policy by name |
| `load_policies_from_dicts(dicts)` | Bulk load from config |
| `evaluate(agent_id, action, tool)` | Check collective constraints |
| `record_action(record)` | Record an observed action |
| `get_window_stats(window)` | Get activity snapshot |
| `clear_history()` | Clear all recorded actions |
| `list_policies()` | List all registered policies |

### CollectiveCondition

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `aggregate` | `AggregateFunction` | required | COUNT, SUM, MAX, DISTINCT_AGENTS |
| `filter_action` | `str` | None | Only match this action name |
| `filter_tool` | `str` | None | Only match this tool name |
| `window_seconds` | `float` | 60.0 | Sliding window size |
| `threshold` | `float` | 1.0 | Trigger value |

## What's Next

- [Tutorial 23 - Delegation Chains](23-delegation-chains.md): Combine with
  scope narrowing in multi-agent setups
- [Tutorial 48 - Intent-Based Authorization](48-intent-based-authorization.md):
  Layer intent verification on top of collective policies
- [Tutorial 13 - Observability & Tracing](13-observability-and-tracing.md):
  Correlate multi-agent policy violations with OTel traces
