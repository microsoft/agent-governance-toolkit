# Tutorial 48: Intent-Based Authorization

> **Declare what your agent will do before it does it, and automatically detect when it strays.**

Intent-Based Authorization is a governance layer that sits between an agent and its actions. Before execution begins, the agent declares a *plan* (`declare_intent`). A reviewer or system approves it (`approve_intent`). Each action is checked against that plan (`check_action`). When the session ends, the system compares planned vs. actual (`verify_intent`) and surfaces any drift.

This tutorial covers:

1. [The core lifecycle](#1-core-lifecycle-declare-approve-execute-verify)
2. [Drift detection: SOFT_BLOCK vs HARD_BLOCK](#2-drift-detection-policies)
3. [Child intent scope narrowing for multi-agent systems](#3-child-intent-scope-narrowing)
4. [Running the complete demo](#4-running-the-demo)

---

## Prerequisites

```bash
pip install agent-os-kernel
```

Python 3.9+ required.

---

## 1. Core Lifecycle: Declare, Approve, Execute, Verify

### Step 1: Declare Intent

The agent announces what it plans to do. Nothing runs yet.

```python
import asyncio
from agent_os.intent import DriftPolicy, IntentAction, IntentManager
from agent_os.stateless import MemoryBackend

async def main():
    manager = IntentManager(backend=MemoryBackend())

    intent = await manager.declare_intent(
        agent_id="payment-agent",
        planned_actions=[
            IntentAction(action="read_balance"),
            IntentAction(action="transfer_funds", params_schema={"max_amount": 1000}),
        ],
        drift_policy=DriftPolicy.SOFT_BLOCK,
        ttl_seconds=300,
    )

    print(f"Intent ID: {intent.intent_id}")
    print(f"State:     {intent.state.value}")        # declared
    print(f"Actions:   {intent.planned_action_names}")
```

`IntentAction` accepts an optional `params_schema`, a dict of parameter constraints the action must satisfy. `ttl_seconds` sets an expiry; the intent is rejected if approval or execution happens after it expires.

### Step 2: Approve Intent

Approval moves the intent from `declared` to `approved`, signalling that a human reviewer or automated policy gate has signed off.

```python
    intent = await manager.approve_intent(intent.intent_id)
    print(f"State: {intent.state.value}")   # approved
```

In production this step would be wired to a human-in-the-loop approval queue or a policy engine.

### Step 3: Check Actions at Runtime

Before each action executes, call `check_action`. The manager records the result and transitions the intent to `executing` on the first call.

```python
    # Planned action - allowed
    check = await manager.check_action(
        intent.intent_id,
        "read_balance",
        {},
        "payment-agent",
        "req-001",
    )
    print(f"read_balance:   {'ALLOWED' if check.allowed else 'BLOCKED'}")
    print(f"  was_planned:  {check.was_planned}")

    # Unplanned action - drift detected
    check = await manager.check_action(
        intent.intent_id,
        "delete_account",
        {},
        "payment-agent",
        "req-002",
    )
    print(f"delete_account: {'ALLOWED' if check.allowed else 'BLOCKED'}")
    if check.drift_policy_applied:
        print(f"  policy:  {check.drift_policy_applied.value}")
        print(f"  penalty: -{check.trust_penalty} trust points")
```

`IntentCheckResult` fields:

| Field | Type | Description |
|---|---|---|
| `allowed` | `bool` | Whether the action may proceed |
| `was_planned` | `bool` | Whether the action was in the declared plan |
| `drift_policy_applied` | `DriftPolicy \| None` | Policy triggered on drift |
| `trust_penalty` | `float` | Trust score deduction (default 50.0) |
| `reason` | `str` | Human-readable explanation |

### Step 4: Verify Intent

`verify_intent` closes the session and produces a structured audit report comparing planned vs. actual.

```python
    verification = await manager.verify_intent(intent.intent_id)

    print(f"Final state:   {verification.state.value}")    # violated or completed
    print(f"Planned:       {verification.planned_actions}")
    print(f"Executed:      {verification.executed_actions}")
    print(f"Unplanned:     {verification.unplanned_actions}")
    print(f"Missed:        {verification.missed_actions}")
    print(f"Drift events:  {verification.total_drift_events}")
    print(f"Trust penalty: {verification.total_trust_penalty}")

asyncio.run(main())
```

The intent transitions to `completed` when there are no drift events, or `violated` when drift was detected.

`IntentVerification` fields:

| Field | Description |
|---|---|
| `planned_actions` | Actions declared before execution |
| `executed_actions` | Actions that ran and succeeded |
| `unplanned_actions` | Executed actions not in the plan |
| `missed_actions` | Planned actions that never ran |
| `total_drift_events` | Count of drift detections |
| `total_trust_penalty` | Cumulative trust score deducted |
| `duration_seconds` | Seconds from approval to verification |

---

## 2. Drift Detection Policies

There are three `DriftPolicy` values. Set the policy at `declare_intent` time.

### SOFT_BLOCK (default)

Unplanned actions are *allowed* but flagged. A trust penalty is applied and a `DriftEvent` is recorded. Use this when continuity matters more than strict enforcement.

```python
intent = await manager.declare_intent(
    agent_id="payment-agent",
    planned_actions=[IntentAction(action="read_balance")],
    drift_policy=DriftPolicy.SOFT_BLOCK,
)
intent = await manager.approve_intent(intent.intent_id)

check = await manager.check_action(
    intent.intent_id, "send_notification", {}, "payment-agent", "req-003"
)
print(check.allowed)               # True - action proceeds
print(check.trust_penalty)         # 50.0 - penalty recorded
```

### HARD_BLOCK

Unplanned actions are *denied outright*. Use this for compliance-critical agents where no deviation is acceptable.

```python
from agent_os.intent import DriftPolicy, IntentAction, IntentManager
from agent_os.stateless import MemoryBackend

async def hard_block_demo():
    manager = IntentManager(backend=MemoryBackend())

    intent = await manager.declare_intent(
        agent_id="compliance-agent",
        planned_actions=[IntentAction(action="generate_report")],
        drift_policy=DriftPolicy.HARD_BLOCK,
    )
    intent = await manager.approve_intent(intent.intent_id)

    # Planned - allowed
    check = await manager.check_action(
        intent.intent_id, "generate_report", {}, "compliance-agent", "req-010"
    )
    print(f"generate_report: {'ALLOWED' if check.allowed else 'BLOCKED'}")  # ALLOWED

    # Unplanned - blocked
    check = await manager.check_action(
        intent.intent_id, "send_email", {}, "compliance-agent", "req-011"
    )
    print(f"send_email:      {'ALLOWED' if check.allowed else 'BLOCKED'}")  # BLOCKED
```

### RE_DECLARE

Unplanned actions are denied, and the agent must declare a new intent before continuing. Use this when scope changes require a full re-review cycle.

```python
intent = await manager.declare_intent(
    agent_id="my-agent",
    planned_actions=[IntentAction(action="read_config")],
    drift_policy=DriftPolicy.RE_DECLARE,
)
```

---

## 3. Child Intent Scope Narrowing

In multi-agent orchestration, an orchestrator declares a broad intent and delegates sub-tasks to specialist agents. Child intents must be a *subset* of the parent's planned actions; they cannot expand scope.

```python
from agent_os.intent import IntentAction, IntentManager, IntentScopeError
from agent_os.stateless import MemoryBackend

async def multi_agent_demo():
    manager = IntentManager(backend=MemoryBackend())

    # Orchestrator declares the full scope
    parent = await manager.declare_intent(
        agent_id="orchestrator",
        planned_actions=[
            IntentAction(action="read_balance"),
            IntentAction(action="transfer_funds"),
            IntentAction(action="generate_report"),
        ],
    )
    parent = await manager.approve_intent(parent.intent_id)
    print(f"Parent scope: {parent.planned_action_names}")

    # Sub-agent gets only the actions it needs
    child = await manager.declare_intent(
        agent_id="report-agent",
        planned_actions=[IntentAction(action="generate_report")],
        parent_intent_id=parent.intent_id,
    )
    print(f"Child scope:  {child.planned_action_names}")   # {'generate_report'}

    # A rogue agent trying to exceed parent scope is rejected
    try:
        await manager.declare_intent(
            agent_id="rogue-agent",
            planned_actions=[IntentAction(action="delete_everything")],
            parent_intent_id=parent.intent_id,
        )
    except IntentScopeError as e:
        print(f"Scope violation blocked: {e}")
```

`IntentScopeError` is raised at `declare_intent` time, before the intent is stored, so there is no window in which the child intent exists with excess scope.

You can also use the convenience method `create_child_intent`, which inherits the parent's drift policy by default:

```python
child = await manager.create_child_intent(
    parent_intent_id=parent.intent_id,
    agent_id="report-agent",
    planned_actions=[IntentAction(action="generate_report")],
)
```

---

## 4. Running the Demo

A complete, runnable script is included in the repository:

```bash
pip install agent-os-kernel
python examples/intent-auth/intent_auth_demo.py
```

Expected output:

```
============================================================
  Intent-Based Authorization Demo
============================================================

--- Step 1: Declare Intent ---
  Intent ID:  intent:...
  State:      declared
  Actions:    {'read_balance', 'transfer_funds'}

--- Step 2: Approve Intent ---
  State:      approved

--- Step 3: Execute Actions ---
  read_balance:   ALLOWED (planned)
  delete_account: ALLOWED (DRIFT!)
    policy:  soft_block
    penalty: -50.0 trust points

--- Step 4: Verify Intent ---
  Final state:   violated
  Planned:       ['read_balance', 'transfer_funds']
  Executed:      ['read_balance', 'delete_account']
  Unplanned:     ['delete_account']
  Missed:        ['transfer_funds']
  Drift events:  1
  Trust penalty: 50.0
...
```

---

## Intent Lifecycle States

```
DECLARED --approve--> APPROVED --first action--> EXECUTING
                                                     |
                                    +----------------+
                                    v                v
                               COMPLETED         VIOLATED
                            (no drift)         (drift found)

Any state --ttl expired--> EXPIRED
```

| State | Description |
|---|---|
| `declared` | Intent created, awaiting approval |
| `approved` | Approved, ready for execution |
| `executing` | First `check_action` call received |
| `completed` | `verify_intent` called, no drift |
| `violated` | `verify_intent` called, drift detected |
| `expired` | TTL elapsed before completion |

---

## Key Classes

| Class / Function | Purpose |
|---|---|
| `IntentManager(backend)` | Main entry point; all methods are async |
| `IntentAction(action, params_schema)` | Declares one planned action |
| `DriftPolicy` | Enum: `SOFT_BLOCK`, `HARD_BLOCK`, `RE_DECLARE` |
| `IntentCheckResult` | Return value of `check_action` |
| `IntentVerification` | Return value of `verify_intent` |
| `IntentScopeError` | Raised when child intent exceeds parent scope |
| `MemoryBackend` | In-process backend for development and testing |

For production deployments, replace `MemoryBackend` with `RedisBackend` to share intent state across multiple agent replicas.

---

## Next Steps

- **[5-Minute Quickstart](5-minute-quickstart.md)** - set up your first governed agent
- **[30-Minute Deep Dive](30-minute-deep-dive.md)** - trust scoring, policy engines, and receipts
- **[Custom Tools Tutorial](custom-tools.md)** - register tools that are checked against intent at runtime
