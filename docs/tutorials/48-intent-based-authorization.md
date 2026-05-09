# Tutorial 48: Intent-Based Authorization

> **Package:** `agent-os-kernel` · **Time:** 20 minutes · **Level:** Advanced

Agents say what they plan to do, the system approves the plan, and then
verifies that the agent stuck to it. This tutorial walks through the full
intent lifecycle: **declare, approve, execute, verify**.

**Prerequisites:** Install AGT with the agent-os kernel:

```bash
pip install agent-os-kernel
```

## Why Intent-Based Authorization?

Traditional policy enforcement asks one question: "Is this action allowed?"
Intent-based authorization adds a second question: "Is this action part of what
the agent said it would do?"

This closes a critical gap: an agent might have permission to call
`transfer_funds` and `read_balance`, but if it only declared intent to
`read_balance` and then calls `transfer_funds`, something has gone wrong.

**Intent as a first-class object** gives you:

| Capability | What It Does |
|------------|-------------|
| Declare | Agent states its plan before acting |
| Approve | System (or human) reviews the plan |
| Execute under | Actions are checked against the declared plan |
| Verify | Post-execution audit: planned vs actual |

## Core Concepts

### Intent Lifecycle

```
DECLARED ──> APPROVED ──> EXECUTING ──> COMPLETED
                                    └──> VIOLATED
                                    └──> EXPIRED
```

An `ExecutionIntent` moves through these states. Once it reaches a terminal
state (COMPLETED, VIOLATED, or EXPIRED), it cannot transition further.

### Drift Policies

When an agent attempts an action not in its declared plan, that is **drift**.
Three configurable responses:

| Policy | Behavior | When To Use |
|--------|----------|-------------|
| `soft_block` (default) | Action proceeds, trust score drops, alert fires | Production monitoring |
| `hard_block` | Action is denied outright | High-security environments |
| `re_declare` | Action is denied; agent must file a new intent | Regulated workflows |

### Child Intents (Orchestration)

In multi-agent systems, the orchestrator declares a top-level intent.
Sub-agents inherit from it with **scope narrowing only**: a child intent
can use a subset of the parent's planned actions, never more.

## Step 1: Declare an Intent

Create a new file `intent_demo.py`:

```python
import asyncio
from agent_os.stateless import MemoryBackend
from agent_os.intent import (
    IntentManager,
    IntentAction,
    DriftPolicy,
)

async def main():
    # Create an IntentManager backed by in-memory state
    backend = MemoryBackend()
    manager = IntentManager(backend=backend)

    # Agent declares what it plans to do
    intent = await manager.declare_intent(
        agent_id="payment-agent",
        planned_actions=[
            IntentAction(action="read_balance"),
            IntentAction(
                action="transfer_funds",
                params_schema={"max_amount": 1000},
            ),
        ],
        drift_policy=DriftPolicy.SOFT_BLOCK,
        ttl_seconds=300,  # Intent expires after 5 minutes
    )

    print(f"Intent declared: {intent.intent_id}")
    print(f"State: {intent.state.value}")
    print(f"Planned actions: {intent.planned_action_names}")

asyncio.run(main())
```

Run it:

```bash
python intent_demo.py
```

Expected output:

```
Intent declared: intent:a1b2c3d4e5f6
State: declared
Planned actions: {'read_balance', 'transfer_funds'}
```

## Step 2: Approve the Intent

Before an agent can execute under an intent, it must be approved. This is
where human-in-the-loop or automated approval logic plugs in:

```python
    # Approve the intent (system or human review)
    intent = await manager.approve_intent(intent.intent_id)
    print(f"State after approval: {intent.state.value}")
    # Output: State after approval: approved
```

## Step 3: Execute Actions Under the Intent

Now the agent runs its actions. Each action is checked against the plan:

```python
    # Check a planned action - should be allowed
    check = await manager.check_action(
        intent_id=intent.intent_id,
        action="read_balance",
        params={},
        agent_id="payment-agent",
        request_id="req-001",
    )
    print(f"read_balance: allowed={check.allowed}, planned={check.was_planned}")
    # Output: read_balance: allowed=True, planned=True

    # Check an UNPLANNED action - drift detected!
    check = await manager.check_action(
        intent_id=intent.intent_id,
        action="delete_account",
        params={},
        agent_id="payment-agent",
        request_id="req-002",
    )
    print(f"delete_account: allowed={check.allowed}, planned={check.was_planned}")
    print(f"  drift policy: {check.drift_policy_applied.value}")
    print(f"  trust penalty: {check.trust_penalty}")
    # Output:
    # delete_account: allowed=True, planned=False
    #   drift policy: soft_block
    #   trust penalty: 50.0
```

Under `soft_block`, the action still proceeds but:
- The trust score drops by 50 points
- A `DriftEvent` is recorded for audit
- An alert would fire in production

## Step 4: Verify the Intent

After the agent finishes, verify what actually happened vs what was planned:

```python
    # Complete the intent and get verification summary
    verification = await manager.verify_intent(intent.intent_id)

    print(f"\n--- Verification Report ---")
    print(f"Intent: {verification.intent_id}")
    print(f"Final state: {verification.state.value}")
    print(f"Planned:   {verification.planned_actions}")
    print(f"Executed:  {verification.executed_actions}")
    print(f"Unplanned: {verification.unplanned_actions}")
    print(f"Missed:    {verification.missed_actions}")
    print(f"Drift events: {verification.total_drift_events}")
    print(f"Trust penalty: {verification.total_trust_penalty}")
```

Expected output:

```
--- Verification Report ---
Intent: intent:a1b2c3d4e5f6
Final state: completed
Planned:   ['read_balance', 'transfer_funds']
Executed:  ['read_balance', 'delete_account']
Unplanned: ['delete_account']
Missed:    ['transfer_funds']
Drift events: 1
Trust penalty: 50.0
```

This tells you the agent drifted: it ran `delete_account` (unplanned) and
never ran `transfer_funds` (missed).

## Step 5: Hard Block Drift Policy

For high-security scenarios, switch to `hard_block` to stop drift immediately:

```python
    # Declare with hard_block
    strict_intent = await manager.declare_intent(
        agent_id="compliance-agent",
        planned_actions=[
            IntentAction(action="generate_report"),
        ],
        drift_policy=DriftPolicy.HARD_BLOCK,
    )
    strict_intent = await manager.approve_intent(strict_intent.intent_id)

    # Try an unplanned action - BLOCKED
    check = await manager.check_action(
        intent_id=strict_intent.intent_id,
        action="send_email",
        params={},
        agent_id="compliance-agent",
        request_id="req-003",
    )
    print(f"send_email: allowed={check.allowed}")
    # Output: send_email: allowed=False
```

## Step 6: Child Intents for Multi-Agent

When an orchestrator delegates to sub-agents, child intents enforce
scope narrowing:

```python
    # Parent (orchestrator) declares broad intent
    parent = await manager.declare_intent(
        agent_id="orchestrator",
        planned_actions=[
            IntentAction(action="read_balance"),
            IntentAction(action="transfer_funds"),
            IntentAction(action="generate_report"),
        ],
    )
    parent = await manager.approve_intent(parent.intent_id)

    # Child agent can only narrow the scope
    child = await manager.declare_intent(
        agent_id="report-agent",
        planned_actions=[
            IntentAction(action="generate_report"),  # subset of parent
        ],
        parent_intent_id=parent.intent_id,
    )
    print(f"Child intent created: {child.intent_id}")

    # Attempting to EXPAND scope beyond parent raises IntentScopeError
    from agent_os.intent import IntentScopeError
    try:
        bad_child = await manager.declare_intent(
            agent_id="rogue-agent",
            planned_actions=[
                IntentAction(action="delete_everything"),  # not in parent!
            ],
            parent_intent_id=parent.intent_id,
        )
    except IntentScopeError as e:
        print(f"Scope violation caught: {e}")
    # Output: Scope violation caught: Child intent cannot expand parent scope...
```

## Step 7: Integration with StatelessKernel

Intent-based authorization integrates directly into the `StatelessKernel`
execution pipeline. When an `intent_id` is provided in the `ExecutionContext`,
the kernel checks every action against the declared plan between policy
evaluation and action execution:

```python
from agent_os.stateless import StatelessKernel, ExecutionContext, MemoryBackend

backend = MemoryBackend()
manager = IntentManager(backend=backend)
kernel = StatelessKernel(intent_manager=manager)

# Declare and approve intent
intent = await manager.declare_intent(
    agent_id="my-agent",
    planned_actions=[IntentAction(action="web_search")],
)
intent = await manager.approve_intent(intent.intent_id)

# Execute with intent_id in context
context = ExecutionContext(
    agent_id="my-agent",
    action="web_search",
    intent_id=intent.intent_id,  # Links to the intent
)
result = await kernel.execute(context)
```

The kernel pipeline becomes:

```
1. Policy evaluation (existing)
2. Intent check (NEW - if intent_id is present)
3. Action execution
4. Audit logging
```

## API Reference

### IntentAction

| Field | Type | Description |
|-------|------|-------------|
| `action` | `str` | Action name (e.g. "database_query") |
| `params_schema` | `dict` | Optional parameter constraints |

### ExecutionIntent

| Field | Type | Description |
|-------|------|-------------|
| `intent_id` | `str` | Unique identifier |
| `agent_id` | `str` | Declaring agent |
| `planned_actions` | `list[IntentAction]` | Actions the agent plans to do |
| `drift_policy` | `DriftPolicy` | soft_block, hard_block, or re_declare |
| `state` | `IntentState` | Current lifecycle state |
| `version` | `int` | Optimistic concurrency version |
| `parent_intent_id` | `str` | Parent intent for scope narrowing |
| `expires_at` | `datetime` | Optional expiry time |

### IntentManager Methods

| Method | Description |
|--------|-------------|
| `declare_intent()` | Create a new intent in DECLARED state |
| `approve_intent()` | Move to APPROVED state |
| `check_action()` | Check if an action is planned; returns `IntentCheckResult` |
| `verify_intent()` | Complete and return `IntentVerification` summary |
| `get_intent()` | Retrieve current intent state |

## What's Next

- [Tutorial 01 - Policy Engine](01-policy-engine.md): Combine intent with
  YAML-based policies
- [Tutorial 13 - Observability & Tracing](13-observability-and-tracing.md):
  Correlate drift events with OTel traces
- [Tutorial 23 - Delegation Chains](23-delegation-chains.md): Use child intents
  alongside delegation chain governance
