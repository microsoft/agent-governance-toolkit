# Tutorial 11 — Saga Orchestration

> **Package:** `agentmesh-runtime` · **Time:** 30 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- Multi-step transactions with compensating actions
- Saga DSL for declarative pipeline definitions
- Fan-out for parallel step execution
- Compensating actions and rollback strategies

---

**Multi-step agent transactions with compensating actions, parallel fan-out, and semantic checkpoints.**

See also: [Execution Sandboxing (Tutorial 06)](./06-execution-sandboxing.md) | [Observability & Tracing (Tutorial 13)](./13-observability-and-tracing.md) | [Agent Runtime README](../../agent-governance-python/agent-runtime/README.md)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Quick Start: A 3-Step Saga with Compensation](#3-quick-start-a-3-step-saga-with-compensation)
4. [SagaOrchestrator](#4-sagaorchestrator)
5. [Saga & Step State Machines](#5-saga--step-state-machines)
6. [SagaDSLParser — Declarative Saga Definitions](#6-sagadslparser--declarative-saga-definitions)
7. [Schema Validation](#7-schema-validation)
8. [Compensating Transactions](#8-compensating-transactions)
9. [FanOutOrchestrator — Parallel Step Execution](#9-fanoutorchestrator--parallel-step-execution)
10. [CheckpointManager — Save & Restore Saga State](#10-checkpointmanager--save--restore-saga-state)
11. [Error Handling](#11-error-handling)
12. [Integration with Execution Rings](#12-integration-with-execution-rings)
13. [Real-World Example: Multi-Agent Data Pipeline](#13-real-world-example-multi-agent-data-pipeline)
14. [Next Steps](#14-next-steps)

---

## 1. Introduction

AI agents executing multi-step workflows face a classic distributed systems
problem: **what happens when step 3 of 5 fails?** Without transaction-like
guarantees, a failed step leaves partial state, orphaned resources, or
invisible corruption.

The **Saga pattern** solves this by pairing every forward action with a
**compensating action**. If any step fails, the orchestrator walks backward
through completed steps, calling each compensator in reverse order.

```
Forward execution:
  Step 1: Create PR  ──→  Step 2: Run tests  ──→  Step 3: Deploy
  (undo: close PR)        (undo: cancel run)       (undo: rollback)

If Step 3 fails:
  ← Compensate Step 2 (cancel test run)
  ← Compensate Step 1 (close PR)
  → Saga: RUNNING → COMPENSATING → COMPLETED
```

| Component | Purpose |
|-----------|---------|
| `SagaOrchestrator` | Sequential step execution with retry and compensation |
| `SagaDSLParser` | Declarative saga definitions from structured dictionaries |
| `SagaSchemaValidator` | JSON schema validation for saga definitions |
| `FanOutOrchestrator` | Parallel step execution with success policies |
| `CheckpointManager` | Semantic checkpoints for replay and skip-ahead |

---

## 2. Installation

```bash
pip install agentmesh-runtime
```

Import from either package:

```python
# From runtime (convenience re-exports)
from agent_runtime import (
    SagaOrchestrator, SagaState, StepState,
    FanOutOrchestrator, FanOutPolicy,
    CheckpointManager, SagaDSLParser, SagaDefinition,
)

# Or directly from hypervisor
from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.saga.state_machine import Saga, SagaStep, SagaState, StepState
from hypervisor.saga.dsl import SagaDSLParser, SagaDefinition
from hypervisor.saga.fan_out import FanOutOrchestrator, FanOutPolicy, FanOutGroup
from hypervisor.saga.checkpoint import CheckpointManager, SemanticCheckpoint
from hypervisor.saga.schema import SagaSchemaValidator, SagaSchemaError
```

**Requirements:** Python ≥ 3.11, `agentmesh-runtime` v2.0.2+

---

## 3. Quick Start: A 3-Step Saga with Compensation

A complete example — define a 3-step deployment saga, execute it, and
handle failure with automatic compensation:

```python
import asyncio
from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.saga.state_machine import SagaState, StepState


async def main():
    orchestrator = SagaOrchestrator()

    # 1. Create a saga bound to a session
    saga = orchestrator.create_saga(session_id="session-deploy-42")

    # 2. Add steps — each pairs a forward action with a compensation
    step_pr = orchestrator.add_step(
        saga_id=saga.saga_id,
        action_id="data.create_pr",
        agent_did="did:mesh:dev-agent",
        execute_api="/api/pr/create",
        undo_api="/api/pr/close",
        timeout_seconds=60,
        max_retries=2,
    )
    step_tests = orchestrator.add_step(
        saga_id=saga.saga_id,
        action_id="test.run_suite",
        agent_did="did:mesh:ci-agent",
        execute_api="/api/tests/run",
        undo_api="/api/tests/cancel",
        timeout_seconds=300,
    )
    step_deploy = orchestrator.add_step(
        saga_id=saga.saga_id,
        action_id="deploy.staging",
        agent_did="did:mesh:deploy-agent",
        execute_api="/api/deploy/staging",
        undo_api="/api/deploy/rollback",
        timeout_seconds=600,
    )

    # 3. Execute each step with an async callable
    async def create_pr():
        return {"pr_number": 142}

    async def run_tests():
        return {"passed": 247, "failed": 0}

    async def deploy_to_staging():
        raise RuntimeError("Staging cluster unreachable")

    steps_and_executors = [
        (step_pr, create_pr),
        (step_tests, run_tests),
        (step_deploy, deploy_to_staging),
    ]

    for step, executor in steps_and_executors:
        try:
            result = await orchestrator.execute_step(
                saga.saga_id, step.step_id, executor=executor,
            )
            print(f"  ✓ {step.action_id} committed: {result}")
        except Exception as e:
            print(f"  ✗ {step.action_id} failed: {e}")
            break

    # 4. Compensate all committed steps in reverse order
    async def compensator(step):
        print(f"  ↩ Compensating {step.action_id} via {step.undo_api}")
        return "compensated"

    failed = await orchestrator.compensate(saga.saga_id, compensator)
    print(f"Saga state: {saga.state}")
    # SagaState.COMPLETED (all compensations succeeded)


asyncio.run(main())
```

**Output:**

```
  ✓ data.create_pr committed: {'pr_number': 142}
  ✓ test.run_suite committed: {'passed': 247, 'failed': 0}
  ✗ deploy.staging failed: Staging cluster unreachable
  ↩ Compensating test.run_suite via /api/tests/cancel
  ↩ Compensating data.create_pr via /api/pr/close
Saga state: SagaState.COMPLETED
```

Compensation runs in **reverse order** — tests cancelled before PR closed.

---

## 4. SagaOrchestrator

The `SagaOrchestrator` is the core engine that manages saga lifecycles.

### 4.1 API Reference

```python
class SagaOrchestrator:
    DEFAULT_MAX_RETRIES = 2
    DEFAULT_RETRY_DELAY_SECONDS = 1.0

    def create_saga(self, session_id: str) -> Saga
    def add_step(self, saga_id, action_id, agent_did, execute_api,
                 undo_api=None, timeout_seconds=300, max_retries=0) -> SagaStep
    async def execute_step(self, saga_id, step_id, executor: Callable) -> Any
    async def compensate(self, saga_id, compensator: Callable) -> list[SagaStep]
    def get_saga(self, saga_id: str) -> Saga | None
    active_sagas: list[Saga]  # property
```

**`add_step` parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `action_id` | — | Action type (dot-notation: `model.`, `data.`, `deploy.`, etc.) |
| `agent_did` | — | Decentralized identifier of the executing agent |
| `execute_api` | — | Forward execution endpoint |
| `undo_api` | `None` | Compensation endpoint (if `None`, step can't be compensated) |
| `timeout_seconds` | `300` | Max wall-clock time for execution |
| `max_retries` | `0` | Number of retry attempts on failure |

### 4.2 Executing Steps

`execute_step` takes an async callable and runs it with timeout and retry:

```python
async def fetch_data():
    response = await http_client.get("https://api.example.com/data")
    return response.json()

result = await orchestrator.execute_step(
    saga.saga_id,
    step.step_id,
    executor=fetch_data,
)
# On success: step.state == StepState.COMMITTED
# On failure: step.state == StepState.FAILED, raises the exception
```

**Execution semantics:**

1. The step transitions `PENDING` → `EXECUTING`.
2. Calls `asyncio.wait_for(executor(), timeout=step.timeout_seconds)`.
3. **On success:** result stored in `step.execute_result`, step → `COMMITTED`.
4. **On failure:** retried up to `max_retries` times (1s delay between attempts).
   After all retries exhausted, error stored in `step.error`, step → `FAILED`,
   and the exception is re-raised.

### 4.3 Listing Active Sagas

```python
# Get all sagas that haven't reached a terminal state
active = orchestrator.active_sagas

# Look up a specific saga by ID
saga = orchestrator.get_saga("saga:a1b2c3d4-...")
if saga:
    print(f"State: {saga.state}, Steps: {len(saga.steps)}")
```

---

## 5. Saga & Step State Machines

Both sagas and steps follow strict state machines with validated transitions.
Invalid transitions raise `SagaStateError`.

### 5.1 Step States

```
  PENDING → EXECUTING → COMMITTED → COMPENSATING → COMPENSATED
                     ↘ FAILED                    ↘ COMPENSATION_FAILED
```

```python
from hypervisor.saga.state_machine import SagaStep, StepState, SagaStateError

step = SagaStep(
    step_id="s1",
    action_id="data.extract",
    agent_did="did:mesh:etl-agent",
    execute_api="/api/extract",
)

# Valid transitions
step.transition(StepState.EXECUTING)    # PENDING → EXECUTING ✓
assert step.started_at is not None      # timestamp set automatically

step.transition(StepState.COMMITTED)    # EXECUTING → COMMITTED ✓
assert step.completed_at is not None

# Invalid transition raises SagaStateError
try:
    step.transition(StepState.PENDING)  # COMMITTED → PENDING ✗
except SagaStateError as e:
    print(e)  # "Invalid step transition: committed → pending"
```

The seven step states and their meanings:

| State | Meaning |
|-------|---------|
| `PENDING` | Step is defined but not yet started |
| `EXECUTING` | Step is currently running |
| `COMMITTED` | Step completed successfully |
| `FAILED` | Step failed after exhausting retries |
| `COMPENSATING` | Compensation is in progress for this step |
| `COMPENSATED` | Compensation completed successfully |
| `COMPENSATION_FAILED` | Compensation itself failed — requires escalation |

### 5.2 Saga States

```python
from hypervisor.saga.state_machine import Saga, SagaState

saga = Saga(saga_id="saga:1", session_id="session:1")
assert saga.state == SagaState.RUNNING

# Saga transitions are also validated
saga.transition(SagaState.COMPENSATING)  # RUNNING → COMPENSATING ✓
saga.transition(SagaState.COMPLETED)     # COMPENSATING → COMPLETED ✓
assert saga.completed_at is not None
```

| State | Meaning | Transitions to |
|-------|---------|----------------|
| `RUNNING` | Steps are being executed | `COMPENSATING`, `COMPLETED`, `FAILED` |
| `COMPENSATING` | Compensation is running in reverse | `COMPLETED`, `ESCALATED` |
| `COMPLETED` | All steps committed or all compensations succeeded | — (terminal) |
| `FAILED` | Execution failed (before compensation) | — (terminal) |
| `ESCALATED` | Compensation itself failed; human intervention required | — (terminal) |

### 5.3 Serialization and Inspection

```python
# Serialize saga to a dictionary
saga_dict = saga.to_dict()
# {"saga_id": "saga:...", "session_id": "...", "state": "running", "steps": [...]}

# Inspect committed steps (execution order and reverse/compensation order)
for step in saga.committed_steps:
    print(f"{step.action_id}: {step.execute_result}")

for step in saga.committed_steps_reversed:
    print(f"Would compensate: {step.action_id}")
```

---

## 6. SagaDSLParser — Declarative Saga Definitions

Instead of building sagas imperatively with `add_step()`, you can define them
declaratively using a structured dictionary format. This is especially useful
for saga definitions stored in configuration files or databases.

### 6.1 Basic Usage

```python
from hypervisor.saga.dsl import SagaDSLParser, SagaDefinition

parser = SagaDSLParser()

definition = parser.parse({
    "name": "deploy-model",
    "session_id": "sess-deploy-42",
    "steps": [
        {
            "id": "validate",
            "action_id": "model.validate",
            "agent": "did:mesh:validator",
            "execute_api": "/api/validate",
            "undo_api": "/api/rollback",
        },
        {
            "id": "deploy",
            "action_id": "deploy.push",
            "agent": "did:mesh:deployer",
            "execute_api": "/api/deploy",
            "undo_api": "/api/deploy/rollback",
            "timeout": 600,
            "retries": 2,
        },
        {
            "id": "notify",
            "action_id": "notify.team",
            "agent": "did:mesh:notifier",
            "execute_api": "/api/notify",
            # No undo_api — notifications can't be unsent
        },
    ],
})

print(definition.name)           # "deploy-model"
print(definition.session_id)     # "sess-deploy-42"
print(definition.saga_id)        # "saga:<auto-generated>"
print(len(definition.steps))     # 3
print(definition.step_ids)       # ["validate", "deploy", "notify"]
```

### 6.2 Definition Schema

**Required top-level:** `name` (str), `session_id` (str), `steps` (non-empty list).
**Optional top-level:** `saga_id` (str, auto-generated), `metadata` (dict).

**Required per step:** `id` (str), `action_id` (str), `agent` (str).
**Optional per step:** `execute_api` (str), `undo_api` (str|None), `timeout` (int, default 300), `retries` (int, default 0), `checkpoint_goal` (str|None).

### 6.3 Converting to SagaSteps

A `SagaDefinition` can be converted into `SagaStep` objects for use with `SagaOrchestrator`:

```python
saga_steps = parser.to_saga_steps(definition)
for step in saga_steps:
    print(f"{step.step_id}: {step.execute_api} (timeout={step.timeout_seconds}s)")
```

### 6.4 Validation

`validate()` returns errors without raising — useful for pre-flight checks:

```python
errors = parser.validate({})
# ["Missing 'name'", "Missing 'session_id'", "Missing 'steps'"]

errors = parser.validate({
    "name": "valid", "session_id": "s1",
    "steps": [{"id": "s1", "action_id": "data.run", "agent": "did:mesh:a"}],
})
# []
```

`parse()` raises `SagaDSLError` for missing `name`, missing `session_id`,
empty/missing `steps`, or duplicate step IDs.

---

## 7. Schema Validation

For production use, enable JSON schema validation to catch definition
errors early — invalid timeouts, unknown action prefixes, circular
dependencies, and more.

### 7.1 SagaSchemaValidator

```python
from hypervisor.saga.schema import SagaSchemaValidator, SagaSchemaError

validator = SagaSchemaValidator()

# Returns a list of error strings (empty = valid)
errors = validator.validate({
    "name": "test-saga",
    "session_id": "sess-1",
    "steps": [
        {
            "id": "step-1",
            "action_id": "model.validate",
            "agent": "did:mesh:validator",
            "execute_api": "/api/validate",
            "undo_api": "/api/rollback",
            "timeout": 300,
            "retries": 0,
        },
    ],
})
assert errors == []
```

### 7.2 What Gets Validated

| Rule | Example |
|------|---------|
| **Action ID prefixes** | Must start with `model.`, `data.`, `deploy.`, `validate.`, `notify.`, `infra.`, `security.`, `monitor.`, `config.`, or `test.` |
| **Timeout range** | 1–86400 seconds |
| **Retry range** | 0–10 |
| **Compensation** | Steps without `undo_api` generate warnings |
| **Dependencies** | Unknown refs and circular dependencies are caught |
| **Duplicate IDs** | Duplicate step IDs are rejected |

```python
from hypervisor.saga.schema import VALID_ACTION_PREFIXES

# All recognized action prefixes
print(VALID_ACTION_PREFIXES)
# ("model.", "data.", "deploy.", "validate.", "notify.",
#  "infra.", "security.", "monitor.", "config.", "test.")
```

### 7.3 Strict Mode and Parser Integration

```python
# Fail-fast: throws SagaSchemaError with all errors
try:
    validator.validate_or_raise({})
except SagaSchemaError as e:
    print(e.errors)  # ["Missing 'name'", "Missing 'session_id'", ...]

# Enable schema validation in the parser
parser = SagaDSLParser(schema_validation=True)
try:
    parser.parse({"name": "", "session_id": "s", "steps": []})
except SagaSchemaError:
    print("Schema validation failed before parsing")
```

---

## 8. Compensating Transactions

Compensation is the core safety mechanism. When a step fails, the
orchestrator walks backward through committed steps, calling a compensator
for each.

### 8.1 Compensation Flow

```python
async def compensator(step: SagaStep) -> Any:
    """Called for each committed step in reverse order."""
    print(f"Undoing {step.action_id} via {step.undo_api}")
    return "compensated"

failed_steps = await orchestrator.compensate(saga.saga_id, compensator)
```

The flow:

1. Saga transitions to `COMPENSATING`.
2. Iterates `saga.committed_steps_reversed` (reverse chronological order).
3. Steps with `undo_api=None` are marked `COMPENSATION_FAILED` immediately.
4. Otherwise, the compensator is called. Success → `COMPENSATED`. Failure → `COMPENSATION_FAILED`.
5. All compensations succeeded → saga `COMPLETED`. Any failed → saga `ESCALATED`.
6. Returns list of steps whose compensation failed.

### 8.2 Steps Without Compensation

Steps with `undo_api=None` cannot be compensated. Place irreversible actions
(notifications, emails) as the **last** step so they're never compensated.

### 8.3 Escalation

When compensation itself fails, the saga enters `ESCALATED` — human
intervention is required:

```python
async def failing_compensator(step):
    raise RuntimeError("Cannot rollback")

failed = await orchestrator.compensate(saga.saga_id, failing_compensator)
assert saga.state == SagaState.ESCALATED
assert len(failed) > 0
assert failed[0].state == StepState.COMPENSATION_FAILED
```

> **Important:** An `ESCALATED` saga means inconsistent state. Wire up
> alerting for this scenario. See
> [Tutorial 13 — Observability & Tracing](./13-observability-and-tracing.md)
> for OpenTelemetry integration.

---

## 9. FanOutOrchestrator — Parallel Step Execution

Some saga steps are independent and can run in parallel — for example,
deploying to multiple regions or validating data with multiple agents.

### 9.1 Core Concepts

The `FanOutOrchestrator` groups saga steps into **branches** within a
**fan-out group** and executes them with a configurable success policy:

```
                    ┌────────────┐
                    │  Fan-Out   │
                    │   Group    │
                    └──┬────┬──┬─┘
                       │    │  │
              ┌────────▼┐ ┌▼──┴────┐ ┌────────┐
              │Branch 1 │ │Branch 2│ │Branch 3│
              │(step s1)│ │(step s2)│ │(step s3)│
              └─────────┘ └────────┘ └────────┘
                    │         │          │
                    ▼         ▼          ▼
              Check policy: ALL_MUST_SUCCEED?
```

### 9.2 Fan-Out Policies

```python
from hypervisor.saga.fan_out import FanOutPolicy

FanOutPolicy.ALL_MUST_SUCCEED       # Every branch must succeed
FanOutPolicy.MAJORITY_MUST_SUCCEED  # > 50% of branches must succeed
FanOutPolicy.ANY_MUST_SUCCEED       # At least one branch must succeed
```

### 9.3 Creating and Executing a Fan-Out Group

```python
from hypervisor.saga.fan_out import FanOutOrchestrator, FanOutPolicy
from hypervisor.saga.state_machine import SagaStep

fan_out = FanOutOrchestrator()

# Create a group within a saga
group = fan_out.create_group("saga:deploy-multi-region", FanOutPolicy.ALL_MUST_SUCCEED)

# Add branches — each wraps a SagaStep
steps = [
    SagaStep(step_id="us-east", action_id="deploy.region",
             agent_did="did:mesh:deployer", execute_api="/api/deploy/us-east"),
    SagaStep(step_id="eu-west", action_id="deploy.region",
             agent_did="did:mesh:deployer", execute_api="/api/deploy/eu-west"),
]
for step in steps:
    fan_out.add_branch(group.group_id, step)

# Define executors keyed by step_id
async def deploy_us():
    return {"region": "us-east-1", "status": "deployed"}

async def deploy_eu():
    return {"region": "eu-west-1", "status": "deployed"}

result = await fan_out.execute(group.group_id, executors={
    "us-east": deploy_us, "eu-west": deploy_eu,
})

print(result.resolved)           # True
print(result.policy_satisfied)   # True — all succeeded
print(result.success_count)      # 2
print(result.compensation_needed)  # []
```

### 9.4 Handling Partial Failures

When a branch fails, `compensation_needed` lists step IDs of branches that
succeeded and now need rollback:

```python
async def deploy_fails():
    raise RuntimeError("Region unavailable")

result = await fan_out.execute(group.group_id, executors={
    "us-east": deploy_us, "eu-west": deploy_fails,
})
print(result.policy_satisfied)     # False
print(result.compensation_needed)  # ["us-east"]
```

### 9.5 Managing Groups

```python
active = fan_out.active_groups            # Unresolved groups
group = fan_out.get_group("fanout:abc123") # Look up by ID

# FanOutGroup properties
group.success_count        # Branches that succeeded
group.failure_count        # Branches that failed
group.total_branches       # Total branches
group.check_policy()       # Re-evaluate success policy
```

---

## 10. CheckpointManager — Save & Restore Saga State

The `CheckpointManager` creates **semantic checkpoints** — snapshots that
record "this goal was achieved," enabling smarter replay where completed
steps can be skipped.

### 10.1 Saving and Querying Checkpoints

```python
from hypervisor.saga.checkpoint import CheckpointManager, SemanticCheckpoint

checkpoint_mgr = CheckpointManager()

# Save a checkpoint after a step achieves its goal
ckpt = checkpoint_mgr.save(
    saga_id="saga:pipeline-7",
    step_id="migrate-db",
    goal_description="Database schema migrated to v5",
    state_snapshot={"schema_version": 5, "tables_added": ["users_v2"]},
)
print(ckpt.checkpoint_id)  # "ckpt:<hash>"
print(ckpt.is_valid)       # True

# Check if a goal was achieved
achieved = checkpoint_mgr.is_achieved("saga:pipeline-7",
    "Database schema migrated to v5", "migrate-db")

# Get all checkpoints for a saga
for ckpt in checkpoint_mgr.get_saga_checkpoints("saga:pipeline-7"):
    print(f"  {ckpt.step_id}: {ckpt.goal_description}")
```

### 10.2 Invalidation and Replay

```python
# Invalidate when underlying data changes
checkpoint_mgr.invalidate("saga:pipeline-7", "migrate-db",
                          reason="Schema manually altered")

# Replay plan — returns only steps needing re-execution
replay = checkpoint_mgr.get_replay_plan("saga:pipeline-7",
    ["extract", "transform", "validate", "load"])
```

### 10.3 Goal Hashes

```python
h1 = SemanticCheckpoint.compute_goal_hash("Deploy to staging", "step-deploy")
h2 = SemanticCheckpoint.compute_goal_hash("Deploy to staging", "step-deploy")
assert h1 == h2  # Same goal + step → same hash
```

> **Note:** In the Public Preview, `is_achieved()` returns `False` by
> default and `get_replay_plan()` returns all steps unchanged. Checkpoints
> are stored but not used for skip-ahead logic. The Enterprise Edition
> includes full semantic checkpoint evaluation.

---

## 11. Error Handling

### 11.1 Exception Types

The saga system defines several exception types:

```python
from hypervisor.saga.state_machine import SagaStateError
from hypervisor.saga.orchestrator import SagaTimeoutError
from hypervisor.saga.dsl import SagaDSLError
from hypervisor.saga.schema import SagaSchemaError
```

| Exception | Raised when |
|-----------|-------------|
| `SagaStateError` | An invalid state transition is attempted |
| `SagaTimeoutError` | A step exceeds its `timeout_seconds` |
| `SagaDSLError` | A saga definition has structural problems (missing fields, duplicates) |
| `SagaSchemaError` | Schema validation fails (invalid values, bad prefixes, circular deps) |

### 11.2 Timeout Handling

Steps that exceed their `timeout_seconds` are failed automatically:

```python
step = orchestrator.add_step(
    saga_id=saga.saga_id,
    action_id="data.long_process",
    agent_did="did:mesh:processor",
    execute_api="/api/process",
    timeout_seconds=10,
)

async def slow_executor():
    await asyncio.sleep(30)  # Exceeds timeout
    return "done"

try:
    await orchestrator.execute_step(saga.saga_id, step.step_id, executor=slow_executor)
except asyncio.TimeoutError:
    print(f"Step state: {step.state}")  # StepState.FAILED
```

### 11.3 Retry Semantics

Steps with `max_retries > 0` are retried automatically with a 1-second
delay between attempts:

```python
attempt_count = 0

async def flaky_executor():
    nonlocal attempt_count
    attempt_count += 1
    if attempt_count < 3:
        raise ConnectionError("Temporarily unavailable")
    return "success on attempt 3"

step = orchestrator.add_step(
    saga_id=saga.saga_id,
    action_id="data.fetch",
    agent_did="did:mesh:fetcher",
    execute_api="/api/fetch",
    max_retries=2,  # 1 initial + 2 retries = 3 total attempts
)

result = await orchestrator.execute_step(
    saga.saga_id, step.step_id, executor=flaky_executor,
)
assert step.state == StepState.COMMITTED
assert step.retry_count == 2
```

### 11.4 Error Propagation Pattern

```python
async def run_saga_safely(orchestrator, saga, steps_and_executors, compensator):
    """Execute a saga with automatic compensation on failure."""
    for step, executor in steps_and_executors:
        try:
            await orchestrator.execute_step(
                saga.saga_id, step.step_id, executor=executor,
            )
        except Exception:
            failed_compensations = await orchestrator.compensate(
                saga.saga_id, compensator,
            )
            if saga.state == SagaState.ESCALATED:
                raise RuntimeError(
                    f"Saga ESCALATED: {len(failed_compensations)} "
                    "compensation(s) failed. Human intervention required."
                )
            return {"status": "rolled_back", "failed_at": step.action_id}

    return {"status": "committed", "steps": len(steps_and_executors)}
```

---

## 12. Integration with Execution Rings

Sagas work with the [Execution Ring Model](./06-execution-sandboxing.md)
to enforce privilege boundaries on each step. An agent can only execute a
saga step if its effective score grants access to the ring required by that
action.

```python
from hypervisor import ExecutionRing
from hypervisor.rings.classifier import ActionClassifier
from hypervisor.saga.orchestrator import SagaOrchestrator

classifier = ActionClassifier()
orchestrator = SagaOrchestrator()

saga = orchestrator.create_saga("session-governed-deploy")
step = orchestrator.add_step(
    saga_id=saga.saga_id,
    action_id="deploy.production",
    agent_did="did:mesh:deploy-bot",
    execute_api="/api/deploy/prod",
    undo_api="/api/deploy/rollback",
)

# Check ring requirements before execution
classification = classifier.classify_action_id("deploy.production")
agent_ring = ExecutionRing.from_eff_score(eff_score=0.72)

if classification.ring.value < agent_ring.value:
    print(f"Agent ring {agent_ring} insufficient for {classification.ring}")
    await orchestrator.compensate(saga.saga_id, compensator)
else:
    await orchestrator.execute_step(saga.saga_id, step.step_id, executor=deploy_fn)
```

For steps needing temporary privilege escalation, combine sagas with
`RingElevationManager` (see [Tutorial 06, §3.3](./06-execution-sandboxing.md#33-ring-elevation-privilege-escalation)).

---

## 13. Real-World Example: Multi-Agent Data Pipeline

Bringing together DSL, fan-out, checkpoints, and compensation:

```python
import asyncio
from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.saga.dsl import SagaDSLParser
from hypervisor.saga.fan_out import FanOutOrchestrator, FanOutPolicy
from hypervisor.saga.checkpoint import CheckpointManager

# ── 1. Define pipeline declaratively ─────────────────────────────

parser = SagaDSLParser(schema_validation=True)
definition = parser.parse({
    "name": "weekly-ml-pipeline",
    "session_id": "pipeline-2025-w03",
    "steps": [
        {"id": "extract-sales", "action_id": "data.extract",
         "agent": "did:mesh:extractor", "execute_api": "/api/extract/sales",
         "undo_api": "/api/extract/cleanup", "timeout": 120, "retries": 2},
        {"id": "extract-inventory", "action_id": "data.extract",
         "agent": "did:mesh:extractor", "execute_api": "/api/extract/inventory",
         "undo_api": "/api/extract/cleanup", "timeout": 120, "retries": 2},
        {"id": "transform", "action_id": "data.transform",
         "agent": "did:mesh:transformer", "execute_api": "/api/transform",
         "undo_api": "/api/transform/rollback", "timeout": 600},
        {"id": "validate", "action_id": "validate.quality",
         "agent": "did:mesh:validator", "execute_api": "/api/validate",
         "undo_api": "/api/validate/reset"},
        {"id": "load", "action_id": "data.load",
         "agent": "did:mesh:loader", "execute_api": "/api/load/warehouse",
         "undo_api": "/api/load/rollback", "timeout": 900},
        {"id": "notify", "action_id": "notify.team",
         "agent": "did:mesh:notifier", "execute_api": "/api/notify/slack"},
    ],
})

# ── 2. Create orchestrators and saga ─────────────────────────────

orchestrator = SagaOrchestrator()
fan_out = FanOutOrchestrator()
checkpoint_mgr = CheckpointManager()
saga = orchestrator.create_saga(session_id=definition.session_id)

saga_steps = parser.to_saga_steps(definition)
step_map = {}
for dsl_step in saga_steps:
    step = orchestrator.add_step(
        saga_id=saga.saga_id, action_id=dsl_step.action_id,
        agent_did=dsl_step.agent_did, execute_api=dsl_step.execute_api,
        undo_api=dsl_step.undo_api, timeout_seconds=dsl_step.timeout_seconds,
        max_retries=dsl_step.max_retries,
    )
    step_map[dsl_step.step_id] = step

# ── 3. Execute: fan-out extraction, then sequential steps ────────

async def run_pipeline():
    # Parallel extraction via fan-out
    group = fan_out.create_group(saga.saga_id, FanOutPolicy.ALL_MUST_SUCCEED)
    for key in ["extract-sales", "extract-inventory"]:
        fan_out.add_branch(group.group_id, step_map[key])

    async def extract_sales():
        return {"records": 15_420}
    async def extract_inventory():
        return {"records": 8_300}

    result = await fan_out.execute(group.group_id, executors={
        step_map["extract-sales"].step_id: extract_sales,
        step_map["extract-inventory"].step_id: extract_inventory,
    })
    if not result.policy_satisfied:
        await orchestrator.compensate(saga.saga_id, compensator)
        return

    checkpoint_mgr.save(saga.saga_id, "extract-phase",
                        "All sources extracted", {"total": 23_720})

    # Sequential: transform → validate → load → notify
    async def transform(): return {"records": 23_720}
    async def validate():  return {"score": 0.97}
    async def load():      return {"rows_inserted": 23_720}
    async def notify():    return {"sent": True}

    for name, fn in [("transform", transform), ("validate", validate),
                     ("load", load), ("notify", notify)]:
        try:
            r = await orchestrator.execute_step(
                saga.saga_id, step_map[name].step_id, executor=fn)
            print(f"  ✓ {name}: {r}")
        except Exception as e:
            print(f"  ✗ {name} failed: {e}")
            await orchestrator.compensate(saga.saga_id, compensator)
            return

    print(f"\n✅ Pipeline complete — saga state: {saga.state}")

async def compensator(step):
    print(f"  ↩ Compensating {step.action_id} via {step.undo_api}")
    return "compensated"

asyncio.run(run_pipeline())
```

---

## 14. Next Steps

You now have a solid understanding of saga orchestration in the Agent
Governance Toolkit. Here's where to go next:

| Topic | Tutorial |
|-------|----------|
| Privilege rings and sandboxing | [Tutorial 06 — Execution Sandboxing](./06-execution-sandboxing.md) |
| OpenTelemetry spans for saga events | [Tutorial 13 — Observability & Tracing](./13-observability-and-tracing.md) |
| Rogue agent detection and circuit breakers | [Tutorial 05 — Agent Reliability](./05-agent-reliability.md) |
| Trust scores and agent identity | [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md) |
| Policy-based governance | [Tutorial 01 — Policy Engine](./01-policy-engine.md) |

### Key Takeaways

1. **Every forward action needs a compensation** — design your APIs with
   undo endpoints from the start.
2. **Use the DSL for complex pipelines** — declarative definitions are
   easier to review, version-control, and share.
3. **Enable schema validation in production** — catch timeout, retry, and
   dependency errors before execution.
4. **Fan-out for independent steps** — parallel execution with policy-based
   success criteria.
5. **Checkpoints enable smart replay** — skip steps whose goals are already
   achieved when restarting a saga.
6. **Plan for ESCALATED state** — wire up alerting for sagas that can't
   be compensated automatically.

---

## Next Steps

- **Liability & Attribution:** [Tutorial 12 — Liability & Attribution](12-liability-and-attribution.md)
- **Observability:** [Tutorial 13 — Observability & Distributed Tracing](13-observability-and-tracing.md)
- **Execution Sandboxing:** [Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md)
