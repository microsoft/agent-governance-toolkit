# Tutorial 11 Saga Orchestration

> **Package:** `agent-hypervisor` · **Time:** 30 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- Multi-step transactions with compensating actions
- Saga and step state machines with validated transitions
- Timeout and retry handling for individual steps
- Reverse-order compensation and rollback strategies
- Integrating saga steps with execution rings

---

**Multi-step agent transactions with compensating actions and reverse-order rollback.**

See also: [Execution Sandboxing (Tutorial 06)](./06-execution-sandboxing.md) | [Observability & Tracing (Tutorial 13)](./13-observability-and-tracing.md) | [Agent Runtime README](../../agent-governance-python/agent-runtime/README.md)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Quick Start: A 3-Step Saga with Compensation](#3-quick-start-a-3-step-saga-with-compensation)
4. [SagaOrchestrator](#4-sagaorchestrator)
5. [Saga & Step State Machines](#5-saga--step-state-machines)
6. [Compensating Transactions](#6-compensating-transactions)
7. [Error Handling](#7-error-handling)
8. [Integration with Execution Rings](#8-integration-with-execution-rings)
9. [Real-World Example: Multi-Agent Data Pipeline](#9-real-world-example-multi-agent-data-pipeline)
10. [Next Steps](#10-next-steps)

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

---

## 2. Installation

```bash
pip install agent-governance-toolkit-core
```

Import from either package:

```python
# From runtime (convenience re-exports)
from agent_runtime import SagaOrchestrator, SagaState, StepState

# Or directly from hypervisor
from hypervisor.saga.orchestrator import SagaOrchestrator, SagaTimeoutError
from hypervisor.saga.state_machine import Saga, SagaStep, SagaState, StepState, SagaStateError
```

**Requirements:** Python 3.11+

---

## 3. Quick Start: A 3-Step Saga with Compensation

A complete example that defines a 3-step deployment saga, executes it, and
handles failure with automatic compensation:

```python
import asyncio
from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.saga.state_machine import SagaState, StepState


async def main():
    orchestrator = SagaOrchestrator()

    # 1. Create a saga bound to a session
    saga = orchestrator.create_saga(session_id="session-deploy-42")

    # 2. Add steps, each pairing a forward action with a compensation
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

Compensation runs in **reverse order**, so tests are cancelled before the PR is closed.

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
| `action_id` | required | Action type (dot-notation: `model.`, `data.`, `deploy.`, etc.) |
| `agent_did` | required | Decentralized identifier of the executing agent |
| `execute_api` | required | Forward execution endpoint |
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
| `COMPENSATION_FAILED` | Compensation itself failed, requires escalation |

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
| `COMPLETED` | All steps committed or all compensations succeeded | terminal |
| `FAILED` | Execution failed (before compensation) | terminal |
| `ESCALATED` | Compensation itself failed; human intervention required | terminal |

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

## 6. Compensating Transactions

Compensation is the core safety mechanism. When a step fails, the
orchestrator walks backward through committed steps, calling a compensator
for each.

### 6.1 Compensation Flow

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

### 6.2 Steps Without Compensation

Steps with `undo_api=None` cannot be compensated. Place irreversible actions
(notifications, emails) as the **last** step so they're never compensated.

### 6.3 Escalation

When compensation itself fails, the saga enters `ESCALATED` and human
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
> [Tutorial 13 Observability & Tracing](./13-observability-and-tracing.md)
> for OpenTelemetry integration.

---

## 7. Error Handling

### 7.1 Exception Types

The saga system defines several exception types:

```python
from hypervisor.saga.state_machine import SagaStateError
from hypervisor.saga.orchestrator import SagaTimeoutError
```

| Exception | Raised when |
|-----------|-------------|
| `SagaStateError` | An invalid state transition is attempted |
| `SagaTimeoutError` | A step exceeds its `timeout_seconds` |

### 7.2 Timeout Handling

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
except SagaTimeoutError:
    print(f"Step state: {step.state}")  # StepState.FAILED
```

### 7.3 Retry Semantics

Steps with `max_retries > 0` are retried automatically with a 1-second
delay between attempts:

```python
attempt_count = 0

async def flaky_executor():
    global attempt_count
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

### 7.4 Error Propagation Pattern

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

## 8. Integration with Execution Rings

Sagas work with the [Execution Ring Model](./06-execution-sandboxing.md)
to enforce privilege boundaries on each step. An agent can only execute a
saga step if its effective score grants access to the ring required by that
action.

```python
from hypervisor import ExecutionRing, ReversibilityLevel
from hypervisor.models import ActionDescriptor
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

# Classify the action, then compare its required ring to the agent ring
action = ActionDescriptor(
    action_id="deploy.production",
    name="Deploy to production",
    execute_api="/api/deploy/prod",
    undo_api="/api/deploy/rollback",
    reversibility=ReversibilityLevel.PARTIAL,
)
classification = classifier.classify(action)
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

## 9. Real-World Example: Multi-Agent Data Pipeline

Bringing together ordered execution, timeouts, retries, and reverse-order
compensation in a single pipeline:

```python
import asyncio
from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.saga.state_machine import SagaState

# ── 1. Create the orchestrator and a saga for the pipeline ───────

orchestrator = SagaOrchestrator()
saga = orchestrator.create_saga(session_id="pipeline-2025-w03")

# ── 2. Add the pipeline steps in execution order ─────────────────

pipeline = [
    # action_id, agent_did, execute_api, undo_api, timeout, retries
    ("data.extract", "did:mesh:extractor", "/api/extract/sales",
     "/api/extract/cleanup", 120, 2),
    ("data.transform", "did:mesh:transformer", "/api/transform",
     "/api/transform/rollback", 600, 0),
    ("validate.quality", "did:mesh:validator", "/api/validate",
     "/api/validate/reset", 300, 0),
    ("data.load", "did:mesh:loader", "/api/load/warehouse",
     "/api/load/rollback", 900, 0),
    ("notify.team", "did:mesh:notifier", "/api/notify/slack",
     None, 60, 0),
]

steps = [
    orchestrator.add_step(
        saga_id=saga.saga_id,
        action_id=action_id,
        agent_did=agent_did,
        execute_api=execute_api,
        undo_api=undo_api,
        timeout_seconds=timeout,
        max_retries=retries,
    )
    for action_id, agent_did, execute_api, undo_api, timeout, retries in pipeline
]

# ── 3. Provide an async executor for each step ───────────────────

async def extract():   return {"records": 23_720}
async def transform(): return {"records": 23_720}
async def validate():  return {"score": 0.97}
async def load():      return {"rows_inserted": 23_720}
async def notify():    return {"sent": True}

executors = [extract, transform, validate, load, notify]

# ── 4. Compensator called for each committed step on rollback ────

async def compensator(step):
    print(f"  ↩ Compensating {step.action_id} via {step.undo_api}")
    return "compensated"

# ── 5. Run the pipeline, compensating on the first failure ───────

async def run_pipeline():
    for step, executor in zip(steps, executors):
        try:
            result = await orchestrator.execute_step(
                saga.saga_id, step.step_id, executor=executor,
            )
            print(f"  ✓ {step.action_id}: {result}")
        except Exception as e:
            print(f"  ✗ {step.action_id} failed: {e}")
            failed = await orchestrator.compensate(saga.saga_id, compensator)
            if saga.state == SagaState.ESCALATED:
                raise RuntimeError(
                    f"{len(failed)} compensation(s) failed; manual repair required"
                )
            return

    print(f"Pipeline complete, saga state: {saga.state}")

asyncio.run(run_pipeline())
```

---

## 10. Next Steps

You now have a solid understanding of saga orchestration in the Agent
Governance Toolkit. Here's where to go next:

| Topic | Tutorial |
|-------|----------|
| Privilege rings and sandboxing | [Tutorial 06 Execution Sandboxing](./06-execution-sandboxing.md) |
| OpenTelemetry spans for saga events | [Tutorial 13 Observability & Tracing](./13-observability-and-tracing.md) |
| Rogue agent detection and circuit breakers | [Tutorial 05 Agent Reliability](./05-agent-reliability.md) |
| Trust scores and agent identity | [Tutorial 02 Trust & Identity](./02-trust-and-identity.md) |
| Policy-based governance | [Tutorial 01 Policy Engine](./01-policy-engine.md) |

### Key Takeaways

1. **Every forward action needs a compensation.** Design your APIs with
   undo endpoints from the start.
2. **Steps and sagas follow validated state machines.** Invalid transitions
   raise `SagaStateError`.
3. **Use timeouts and retries per step.** `execute_step` enforces
   `timeout_seconds` and retries up to `max_retries`.
4. **Plan for ESCALATED state.** Wire up alerting for sagas that can't
   be compensated automatically.

---

## Next Steps

- **Observability:** [Tutorial 13 Observability and Distributed Tracing](13-observability-and-tracing.md)
- **Execution Sandboxing:** [Tutorial 06 Execution Sandboxing](06-execution-sandboxing.md)
