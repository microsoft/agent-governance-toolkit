# Tutorial 11 Saga Orchestration

> **Package:** `agent-hypervisor` · **Time:** 20 minutes · **Prerequisites:** Python 3.11+

## What you will learn

- Create a saga with `SagaOrchestrator`
- Add ordered steps with execute and undo endpoints
- Run steps with timeout and retry handling
- Compensate committed steps in reverse order after a failure
- Combine saga execution with ring checks and observability

See also [Execution Sandboxing](./06-execution-sandboxing.md), [Observability and Tracing](./13-observability-and-tracing.md), and [Kill Switch and Rate Limiting](./14-kill-switch-and-rate-limiting.md).

## 1 Introduction

A saga is a multi-step workflow where each forward action can have a compensating action. If a later step fails, the orchestrator walks backward through the steps that already committed and calls their compensators.

```text
create PR -> run tests -> deploy
   undo        undo        undo

If deploy fails:
  compensate run tests
  compensate create PR
```

`SagaOrchestrator` is the implemented engine in Agent Hypervisor. It manages the saga state machine, step state machine, timeout handling, retry count, and reverse-order compensation.

## 2 Installation

```bash
pip install agent-governance-toolkit-core
```

For local development from this repository:

```bash
cd agent-governance-python/agent-hypervisor
pip install -e ".[dev]"
```

## 3 Quick start

```python
import asyncio

from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.saga.state_machine import SagaState, StepState


async def main():
    orchestrator = SagaOrchestrator()
    saga = orchestrator.create_saga(session_id="session-deploy-42")

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

    async def create_pr():
        return {"pr_number": 142}

    async def run_tests():
        return {"passed": 247, "failed": 0}

    async def deploy_to_staging():
        raise RuntimeError("staging cluster unreachable")

    steps_and_executors = [
        (step_pr, create_pr),
        (step_tests, run_tests),
        (step_deploy, deploy_to_staging),
    ]

    for step, executor in steps_and_executors:
        try:
            result = await orchestrator.execute_step(
                saga.saga_id,
                step.step_id,
                executor=executor,
            )
            print(f"committed {step.action_id}: {result}")
        except Exception as exc:
            print(f"failed {step.action_id}: {exc}")
            break

    async def compensator(step):
        print(f"compensating {step.action_id} via {step.undo_api}")
        return "compensated"

    failed_compensations = await orchestrator.compensate(saga.saga_id, compensator)
    print(f"saga state: {saga.state}")
    print(f"failed compensations: {len(failed_compensations)}")


asyncio.run(main())
```

## 4 SagaOrchestrator API

```python
class SagaOrchestrator:
    def create_saga(self, session_id: str) -> Saga
    def add_step(
        self,
        saga_id: str,
        action_id: str,
        agent_did: str,
        execute_api: str,
        undo_api: str | None = None,
        timeout_seconds: int = 300,
        max_retries: int = 0,
    ) -> SagaStep
    async def execute_step(self, saga_id: str, step_id: str, executor) -> object
    async def compensate(self, saga_id: str, compensator) -> list[SagaStep]
    def get_saga(self, saga_id: str) -> Saga | None
```

### Step parameters

| Parameter | Description |
|-----------|-------------|
| `action_id` | Stable action identifier, such as `data.extract` or `deploy.staging` |
| `agent_did` | DID of the agent running the step |
| `execute_api` | Endpoint or symbolic name for the forward action |
| `undo_api` | Endpoint or symbolic name for the compensating action |
| `timeout_seconds` | Maximum wall-clock time for the executor |
| `max_retries` | Retry attempts after the first failed attempt |

## 5 State machines

Step states:

```text
PENDING -> EXECUTING -> COMMITTED -> COMPENSATING -> COMPENSATED
                    \-> FAILED                 \-> COMPENSATION_FAILED
```

Saga states:

| State | Meaning |
|-------|---------|
| `RUNNING` | Steps are still being executed |
| `COMPENSATING` | The orchestrator is rolling back committed steps |
| `COMPLETED` | All forward steps committed or all compensations succeeded |
| `FAILED` | Execution failed before compensation completed |
| `ESCALATED` | At least one compensation failed and human action is required |

Invalid transitions raise `SagaStateError`.

## 6 Timeout and retry handling

`execute_step` wraps the executor with `asyncio.wait_for`. On failure, the step retries until `max_retries` is exhausted. After the final failure, the step moves to `FAILED` and the original exception is raised.

```python
attempt_count = 0

async def flaky_executor():
    global attempt_count
    attempt_count += 1
    if attempt_count < 3:
        raise ConnectionError("temporarily unavailable")
    return "success"

step = orchestrator.add_step(
    saga.saga_id,
    "data.fetch",
    "did:mesh:fetcher",
    execute_api="/api/fetch",
    undo_api="/api/fetch/undo",
    max_retries=2,
)

result = await orchestrator.execute_step(saga.saga_id, step.step_id, flaky_executor)
assert step.state == StepState.COMMITTED
```

## 7 Compensation pattern

Use compensation when any step fails. The orchestrator passes each committed step to your compensator in reverse commit order.

```python
async def run_saga_safely(orchestrator, saga, steps_and_executors, compensator):
    for step, executor in steps_and_executors:
        try:
            await orchestrator.execute_step(saga.saga_id, step.step_id, executor=executor)
        except Exception:
            failed = await orchestrator.compensate(saga.saga_id, compensator)
            if saga.state == SagaState.ESCALATED:
                raise RuntimeError(f"manual repair required for {len(failed)} step(s)")
            return {"status": "rolled_back", "failed_at": step.action_id}

    return {"status": "committed", "steps": len(steps_and_executors)}
```

## 8 Integration with execution rings

Before executing a step, classify the action and compare the required ring to the agent ring.

```python
from hypervisor import ExecutionRing, ReversibilityLevel
from hypervisor.models import ActionDescriptor
from hypervisor.rings.classifier import ActionClassifier

action = ActionDescriptor(
    action_id="deploy.production",
    name="Deploy to production",
    execute_api="/deploy/production",
    undo_api="/deploy/rollback",
    reversibility=ReversibilityLevel.PARTIAL,
)
classification = ActionClassifier().classify(action)
agent_ring = ExecutionRing.from_eff_score(0.72)

if classification.ring.value < agent_ring.value:
    await orchestrator.compensate(saga.saga_id, compensator)
else:
    await orchestrator.execute_step(saga.saga_id, step.step_id, executor=deploy_fn)
```

## 9 Observability

Saga events can be emitted through `HypervisorEventBus` and correlated with `CausalTraceId`. The package also includes a saga span exporter for OpenTelemetry integrations.

```python
from hypervisor.observability import CausalTraceId, EventType, HypervisorEvent, HypervisorEventBus

bus = HypervisorEventBus()
trace = CausalTraceId()

bus.emit(HypervisorEvent(
    event_type=EventType.SAGA_CREATED,
    session_id="session-deploy-42",
    causal_trace_id=trace.full_id,
))
```

## 10 Next steps

| Topic | Tutorial |
|-------|----------|
| Privilege rings and sandboxing | [Tutorial 06](./06-execution-sandboxing.md) |
| OpenTelemetry spans for saga events | [Tutorial 13](./13-observability-and-tracing.md) |
| Kill switch and rate limiting | [Tutorial 14](./14-kill-switch-and-rate-limiting.md) |
| Trust scores and identity | [Tutorial 02](./02-trust-and-identity.md) |
