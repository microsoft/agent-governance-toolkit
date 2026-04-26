# Tutorial: Saga Orchestration with Automatic Compensation

This tutorial demonstrates how the **agent-hypervisor** saga engine executes
multi-step transactions and automatically rolls back completed steps when a
later step fails.

## What you'll learn

1. Define a 5-step saga using `SagaOrchestrator`
2. Execute steps sequentially with mock operations
3. Simulate a failure mid-saga (payment step)
4. Watch automatic compensation roll back committed steps in reverse order
5. Inspect the saga timeline and step states

## Concepts

### Saga pattern

A **saga** is a sequence of steps where each step has an *action* and an
optional *compensation* (undo). If any step fails, all previously committed
steps are compensated in reverse order so the system returns to a consistent
state.

```
Forward execution ──►
  Step 1 ✓  →  Step 2 ✓  →  Step 3 ✓  →  Step 4 ✗ (fails)

◄── Compensation (reverse)
  Undo 3  ←  Undo 2  ←  Undo 1
```

### Key classes

| Class | Module | Role |
|---|---|---|
| `SagaOrchestrator` | `hypervisor.saga.orchestrator` | Creates sagas, executes steps, triggers compensation |
| `Saga` | `hypervisor.saga.state_machine` | Holds ordered steps and overall saga state |
| `SagaStep` | `hypervisor.saga.state_machine` | Individual step with state, result, and error tracking |
| `SagaState` | `hypervisor.saga.state_machine` | Saga lifecycle enum: `RUNNING → COMPENSATING → COMPLETED` |
| `StepState` | `hypervisor.saga.state_machine` | Step lifecycle enum: `PENDING → EXECUTING → COMMITTED → …` |

### State transitions

**Step states:**

```
PENDING → EXECUTING → COMMITTED → COMPENSATING → COMPENSATED
                   ↘ FAILED        ↘ COMPENSATION_FAILED
```

**Saga states:**

```
RUNNING → COMPENSATING → COMPLETED
      ↘ FAILED          ↘ ESCALATED (if compensation itself fails)
```

## The scenario

We model a travel booking saga with five steps:

| # | Step | Action | Compensation |
|---|------|--------|--------------|
| 1 | Book flight | Reserve a seat | Cancel flight reservation |
| 2 | Reserve hotel | Book a room | Cancel hotel reservation |
| 3 | Rent car | Reserve a vehicle | Cancel car rental |
| 4 | Charge payment | Process credit card | Refund payment |
| 5 | Send confirmation | Email the itinerary | *(none — idempotent)* |

Step 4 (payment) will **fail**, triggering automatic compensation of steps
3 → 2 → 1 in reverse order.

## Running the demo

```bash
# From the repository root
cd tutorials/saga-compensation
python demo.py
```

No external services are required — all operations are mocked with
`asyncio.sleep` delays.

## Expected output

```
══════════════════════════════════════════════════════════
  Saga Compensation Demo — Travel Booking
══════════════════════════════════════════════════════════

▶ Executing: book_flight ... ✓ committed
▶ Executing: reserve_hotel ... ✓ committed
▶ Executing: rent_car ... ✓ committed
▶ Executing: charge_payment ... ✗ FAILED (Payment declined: insufficient funds)

⚠ Step charge_payment failed — starting compensation...

◀ Compensating: rent_car ... ✓ compensated
◀ Compensating: reserve_hotel ... ✓ compensated
◀ Compensating: book_flight ... ✓ compensated

✓ Compensation complete — all committed steps rolled back.

── Saga Timeline ──────────────────────────────────────
  Step               State                 Error
  book_flight        compensated
  reserve_hotel      compensated
  rent_car           compensated
  charge_payment     failed                Payment declined: insufficient funds
  send_confirmation  pending
──────────────────────────────────────────────────────
  Saga state: completed
══════════════════════════════════════════════════════════
```

## How it works

### 1. Create an orchestrator and saga

```python
from hypervisor.saga.orchestrator import SagaOrchestrator

orch = SagaOrchestrator()
saga = orch.create_saga(session_id="tutorial-session")
```

### 2. Add steps with undo APIs

```python
step = orch.add_step(
    saga_id=saga.saga_id,
    action_id="book_flight",
    agent_did="did:agent:travel",
    execute_api="/flights/reserve",
    undo_api="/flights/cancel",      # compensation endpoint
)
```

### 3. Execute each step

```python
result = await orch.execute_step(
    saga_id=saga.saga_id,
    step_id=step.step_id,
    executor=book_flight_fn,         # async callable
)
```

### 4. On failure, compensate

```python
failed = await orch.compensate(
    saga_id=saga.saga_id,
    compensator=undo_step_fn,        # async callable receiving a SagaStep
)
```

The orchestrator iterates `saga.committed_steps_reversed` and calls the
compensator for each step that has an `undo_api`.

## Next steps

- Add retry logic by setting `max_retries` on critical steps
- Integrate real service calls instead of mocks
- Persist saga state with `saga.to_dict()` for crash recovery
- Explore the `SagaDSLParser` for declarative saga definitions
