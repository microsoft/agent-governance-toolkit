#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Saga Compensation Demo — Travel Booking

Demonstrates the agent-hypervisor saga engine executing a 5-step travel
booking saga, simulating a payment failure at step 4, and automatically
compensating (rolling back) steps 3, 2, 1 in reverse order.

Run:
    python demo.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Allow running from the tutorials/saga-compensation directory without
# installing the package by adding the repo src/ to sys.path.
_repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_repo_root / "src"))

from hypervisor.saga.orchestrator import SagaOrchestrator  # noqa: E402
from hypervisor.saga.state_machine import SagaStep, StepState  # noqa: E402

# ── Mock operations ──────────────────────────────────────────────────────────
# Each "execute" function simulates a service call. The payment step is
# configured to always fail so we can observe compensation.

DELAY = 0.15  # seconds — artificial latency for realism


async def book_flight() -> dict:
    await asyncio.sleep(DELAY)
    return {"confirmation": "FL-1024", "route": "SFO → JFK"}


async def cancel_flight(step: SagaStep) -> dict:
    await asyncio.sleep(DELAY)
    return {"cancelled": step.execute_result}


async def reserve_hotel() -> dict:
    await asyncio.sleep(DELAY)
    return {"reservation": "HT-2048", "hotel": "Grand Central"}


async def cancel_hotel(step: SagaStep) -> dict:
    await asyncio.sleep(DELAY)
    return {"cancelled": step.execute_result}


async def rent_car() -> dict:
    await asyncio.sleep(DELAY)
    return {"rental": "CR-4096", "vehicle": "Sedan"}


async def cancel_car(step: SagaStep) -> dict:
    await asyncio.sleep(DELAY)
    return {"cancelled": step.execute_result}


async def charge_payment() -> dict:
    """Always fails to demonstrate compensation."""
    await asyncio.sleep(DELAY)
    raise RuntimeError("Payment declined: insufficient funds")


async def refund_payment(step: SagaStep) -> dict:
    await asyncio.sleep(DELAY)
    return {"refunded": True}


async def send_confirmation() -> dict:
    await asyncio.sleep(DELAY)
    return {"email_sent": True}


# ── Step definitions ─────────────────────────────────────────────────────────

STEPS = [
    {
        "action_id": "book_flight",
        "agent_did": "did:agent:travel",
        "execute_api": "/flights/reserve",
        "undo_api": "/flights/cancel",
        "executor": book_flight,
        "compensator": cancel_flight,
    },
    {
        "action_id": "reserve_hotel",
        "agent_did": "did:agent:travel",
        "execute_api": "/hotels/reserve",
        "undo_api": "/hotels/cancel",
        "executor": reserve_hotel,
        "compensator": cancel_hotel,
    },
    {
        "action_id": "rent_car",
        "agent_did": "did:agent:travel",
        "execute_api": "/cars/reserve",
        "undo_api": "/cars/cancel",
        "executor": rent_car,
        "compensator": cancel_car,
    },
    {
        "action_id": "charge_payment",
        "agent_did": "did:agent:billing",
        "execute_api": "/payments/charge",
        "undo_api": "/payments/refund",
        "executor": charge_payment,
        "compensator": refund_payment,
    },
    {
        "action_id": "send_confirmation",
        "agent_did": "did:agent:notifications",
        "execute_api": "/notifications/send",
        "undo_api": None,  # idempotent — no compensation needed
        "executor": send_confirmation,
        "compensator": None,
    },
]

# ── Compensator dispatch ─────────────────────────────────────────────────────
# The orchestrator's compensate() method expects a single async callable that
# receives a SagaStep.  We build a lookup so each step calls its own undo fn.

_compensators: dict[str, object] = {}


def _build_compensator_dispatch():
    """Build action_id → compensator mapping from STEPS."""
    for defn in STEPS:
        if defn["compensator"] is not None:
            _compensators[defn["action_id"]] = defn["compensator"]


async def dispatch_compensator(step: SagaStep):
    """Route compensation to the correct undo function by action_id."""
    fn = _compensators.get(step.action_id)
    if fn is None:
        raise RuntimeError(f"No compensator for {step.action_id}")
    return await fn(step)


# ── Display helpers ──────────────────────────────────────────────────────────

SEPARATOR = "═" * 58


def print_header():
    print(f"\n{SEPARATOR}")
    print("  Saga Compensation Demo — Travel Booking")
    print(f"{SEPARATOR}\n")


def print_timeline(saga):
    """Print the final saga timeline showing each step's state."""
    print(f"\n── Saga Timeline {'─' * 40}")
    print(f"  {'Step':<20} {'State':<22} {'Error'}")
    for step in saga.steps:
        error = step.error or ""
        print(f"  {step.action_id:<20} {step.state.value:<22} {error}")
    print("─" * 58)
    print(f"  Saga state: {saga.state.value}")
    print(SEPARATOR)


# ── Main demo ────────────────────────────────────────────────────────────────


async def run_demo():
    _build_compensator_dispatch()
    print_header()

    # 1. Create orchestrator and saga
    orch = SagaOrchestrator()
    saga = orch.create_saga(session_id="tutorial-travel-booking")

    # 2. Register all steps
    registered = []
    for defn in STEPS:
        step = orch.add_step(
            saga_id=saga.saga_id,
            action_id=defn["action_id"],
            agent_did=defn["agent_did"],
            execute_api=defn["execute_api"],
            undo_api=defn["undo_api"],
        )
        registered.append((step, defn["executor"]))

    # 3. Execute steps sequentially; stop on first failure
    failed_step_action = None
    for step, executor in registered:
        print(f"▶ Executing: {step.action_id} ... ", end="", flush=True)
        try:
            await orch.execute_step(saga.saga_id, step.step_id, executor)
            print("✓ committed")
        except Exception as exc:
            print(f"✗ FAILED ({exc})")
            failed_step_action = step.action_id
            break

    # 4. If a step failed, compensate committed steps in reverse
    if failed_step_action:
        print(f"\n⚠ Step {failed_step_action} failed — starting compensation...\n")

        failed_compensations = await orch.compensate(
            saga_id=saga.saga_id,
            compensator=dispatch_compensator,
        )

        # Report per-step compensation results (reverse order matches execution)
        for step in reversed(saga.steps):
            if step.state == StepState.COMPENSATED:
                print(f"◀ Compensating: {step.action_id} ... ✓ compensated")
            elif step.state == StepState.COMPENSATION_FAILED:
                print(
                    f"◀ Compensating: {step.action_id} ... "
                    f"✗ FAILED ({step.error})"
                )

        if not failed_compensations:
            print("\n✓ Compensation complete — all committed steps rolled back.")
        else:
            print(
                f"\n⚠ {len(failed_compensations)} step(s) failed compensation "
                "— manual intervention required."
            )
    else:
        # All steps succeeded — mark saga complete
        saga.transition(
            __import__(
                "hypervisor.saga.state_machine", fromlist=["SagaState"]
            ).SagaState.COMPLETED
        )
        print("\n✓ All steps completed successfully.")

    # 5. Print the timeline
    print_timeline(saga)


def main():
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
