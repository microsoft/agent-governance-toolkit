"""Intent-Based Authorization Demo.

Demonstrates the full intent lifecycle: declare, approve, execute, verify.
Shows drift detection with soft_block and hard_block policies, plus
child intent scope narrowing for multi-agent orchestration.

Usage:
    pip install agent-os-kernel
    python examples/intent-auth/intent_auth_demo.py
"""

import asyncio

from agent_os.intent import (
    DriftPolicy,
    IntentAction,
    IntentManager,
    IntentScopeError,
)
from agent_os.stateless import MemoryBackend


async def main():
    backend = MemoryBackend()
    manager = IntentManager(backend=backend)

    # ---------------------------------------------------------------
    # 1. Declare, Approve, Execute, Verify
    # ---------------------------------------------------------------
    print("=" * 60)
    print("  Intent-Based Authorization Demo")
    print("=" * 60)

    print("\n--- Step 1: Declare Intent ---")
    intent = await manager.declare_intent(
        agent_id="payment-agent",
        planned_actions=[
            IntentAction(action="read_balance"),
            IntentAction(action="transfer_funds", params_schema={"max_amount": 1000}),
        ],
        drift_policy=DriftPolicy.SOFT_BLOCK,
        ttl_seconds=300,
    )
    print(f"  Intent ID:  {intent.intent_id}")
    print(f"  State:      {intent.state.value}")
    print(f"  Actions:    {intent.planned_action_names}")

    print("\n--- Step 2: Approve Intent ---")
    intent = await manager.approve_intent(intent.intent_id)
    print(f"  State:      {intent.state.value}")

    print("\n--- Step 3: Execute Actions ---")

    # Planned action
    check = await manager.check_action(
        intent.intent_id, "read_balance", {}, "payment-agent", "req-001"
    )
    status = "ALLOWED" if check.allowed else "BLOCKED"
    drift = " (planned)" if check.was_planned else " (DRIFT!)"
    print(f"  read_balance:   {status}{drift}")

    # Unplanned action (drift!)
    check = await manager.check_action(
        intent.intent_id, "delete_account", {}, "payment-agent", "req-002"
    )
    status = "ALLOWED" if check.allowed else "BLOCKED"
    drift = " (planned)" if check.was_planned else " (DRIFT!)"
    print(f"  delete_account: {status}{drift}")
    if check.drift_policy_applied:
        print(f"    policy:  {check.drift_policy_applied.value}")
        print(f"    penalty: -{check.trust_penalty} trust points")

    print("\n--- Step 4: Verify Intent ---")
    verification = await manager.verify_intent(intent.intent_id)
    print(f"  Final state:   {verification.state.value}")
    print(f"  Planned:       {verification.planned_actions}")
    print(f"  Executed:      {verification.executed_actions}")
    print(f"  Unplanned:     {verification.unplanned_actions}")
    print(f"  Missed:        {verification.missed_actions}")
    print(f"  Drift events:  {verification.total_drift_events}")
    print(f"  Trust penalty: {verification.total_trust_penalty}")

    # ---------------------------------------------------------------
    # 2. Hard Block Drift Policy
    # ---------------------------------------------------------------
    print("\n" + "=" * 60)
    print("  Hard Block Demo")
    print("=" * 60)

    strict = await manager.declare_intent(
        agent_id="compliance-agent",
        planned_actions=[IntentAction(action="generate_report")],
        drift_policy=DriftPolicy.HARD_BLOCK,
    )
    strict = await manager.approve_intent(strict.intent_id)

    check = await manager.check_action(
        strict.intent_id, "generate_report", {}, "compliance-agent", "req-010"
    )
    print(f"\n  generate_report: {'ALLOWED' if check.allowed else 'BLOCKED'}")

    check = await manager.check_action(
        strict.intent_id, "send_email", {}, "compliance-agent", "req-011"
    )
    print(f"  send_email:      {'ALLOWED' if check.allowed else 'BLOCKED'} (hard_block)")

    # ---------------------------------------------------------------
    # 3. Child Intent Scope Narrowing
    # ---------------------------------------------------------------
    print("\n" + "=" * 60)
    print("  Child Intent Scope Narrowing")
    print("=" * 60)

    parent = await manager.declare_intent(
        agent_id="orchestrator",
        planned_actions=[
            IntentAction(action="read_balance"),
            IntentAction(action="transfer_funds"),
            IntentAction(action="generate_report"),
        ],
    )
    parent = await manager.approve_intent(parent.intent_id)
    print(f"\n  Parent scope: {parent.planned_action_names}")

    # Valid child: subset of parent
    child = await manager.declare_intent(
        agent_id="report-agent",
        planned_actions=[IntentAction(action="generate_report")],
        parent_intent_id=parent.intent_id,
    )
    print(f"  Child scope:  {child.planned_action_names} (valid subset)")

    # Invalid child: exceeds parent scope
    try:
        await manager.declare_intent(
            agent_id="rogue-agent",
            planned_actions=[IntentAction(action="delete_everything")],
            parent_intent_id=parent.intent_id,
        )
    except IntentScopeError as e:
        print(f"  Scope violation: {e}")

    print(f"\n{'=' * 60}")
    print("  Demo complete!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    asyncio.run(main())
