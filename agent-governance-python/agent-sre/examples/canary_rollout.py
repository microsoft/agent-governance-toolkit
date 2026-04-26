# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Staged Rollout Example — Safely deploy a new agent version.

Compares agent v1 vs v2 decision quality using golden test cases,
with automatic rollback if the new version performs worse.

Run:
    pip install agent-sre
    python examples/canary_rollout.py
"""

import random

from agent_sre.delivery.rollout import (
    CanaryRollout,
    RollbackCondition,
    RolloutStep,
)

# ── Define rollout stages ───────────────────────────────────────────────

rollout = CanaryRollout(
    name="assistant-v2",
    steps=[
        RolloutStep(weight=0.05, duration_seconds=60, name="5% canary"),
        RolloutStep(weight=0.25, duration_seconds=120, name="25% ramp"),
        RolloutStep(weight=1.0, duration_seconds=0, name="full rollout"),
    ],
    rollback_conditions=[
        RollbackCondition(metric="error_rate", threshold=0.10, comparator="gte"),
        RollbackCondition(metric="hallucination_rate", threshold=0.08, comparator="gte"),
    ],
)

# ── Simulate golden test evaluation ────────────────────────────────────

def evaluate_agent_version(version: str, n_tasks: int = 50) -> dict[str, float]:
    """Simulate evaluating an agent version against golden test cases."""
    if version == "v1":
        return {
            "accuracy": 0.94,
            "error_rate": 0.06,
            "hallucination_rate": 0.04,
            "avg_latency_ms": 1200,
            "cost_per_task": 0.35,
        }
    else:
        # v2 is worse on hallucinations (simulate regression)
        return {
            "accuracy": 0.91,
            "error_rate": 0.09,
            "hallucination_rate": 0.12,  # Regression!
            "avg_latency_ms": 900,
            "cost_per_task": 0.28,
        }


print("Staged Rollout Example")
print("=" * 60)
print()

# ── Start rollout ──────────────────────────────────────────────────────

rollout.start()
print(f"Started rollout: {rollout.name}")
print(f"Status: {rollout.state.value}")
print()

# ── Step through canary stages ─────────────────────────────────────────

step_num = 0
while rollout.current_step is not None:
    step = rollout.current_step
    step_num += 1
    print(f"Stage {step_num}: {step.name} (traffic: {step.weight:.0%})")

    # Evaluate candidate
    metrics = evaluate_agent_version("v2")
    print(f"  Accuracy:         {metrics['accuracy']:.1%}")
    print(f"  Error Rate:       {metrics['error_rate']:.1%}")
    print(f"  Hallucination:    {metrics['hallucination_rate']:.1%}")
    print(f"  Latency:          {metrics['avg_latency_ms']:.0f}ms")
    print(f"  Cost/Task:        ${metrics['cost_per_task']:.2f}")

    # Check rollback conditions
    should_rollback = rollout.check_rollback(metrics)
    if should_rollback:
        rollout.rollback(reason="Canary metrics breached rollback thresholds")
        print()
        print(f"  🛑 ROLLBACK triggered!")
        print(f"     Reason: hallucination_rate {metrics['hallucination_rate']:.1%} >= 8% threshold")
        break

    # Advance to next stage
    advanced = rollout.advance()
    if not advanced:
        break
    print(f"  ✅ Metrics within bounds, advancing...")
    print()

print()
print(f"Final Status:   {rollout.state.value}")
print(f"Progress:       {rollout.progress_percent:.0f}%")
print()
print("─" * 60)

if rollout.state.value == "rolled_back":
    print("Agent v2 was automatically rolled back due to hallucination regression.")
    print("Users continue to receive agent v1 — zero impact.")
else:
    print("Agent v2 promoted to full traffic.")
