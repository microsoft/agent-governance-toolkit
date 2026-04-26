# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chaos Testing Example — Verify agent resilience to failures.

Injects faults (tool timeouts, LLM degradation, trust failures)
and measures how gracefully the agent degrades.

Run:
    pip install agent-sre
    python examples/chaos_test.py
"""

from agent_sre.chaos.engine import ChaosExperiment, Fault, AbortCondition

# ── Define a chaos experiment ───────────────────────────────────────────

experiment = ChaosExperiment(
    name="tool-timeout-resilience",
    target_agent="payment-agent",
    description="Verify payment agent handles search tool timeouts gracefully",
    faults=[
        Fault.tool_timeout("web_search", delay_ms=30_000, rate=0.5),
        Fault.llm_latency("openai", p99_ms=10_000, rate=0.3),
    ],
    duration_seconds=300,
    abort_conditions=[
        AbortCondition(metric="error_rate", threshold=0.50, comparator="gte"),
    ],
    blast_radius=0.1,  # Only affect 10% of requests
)

print("Chaos Testing Example")
print("=" * 60)
print()

# ── Run the experiment ──────────────────────────────────────────────────

experiment.start()
print(f"Experiment: {experiment.name}")
print(f"Target:     {experiment.target_agent}")
print(f"Duration:   {experiment.duration_seconds}s")
print(f"Faults:     {len(experiment.faults)}")
print()

# Simulate injecting faults and observing results
print("Injecting faults...")
for fault in experiment.faults:
    experiment.inject_fault(fault, applied=True, details={"simulated": True})
    print(f"  💉 {fault.fault_type.value}: {fault.target} (rate={fault.rate:.0%})")

print()

# Simulate metrics during chaos
simulated_metrics = {
    "error_rate": 0.12,       # Elevated but manageable
    "success_rate": 0.88,
    "avg_latency_ms": 3500,   # Slower due to retries
    "cost_per_task": 0.55,    # Slightly higher cost from retries
}

print("Observed metrics under chaos:")
for metric, value in simulated_metrics.items():
    print(f"  {metric}: {value}")

# Check abort conditions
should_abort = experiment.check_abort(simulated_metrics)
if should_abort:
    experiment.abort(reason="Abort threshold exceeded")
    print("\n🛑 Experiment ABORTED — error rate too high")
else:
    print("\n✅ Agent is handling faults gracefully")

    # Calculate fault impact score
    resilience = experiment.calculate_resilience(
        baseline_success_rate=0.98,
        experiment_success_rate=0.88,
        recovery_time_ms=2500,
        cost_increase_percent=15.0,
    )

    experiment.complete(resilience=resilience)

    print(f"\nFault Impact Score: {resilience.overall:.0f}/100")
    print(f"  Fault Tolerance:    {resilience.fault_tolerance:.1%}")
    print(f"  Recovery Time:      {resilience.recovery_time_ms:.0f}ms")
    print(f"  Degradation:        {resilience.degradation_percent:.1f}%")
    print(f"  Cost Impact:        +{resilience.cost_impact_percent:.1f}%")

print()
print("─" * 60)
print("Chaos testing reveals how your agent fails — before users do.")
