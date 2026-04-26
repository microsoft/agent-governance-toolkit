# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
SLO Alerting Example — Set up SLOs for an AI agent with error budgets.

Demonstrates defining SLIs (latency, accuracy, error rate), combining them
into an SLO with an error budget, and triggering alerts when the budget burns
too fast.

Run:
    pip install agent-sre
    python examples/slo_alerting.py
"""

import random

from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import (
    ResponseLatency,
    TaskSuccessRate,
    ToolCallAccuracy,
)
from agent_sre.slo.objectives import ExhaustionAction, SLOStatus

# ── 1. Register SLIs ───────────────────────────────────────────────────

latency = ResponseLatency(target_ms=3000.0, percentile=0.95, window="1h")
accuracy = ToolCallAccuracy(target=0.99, window="24h")
success = TaskSuccessRate(target=0.95, window="24h")

# ── 2. Create SLO with error budget ───────────────────────────────────

budget = ErrorBudget(
    total=0.05,  # 5% error budget (1 - 0.95 target)
    burn_rate_alert=2.0,  # Warn at 2× normal consumption
    burn_rate_critical=10.0,  # Critical at 10× normal consumption
    exhaustion_action=ExhaustionAction.FREEZE_DEPLOYMENTS,
)

slo = SLO(
    name="code-review-agent",
    description="Reliability targets for code-review agent",
    indicators=[latency, accuracy, success],
    error_budget=budget,
    agent_id="code-review-agent",
)

# ── 3. Simulate agent work ─────────────────────────────────────────────

print("SLO Alerting Example")
print("=" * 60)
print()

for i in range(200):
    # Simulate realistic agent outcomes
    task_ok = random.random() < 0.92  # 92% success (below 95% target)
    tool_ok = random.random() < 0.98  # 98% accuracy (below 99% target)
    latency_ms = random.gauss(2500, 800)

    success.record_task(task_ok)
    accuracy.record_call(tool_ok)
    latency.record_latency(max(100, latency_ms))

    # Every event counts against the error budget
    slo.record_event(good=task_ok and tool_ok)

# ── 4. Check error budget consumption ──────────────────────────────────

print("SLO Status")
print("-" * 40)
status = slo.evaluate()
print(f"  Name:              {slo.name}")
print(f"  Status:            {status.value}")
print(f"  Error Budget Left: {slo.error_budget.remaining_percent:.1f}%")
print(f"  Budget Exhausted:  {slo.error_budget.is_exhausted}")
print(f"  Burn Rate (1h):    {slo.error_budget.burn_rate(3600):.1f}×")
print()

# ── 5. Check indicators ───────────────────────────────────────────────

print("Indicators")
print("-" * 40)
for ind in slo.indicators:
    val = ind.current_value()
    comp = ind.compliance()
    if val is not None and comp is not None:
        ok = "✅" if comp >= ind.target else "❌"
        print(f"  {ok} {ind.name}: {val:.3f} (target: {ind.target}, compliance: {comp:.1%})")

print()

# ── 6. Trigger alerts based on budget ──────────────────────────────────

print("Alerts")
print("-" * 40)
firing = slo.error_budget.firing_alerts()
if firing:
    for alert in firing:
        print(f"  🔔 {alert.severity.upper()}: {alert.name} (threshold: {alert.rate:.1f}×)")
else:
    print("  No alerts firing")

if status == SLOStatus.EXHAUSTED:
    print()
    print(f"  🚨 Error budget exhausted — action: {budget.exhaustion_action.value}")
elif status in (SLOStatus.CRITICAL, SLOStatus.WARNING):
    print()
    print(f"  ⚠️  SLO at risk — consider slowing deployments")

print()
print("─" * 60)
print("Use SLOs to define 'reliable' and error budgets to know when to slow down.")
