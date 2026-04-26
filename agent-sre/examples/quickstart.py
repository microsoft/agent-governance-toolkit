# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent-SRE Quickstart — Monitor an AI agent in 30 lines.

Run:
    pip install agent-sre
    python examples/quickstart.py
"""

import random

from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate, CostPerTask, HallucinationRate
from agent_sre.slo.dashboard import SLODashboard
from agent_sre.cost.guard import CostGuard
from agent_sre.incidents.detector import IncidentDetector, Signal, SignalType

# ── 1. Define what "reliable" means for your agent ──────────────────────

success_rate = TaskSuccessRate(target=0.95, window="24h")
cost_per_task = CostPerTask(target_usd=0.50, window="24h")
hallucination = HallucinationRate(target=0.05, window="24h")

slo = SLO(
    name="my-assistant",
    description="Production assistant agent reliability targets",
    indicators=[success_rate, cost_per_task, hallucination],
    error_budget=ErrorBudget(total=0.05, burn_rate_critical=10.0),
)

# ── 2. Set cost guardrails ──────────────────────────────────────────────

guard = CostGuard(
    per_task_limit=2.00,
    per_agent_daily_limit=50.0,
    org_monthly_budget=1000.0,
)

# ── 3. Wire up incident detection ──────────────────────────────────────

detector = IncidentDetector(correlation_window_seconds=60)

# ── 4. Simulate agent work ─────────────────────────────────────────────

print("Agent-SRE Quickstart")
print("=" * 60)
print()

for i in range(100):
    # Simulate agent task outcomes
    succeeded = random.random() < 0.93  # 93% success (below 95% target!)
    cost = random.uniform(0.05, 0.80)
    hallucinated = random.random() < 0.08  # 8% hallucination (above 5% target!)

    # Record into SLIs
    success_rate.record_task(success=succeeded)
    cost_per_task.record_cost(cost_usd=cost)
    hallucination.record_evaluation(hallucinated=hallucinated)

    # Track cost
    allowed, reason = guard.check_task("my-assistant", estimated_cost=cost)
    if allowed:
        guard.record_cost("my-assistant", f"task-{i}", cost)

    # Record into error budget
    slo.record_event(good=succeeded and not hallucinated)

# ── 5. Check results ───────────────────────────────────────────────────

status = slo.evaluate()
print(f"SLO Status:          {status.value}")
print(f"Error Budget Left:   {slo.error_budget.remaining_percent:.1f}%")
print(f"Burn Rate (1h):      {slo.error_budget.burn_rate(3600):.1f}x")
print()

print("Indicators:")
for ind in slo.indicators:
    val = ind.current_value()
    comp = ind.compliance()
    label = "✅" if comp and comp >= ind.target else "❌"
    print(f"  {label} {ind.name}: {val:.3f} (target: {ind.target:.3f}, compliance: {comp:.1%})")

print()

# Cost summary
print(f"Cost Today:          ${guard.org_spent_month:.2f} / ${guard.org_monthly_budget:.2f}")
budget_info = guard.get_budget("my-assistant")
print(f"Agent Budget Left:   ${budget_info.remaining_today_usd:.2f} / ${budget_info.daily_limit_usd:.2f}")
print()

# Check for SLO breaches
if slo.error_budget.is_exhausted:
    signal = Signal(
        signal_type=SignalType.ERROR_BUDGET_EXHAUSTED,
        source="my-assistant",
        message="Error budget fully consumed — freeze deployments",
    )
    incident = detector.ingest_signal(signal)
    if incident:
        print(f"🚨 Incident Created: {incident.title}")
        print(f"   Severity: {incident.severity.value}")

for alert in slo.error_budget.firing_alerts():
    print(f"⚠️  Burn Rate Alert: {alert.name} burn rate = {alert.rate:.1f}x")

print()
print("─" * 60)
print("This is what Agent-SRE does: SLOs, cost budgets, and incidents")
print("for AI agents — not infrastructure.")
