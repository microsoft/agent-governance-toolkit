# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Cost Guard Example — Catch runaway agent spending.

Demonstrates how CostGuard prevents agent cost explosions by setting
per-task, per-agent, and organization-wide budgets with automatic alerts.

Run:
    pip install agent-sre
    python examples/cost_guard.py
"""

from agent_sre.cost.guard import CostGuard

# ── Set up cost guardrails ──────────────────────────────────────────────

guard = CostGuard(
    per_task_limit=1.00,         # No single task should cost > $1
    per_agent_daily_limit=20.0,  # Each agent: max $20/day
    org_monthly_budget=500.0,    # Org-wide: $500/month
    alert_thresholds=[0.50, 0.75, 0.90],  # Alert at 50%, 75%, 90%
)

print("Cost Guard Example")
print("=" * 60)
print()

# ── Simulate normal agent work ──────────────────────────────────────────

agents = ["researcher", "writer", "reviewer"]

for i in range(30):
    agent = agents[i % len(agents)]
    cost = 0.25  # Normal cost: $0.25 per task

    allowed, reason = guard.check_task(agent, estimated_cost=cost)
    if allowed:
        alerts = guard.record_cost(agent, f"task-{i}", cost)
        for alert in alerts:
            print(f"  ⚠️  {alert.severity.value}: {alert.message}")

print(f"After 30 normal tasks:")
print(f"  Total spent: ${guard.org_spent_month:.2f}")
for agent in agents:
    budget = guard.get_budget(agent)
    print(f"  {agent}: ${budget.spent_today_usd:.2f} spent, ${budget.remaining_today_usd:.2f} remaining")
print()

# ── Simulate runaway tool loop ──────────────────────────────────────────

print("Simulating runaway tool loop (researcher calls expensive API)...")
print()

for i in range(50):
    cost = 0.80  # Expensive: $0.80 per call

    allowed, reason = guard.check_task("researcher", estimated_cost=cost)
    if not allowed:
        print(f"  🛑 Task {i} BLOCKED: {reason}")
        break

    alerts = guard.record_cost("researcher", f"loop-{i}", cost)
    for alert in alerts:
        print(f"  ⚠️  {alert.severity.value}: {alert.message}")

print()
print("Summary:")
print(f"  Org spent: ${guard.org_spent_month:.2f} / ${guard.org_monthly_budget:.2f}")
researcher = guard.get_budget("researcher")
print(f"  Researcher: ${researcher.spent_today_usd:.2f} spent (limit: ${researcher.daily_limit_usd:.2f})")
print()
print("─" * 60)
print("CostGuard stopped the runaway before it burned through the budget.")
