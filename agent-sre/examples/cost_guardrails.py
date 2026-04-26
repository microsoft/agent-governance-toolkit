# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Cost Guardrails Example — Prevent LLM API cost overruns.

Demonstrates setting per-task, per-agent, and org-wide budget limits,
tracking per-request costs, and automatic throttling when a budget is
exceeded.

Run:
    pip install agent-sre
    python examples/cost_guardrails.py
"""

import random

from agent_sre.cost.guard import CostGuard

# ── 1. Configure budget limits ─────────────────────────────────────────

guard = CostGuard(
    per_task_limit=1.50,         # Max $1.50 per single LLM call
    per_agent_daily_limit=25.0,  # Each agent capped at $25/day
    org_monthly_budget=500.0,    # Organization-wide: $500/month
    auto_throttle=True,          # Automatically throttle at 85% budget
    kill_switch_threshold=0.95,  # Hard-stop at 95% budget
    alert_thresholds=[0.50, 0.75, 0.90],
)

print("Cost Guardrails Example")
print("=" * 60)
print()

# ── 2. Track per-request costs ─────────────────────────────────────────

print("Phase 1: Normal operation")
print("-" * 40)

agents = ["summarizer", "code-gen", "qa-bot"]

for i in range(60):
    agent = agents[i % len(agents)]
    # Typical LLM costs: $0.01–$0.30 per request
    cost = random.uniform(0.05, 0.35)

    allowed, reason = guard.check_task(agent, estimated_cost=cost)
    if allowed:
        alerts = guard.record_cost(agent, f"req-{i}", cost)
        for alert in alerts:
            print(f"  ⚠️  {alert.severity.value}: {alert.message}")
    else:
        print(f"  🛑 {agent} req-{i} BLOCKED: {reason}")

print()
for agent in agents:
    b = guard.get_budget(agent)
    print(f"  {agent}: ${b.spent_today_usd:.2f} spent, "
          f"${b.remaining_today_usd:.2f} remaining, "
          f"{b.task_count_today} calls")

print()

# ── 3. Demonstrate automatic throttling ────────────────────────────────

print("Phase 2: Runaway loop — code-gen calls expensive model repeatedly")
print("-" * 40)

for i in range(100):
    # Expensive GPT-4 calls at ~$0.80 each
    cost = random.uniform(0.60, 1.00)

    allowed, reason = guard.check_task("code-gen", estimated_cost=cost)
    if not allowed:
        print(f"  🛑 Call {i} BLOCKED: {reason}")
        break

    alerts = guard.record_cost("code-gen", f"expensive-{i}", cost)
    for alert in alerts:
        print(f"  ⚠️  {alert.severity.value}: {alert.message}")

print()

# ── 4. Summary ─────────────────────────────────────────────────────────

print("Budget Summary")
print("-" * 40)
summary = guard.summary()
print(f"  Org spent:      ${summary['org_spent_month']:.2f} / ${guard.org_monthly_budget:.2f}")
print(f"  Total requests: {summary['total_records']}")
print(f"  Total alerts:   {summary['total_alerts']}")
print()

for agent_id, info in summary["agents"].items():
    status = "🔴 KILLED" if info["killed"] else "🟡 THROTTLED" if info["throttled"] else "🟢 OK"
    print(f"  {agent_id}: {status}  ${info['spent_today_usd']:.2f} "
          f"({info['utilization_percent']:.0f}% of daily limit)")

print()
print("─" * 60)
print("CostGuard auto-throttled the runaway agent before it blew the budget.")
