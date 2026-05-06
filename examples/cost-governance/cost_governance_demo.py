"""Cost Governance and Budget Enforcement Demo.

Demonstrates tiered budget enforcement with per-agent limits,
organization-wide caps, auto-throttle, and kill switches.

Usage:
    pip install agent-sre
    python examples/cost-governance/cost_governance_demo.py
"""

from agent_sre.cost import (
    CostGuard,
    CostAnomalyDetector,
)


def main():
    print("=" * 60)
    print("  Cost Governance Demo")
    print("=" * 60)

    # ---------------------------------------------------------------
    # 1. Budget Setup and Pre-Check
    # ---------------------------------------------------------------
    print("\n--- Budget Setup ---")
    guard = CostGuard(
        per_task_limit=2.00,
        per_agent_daily_limit=20.00,
        org_monthly_budget=100.00,
        auto_throttle=True,
        kill_switch_threshold=0.95,
    )
    print(f"  Per-task limit:    ${guard.per_task_limit:.2f}")
    print(f"  Daily agent limit: ${guard.per_agent_daily_limit:.2f}")
    print(f"  Org monthly:       ${guard.org_monthly_budget:.2f}")

    print("\n--- Pre-Task Budget Check ---")
    allowed, reason = guard.check_task("analyst-agent", estimated_cost=1.50)
    print(f"  $1.50 task: allowed={allowed} ({reason})")

    allowed, reason = guard.check_task("analyst-agent", estimated_cost=5.00)
    print(f"  $5.00 task: allowed={allowed} ({reason})")

    # ---------------------------------------------------------------
    # 2. Record Costs and Watch Alerts Escalate
    # ---------------------------------------------------------------
    print("\n--- Recording Costs (watch alerts escalate) ---")

    for i in range(12):
        task_id = f"task-{i + 1:03d}"
        alerts = guard.record_cost("analyst-agent", task_id, cost_usd=1.80)
        budget = guard.get_budget("analyst-agent")

        if alerts:
            for alert in alerts:
                action_str = f" [{alert.action.value}]" if alert.action.value != "alert" else ""
                print(f"  ${budget.spent_today_usd:6.2f} "
                      f"({budget.utilization_percent:5.1f}%) "
                      f"[{alert.severity.value.upper()}]{action_str} {alert.message}")
        elif i == 0:
            print(f"  ${budget.spent_today_usd:6.2f} "
                  f"({budget.utilization_percent:5.1f}%) OK")

    # Check if killed
    budget = guard.get_budget("analyst-agent")
    print(f"\n  Final: ${budget.spent_today_usd:.2f} spent, "
          f"throttled={budget.throttled}, killed={budget.killed}")

    allowed, reason = guard.check_task("analyst-agent", estimated_cost=0.01)
    print(f"  Next task: allowed={allowed} ({reason})")

    # ---------------------------------------------------------------
    # 3. Organization Budget
    # ---------------------------------------------------------------
    print("\n--- Organization Budget ---")
    org_guard = CostGuard(
        per_agent_daily_limit=50.00,
        org_monthly_budget=100.00,
        kill_switch_threshold=0.95,
    )

    for agent in ["agent-a", "agent-b"]:
        alerts = org_guard.record_cost(agent, "task-1", cost_usd=48.00)
        budget = org_guard.get_budget(agent)
        print(f"  {agent}: ${budget.spent_today_usd:.2f} spent")
        for alert in alerts:
            if "Org" in alert.message or "org" in alert.message:
                print(f"    [{alert.severity.value.upper()}] {alert.message}")

    # Check all agents after org kill
    for agent in ["agent-a", "agent-b", "agent-c"]:
        allowed, reason = org_guard.check_task(agent, estimated_cost=0.01)
        status = "ALLOWED" if allowed else "BLOCKED"
        print(f"  {agent} next task: {status}")

    # ---------------------------------------------------------------
    # 4. Anomaly Detection
    # ---------------------------------------------------------------
    print("\n--- Cost Anomaly Detection ---")
    detector = CostAnomalyDetector()

    # Feed normal cost history
    for i in range(20):
        detector.ingest(1.0 + (i % 3) * 0.2, agent_id="data-agent")

    # Check an anomalous cost
    result = detector.ingest(50.0, agent_id="data-agent")
    print(f"  Normal cost range: $1.00-$1.40")
    print(f"  Checked cost:      $50.00")
    if result:
        print(f"  Anomaly detected:  True")
        print(f"  Severity:          {result.severity.value}")
    else:
        print(f"  Anomaly detected:  False (within tolerance)")

    print(f"\n{'=' * 60}")
    print("  Demo complete!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
