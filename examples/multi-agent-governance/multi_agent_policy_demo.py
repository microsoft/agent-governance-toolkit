"""Multi-Agent Collective Policy Demo.

Demonstrates how the MultiAgentPolicyEvaluator enforces collective
constraints across all agents in a mesh: rate limits, concurrent agent
caps, and alert-only monitoring.

Usage:
    pip install agentmesh-platform
    python examples/multi-agent-governance/multi_agent_policy_demo.py
"""

from agentmesh.governance.multi_agent_policy import (
    ActionRecord,
    AggregateFunction,
    CollectiveCondition,
    MultiAgentAction,
    MultiAgentPolicy,
    MultiAgentPolicyEvaluator,
)


def main():
    # ---------------------------------------------------------------
    # 1. Rate Limiting Across All Agents
    # ---------------------------------------------------------------
    print("=" * 60)
    print("  Multi-Agent Collective Policy Demo")
    print("=" * 60)

    evaluator = MultiAgentPolicyEvaluator()

    # Max 3 transfers per 60 seconds across ALL agents
    evaluator.add_policy(MultiAgentPolicy(
        name="rate-limit-transfers",
        condition=CollectiveCondition(
            aggregate=AggregateFunction.COUNT,
            filter_tool="transfer_funds",
            window_seconds=60.0,
            threshold=3.0,
        ),
        action=MultiAgentAction.DENY,
    ))

    print("\n--- Rate Limit: Max 3 Transfers/Minute ---")

    for i in range(4):
        agent = f"agent-{i + 1}"
        result = evaluator.evaluate(agent, "transfer", "transfer_funds")
        status = "ALLOWED" if result.allowed else "DENIED"
        violated = f" (violated: {result.violated_policies})" if result.violated_policies else ""
        print(f"  {agent} transfer: {status}{violated}")

        if result.allowed:
            evaluator.record_action(ActionRecord(
                agent_id=agent, action="transfer", tool_name="transfer_funds",
            ))

    # ---------------------------------------------------------------
    # 2. Concurrent Agent Cap
    # ---------------------------------------------------------------
    print("\n--- Concurrent Cap: Max 2 DB Writers ---")

    evaluator.add_policy(MultiAgentPolicy(
        name="max-db-writers",
        condition=CollectiveCondition(
            aggregate=AggregateFunction.DISTINCT_AGENTS,
            filter_action="database_write",
            window_seconds=30.0,
            threshold=2.0,
        ),
        action=MultiAgentAction.DENY,
    ))

    # Two agents write successfully
    for agent in ["writer-1", "writer-2"]:
        evaluator.record_action(ActionRecord(
            agent_id=agent, action="database_write", tool_name="db",
        ))
        print(f"  {agent}: recorded write")

    # Same agent writing again is fine (still 2 distinct)
    result = evaluator.evaluate("writer-1", "database_write", "db")
    print(f"  writer-1 again: {'ALLOWED' if result.allowed else 'DENIED'}")

    # Third agent is blocked
    result = evaluator.evaluate("writer-3", "database_write", "db")
    print(f"  writer-3: {'ALLOWED' if result.allowed else 'DENIED'} (3rd distinct agent)")

    # ---------------------------------------------------------------
    # 3. Alert Without Blocking
    # ---------------------------------------------------------------
    print("\n--- Alert-Only Monitoring ---")

    alert_evaluator = MultiAgentPolicyEvaluator()
    alert_evaluator.add_policy(MultiAgentPolicy(
        name="high-volume-alert",
        condition=CollectiveCondition(
            aggregate=AggregateFunction.COUNT,
            threshold=3.0,
            window_seconds=60.0,
        ),
        action=MultiAgentAction.ALERT,
    ))

    for i in range(4):
        alert_evaluator.record_action(ActionRecord(
            agent_id=f"a-{i}", action="process",
        ))

    result = alert_evaluator.evaluate("a-5", "process")
    print(f"  High volume: allowed={result.allowed}, alerts={result.violated_policies}")

    # ---------------------------------------------------------------
    # 4. Load from Config
    # ---------------------------------------------------------------
    print("\n--- Load from Config ---")

    config_evaluator = MultiAgentPolicyEvaluator()
    count = config_evaluator.load_policies_from_dicts([
        {
            "name": "global-transfer-limit",
            "condition": {"aggregate": "count", "filter_tool": "transfer_funds",
                          "window_seconds": 60, "threshold": 5},
            "action": "deny",
        },
        {
            "name": "email-volume-alert",
            "condition": {"aggregate": "count", "filter_tool": "send_email",
                          "window_seconds": 3600, "threshold": 100},
            "action": "alert",
        },
    ])
    print(f"  Loaded {count} policies from config")
    for p in config_evaluator.list_policies():
        print(f"    - {p.name}: {p.condition.aggregate.value} "
              f">= {p.condition.threshold} -> {p.action.value}")

    # ---------------------------------------------------------------
    # 5. Window Stats
    # ---------------------------------------------------------------
    print("\n--- Window Stats ---")
    stats = evaluator.get_window_stats(window_seconds=60.0)
    print(f"  Actions in last 60s: {stats['total_actions']}")
    print(f"  Unique agents:       {stats['unique_agents']}")

    print(f"\n{'=' * 60}")
    print("  Demo complete!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
