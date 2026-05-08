# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Hardened tests for Multi-Agent Policy Evaluator.

Covers SUM/MAX aggregates, thread safety, throttle action,
edge cases with metadata, and boundary conditions.
"""

import threading
import time

import pytest

from agentmesh.governance.multi_agent_policy import (
    ActionRecord,
    AggregateFunction,
    CollectiveCondition,
    MultiAgentAction,
    MultiAgentPolicy,
    MultiAgentPolicyEvaluator,
)


# ---------------------------------------------------------------------------
# SUM Aggregate Tests
# ---------------------------------------------------------------------------


class TestSumAggregate:
    """SUM uses metadata['cost'] for aggregation."""

    def test_sum_under_threshold_allows(self):
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="cost-cap",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.SUM,
                threshold=100.0,
            ),
            action=MultiAgentAction.DENY,
        ))

        evaluator.record_action(ActionRecord(
            agent_id="a1", action="query", metadata={"cost": 30.0},
        ))
        evaluator.record_action(ActionRecord(
            agent_id="a2", action="query", metadata={"cost": 20.0},
        ))

        # 50 total + 1 proposed (count projection) should be under 100
        result = evaluator.evaluate("a3", "query")
        assert result.allowed

    def test_sum_at_threshold_denies(self):
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="cost-cap",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.SUM,
                threshold=100.0,
            ),
            action=MultiAgentAction.DENY,
        ))

        evaluator.record_action(ActionRecord(
            agent_id="a1", action="query", metadata={"cost": 60.0},
        ))
        evaluator.record_action(ActionRecord(
            agent_id="a2", action="query", metadata={"cost": 40.0},
        ))

        # 100 total: projected adds 1 new record with cost=0 default
        # SUM sees 100 from existing + 0 from projected = 100 >= 100
        result = evaluator.evaluate("a3", "query")
        assert not result.allowed

    def test_sum_with_no_cost_metadata_defaults_to_zero(self):
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="cost-cap",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.SUM,
                threshold=10.0,
            ),
            action=MultiAgentAction.DENY,
        ))

        # Record actions without cost metadata
        for i in range(20):
            evaluator.record_action(ActionRecord(
                agent_id=f"a{i}", action="query",
            ))

        # SUM of zeros is 0, under threshold
        result = evaluator.evaluate("a-new", "query")
        assert result.allowed


# ---------------------------------------------------------------------------
# MAX Aggregate Tests
# ---------------------------------------------------------------------------


class TestMaxAggregate:
    """MAX uses metadata['value'] for aggregation."""

    def test_max_under_threshold_allows(self):
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="max-value",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.MAX,
                threshold=100.0,
            ),
            action=MultiAgentAction.DENY,
        ))

        evaluator.record_action(ActionRecord(
            agent_id="a1", action="trade", metadata={"value": 50.0},
        ))

        result = evaluator.evaluate("a2", "trade")
        assert result.allowed

    def test_max_at_threshold_denies(self):
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="max-value",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.MAX,
                threshold=100.0,
            ),
            action=MultiAgentAction.DENY,
        ))

        evaluator.record_action(ActionRecord(
            agent_id="a1", action="trade", metadata={"value": 100.0},
        ))

        # MAX sees 100 from existing, projected record has value=0
        # MAX(100, 0) = 100 >= 100 -> deny
        result = evaluator.evaluate("a2", "trade")
        assert not result.allowed

    def test_max_empty_records_allows(self):
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="max-value",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.MAX,
                threshold=100.0,
            ),
            action=MultiAgentAction.DENY,
        ))

        # No records, proposed record has value=0
        result = evaluator.evaluate("a1", "trade")
        assert result.allowed


# ---------------------------------------------------------------------------
# Throttle Action Tests
# ---------------------------------------------------------------------------


class TestThrottleAction:
    def test_throttle_is_neither_deny_nor_alert(self):
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="throttle-policy",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                threshold=1,
            ),
            action=MultiAgentAction.THROTTLE,
        ))

        result = evaluator.evaluate("a1", "x")
        # THROTTLE is not DENY, so it should violate but not deny
        # (THROTTLE should behave like ALERT: violation recorded but allowed)
        assert "throttle-policy" in result.violated_policies


# ---------------------------------------------------------------------------
# Thread Safety Tests
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_record_and_evaluate(self):
        """Multiple threads recording and evaluating should not crash."""
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="rate-limit",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                threshold=1000,  # high threshold to avoid interference
            ),
            action=MultiAgentAction.DENY,
        ))

        errors: list[str] = []

        def record_actions(agent_id: str) -> None:
            try:
                for i in range(50):
                    evaluator.record_action(ActionRecord(
                        agent_id=agent_id, action="x",
                    ))
                    evaluator.evaluate(agent_id, "x")
            except Exception as e:
                errors.append(f"{agent_id}: {e}")

        threads = [
            threading.Thread(target=record_actions, args=(f"agent-{i}",))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Concurrent errors: {errors}"

    def test_concurrent_evaluate_consistency(self):
        """Evaluate returns consistent results under concurrent access."""
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="low-limit",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                threshold=5,
            ),
            action=MultiAgentAction.DENY,
        ))

        # Pre-fill 4 records (one below threshold)
        for i in range(4):
            evaluator.record_action(ActionRecord(agent_id=f"a{i}", action="x"))

        results: list[bool] = []

        def check(_: int) -> None:
            r = evaluator.evaluate("new-agent", "x")
            results.append(r.allowed)

        threads = [threading.Thread(target=check, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should see the same state (4 recorded + 1 proposed = 5 >= 5 -> deny)
        assert all(r is False for r in results)


# ---------------------------------------------------------------------------
# Filter Interaction Tests
# ---------------------------------------------------------------------------


class TestFilterInteractions:
    def test_filter_tool_and_filter_action_combined(self):
        """When both filter_tool and filter_action are set, both must match."""
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="strict-filter",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                filter_tool="transfer_funds",
                filter_action="transfer",
                threshold=2,
            ),
            action=MultiAgentAction.DENY,
        ))

        # Record action with matching tool but different action
        evaluator.record_action(ActionRecord(
            agent_id="a1", action="query", tool_name="transfer_funds",
        ))
        # Record action with matching action but different tool
        evaluator.record_action(ActionRecord(
            agent_id="a2", action="transfer", tool_name="other_tool",
        ))

        # Neither matches both filters, so should be allowed
        result = evaluator.evaluate("a3", "transfer", "transfer_funds")
        assert result.allowed

    def test_policy_with_no_filters_matches_everything(self):
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="catch-all",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                threshold=2,
            ),
            action=MultiAgentAction.DENY,
        ))

        evaluator.record_action(ActionRecord(agent_id="a1", action="anything"))

        result = evaluator.evaluate("a2", "something_else")
        assert not result.allowed  # 1 existing + 1 proposed = 2 >= 2

    def test_multiple_policies_independent_decisions(self):
        evaluator = MultiAgentPolicyEvaluator()

        # Policy that triggers
        evaluator.add_policy(MultiAgentPolicy(
            name="trigger",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                filter_tool="email",
                threshold=1,
            ),
            action=MultiAgentAction.DENY,
        ))

        # Policy that doesn't trigger
        evaluator.add_policy(MultiAgentPolicy(
            name="no-trigger",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                filter_tool="database",
                threshold=1,
            ),
            action=MultiAgentAction.DENY,
        ))

        result = evaluator.evaluate("a1", "send", "email")
        assert not result.allowed
        assert "trigger" in result.violated_policies
        assert "no-trigger" not in result.violated_policies


# ---------------------------------------------------------------------------
# Decision Serialization
# ---------------------------------------------------------------------------


class TestResultSerialization:
    def test_allowed_result_to_dict(self):
        evaluator = MultiAgentPolicyEvaluator()
        result = evaluator.evaluate("a1", "x")
        d = result.to_dict()
        assert d["allowed"] is True
        assert d["decisions"] == []

    def test_denied_result_contains_policy_details(self):
        evaluator = MultiAgentPolicyEvaluator()
        evaluator.add_policy(MultiAgentPolicy(
            name="strict",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                threshold=1,
            ),
            action=MultiAgentAction.DENY,
        ))

        result = evaluator.evaluate("a1", "x")
        d = result.to_dict()
        assert d["allowed"] is False
        assert len(d["decisions"]) == 1
        decision = d["decisions"][0]
        assert decision["policy_name"] == "strict"
        assert "current_value" in decision
