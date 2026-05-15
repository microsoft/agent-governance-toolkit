# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Multi-Agent Policy Evaluator."""

import time

import pytest

from agentmesh.governance.multi_agent_policy import (
    ActionRecord,
    AggregateFunction,
    CollectiveCondition,
    MultiAgentAction,
    MultiAgentPolicy,
    MultiAgentPolicyEvaluator,
    MultiAgentPolicyScope,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def evaluator():
    return MultiAgentPolicyEvaluator()


@pytest.fixture
def rate_limit_policy():
    return MultiAgentPolicy(
        name="rate-limit-transfers",
        condition=CollectiveCondition(
            aggregate=AggregateFunction.COUNT,
            filter_tool="transfer_funds",
            window_seconds=60.0,
            threshold=3.0,
        ),
        action=MultiAgentAction.DENY,
    )


@pytest.fixture
def distinct_agents_policy():
    return MultiAgentPolicy(
        name="max-concurrent-agents",
        condition=CollectiveCondition(
            aggregate=AggregateFunction.DISTINCT_AGENTS,
            filter_action="database_write",
            window_seconds=30.0,
            threshold=2.0,
        ),
        action=MultiAgentAction.DENY,
    )


# ---------------------------------------------------------------------------
# Policy Model Tests
# ---------------------------------------------------------------------------

class TestMultiAgentPolicy:
    def test_from_dict(self):
        d = {
            "name": "test-policy",
            "scope": "multi-agent",
            "condition": {
                "aggregate": "count",
                "filter_tool": "send_email",
                "window_seconds": 120,
                "threshold": 5,
            },
            "action": "deny",
        }
        policy = MultiAgentPolicy.from_dict(d)
        assert policy.name == "test-policy"
        assert policy.condition.aggregate == AggregateFunction.COUNT
        assert policy.condition.filter_tool == "send_email"
        assert policy.condition.window_seconds == 120.0
        assert policy.condition.threshold == 5.0
        assert policy.action == MultiAgentAction.DENY

    def test_to_dict_roundtrip(self):
        policy = MultiAgentPolicy(
            name="roundtrip",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.DISTINCT_AGENTS,
                filter_action="write",
                threshold=10,
            ),
            action=MultiAgentAction.ALERT,
        )
        d = policy.to_dict()
        restored = MultiAgentPolicy.from_dict(d)
        assert restored.name == policy.name
        assert restored.condition.aggregate == policy.condition.aggregate
        assert restored.action == policy.action

    def test_from_dict_with_window_shorthand(self):
        """Support 'window' as alias for 'window_seconds'."""
        d = {
            "name": "shorthand",
            "condition": {"aggregate": "count", "window": 90, "threshold": 5},
        }
        policy = MultiAgentPolicy.from_dict(d)
        assert policy.condition.window_seconds == 90.0


# ---------------------------------------------------------------------------
# Evaluator Basic Tests
# ---------------------------------------------------------------------------

class TestEvaluatorBasics:
    def test_add_and_list_policies(self, evaluator, rate_limit_policy):
        evaluator.add_policy(rate_limit_policy)
        assert evaluator.policy_count == 1
        assert evaluator.list_policies()[0].name == "rate-limit-transfers"

    def test_remove_policy(self, evaluator, rate_limit_policy):
        evaluator.add_policy(rate_limit_policy)
        assert evaluator.remove_policy("rate-limit-transfers")
        assert evaluator.policy_count == 0

    def test_remove_nonexistent(self, evaluator):
        assert not evaluator.remove_policy("nope")

    def test_load_policies_from_dicts(self, evaluator):
        policies = [
            {"name": "p1", "condition": {"aggregate": "count", "threshold": 5}},
            {"name": "p2", "condition": {"aggregate": "count", "threshold": 10}},
        ]
        count = evaluator.load_policies_from_dicts(policies)
        assert count == 2
        assert evaluator.policy_count == 2

    def test_no_policies_allows_everything(self, evaluator):
        result = evaluator.evaluate("agent-1", "any_action")
        assert result.allowed
        assert len(result.decisions) == 0


# ---------------------------------------------------------------------------
# Collective Constraint Tests
# ---------------------------------------------------------------------------

class TestCollectiveConstraints:
    def test_count_under_threshold_allows(self, evaluator, rate_limit_policy):
        evaluator.add_policy(rate_limit_policy)

        # Record 1 transfer
        evaluator.record_action(ActionRecord(
            agent_id="agent-1", action="transfer", tool_name="transfer_funds",
        ))

        result = evaluator.evaluate("agent-2", "transfer", "transfer_funds")
        assert result.allowed

    def test_count_at_threshold_denies(self, evaluator, rate_limit_policy):
        evaluator.add_policy(rate_limit_policy)

        # Record 2 transfers, the proposed 3rd would hit threshold of 3
        evaluator.record_action(ActionRecord(
            agent_id="agent-1", action="transfer", tool_name="transfer_funds",
        ))
        evaluator.record_action(ActionRecord(
            agent_id="agent-2", action="transfer", tool_name="transfer_funds",
        ))

        result = evaluator.evaluate("agent-3", "transfer", "transfer_funds")
        assert not result.allowed
        assert "rate-limit-transfers" in result.violated_policies

    def test_different_tool_not_counted(self, evaluator, rate_limit_policy):
        evaluator.add_policy(rate_limit_policy)

        # Record 5 actions with different tool
        for i in range(5):
            evaluator.record_action(ActionRecord(
                agent_id=f"agent-{i}", action="query", tool_name="database_read",
            ))

        result = evaluator.evaluate("agent-6", "transfer", "transfer_funds")
        assert result.allowed

    def test_distinct_agents_under_threshold(self, evaluator, distinct_agents_policy):
        evaluator.add_policy(distinct_agents_policy)

        # Same agent writing multiple times
        evaluator.record_action(ActionRecord(
            agent_id="agent-1", action="database_write", tool_name="db",
        ))

        # New agent would make 2 distinct agents, which hits threshold of 2
        result = evaluator.evaluate("agent-2", "database_write", "db")
        assert not result.allowed

    def test_distinct_agents_same_agent_ok(self, evaluator, distinct_agents_policy):
        evaluator.add_policy(distinct_agents_policy)

        evaluator.record_action(ActionRecord(
            agent_id="agent-1", action="database_write", tool_name="db",
        ))

        # Same agent again, still 1 distinct agent
        result = evaluator.evaluate("agent-1", "database_write", "db")
        assert result.allowed

    def test_disabled_policy_skipped(self, evaluator):
        policy = MultiAgentPolicy(
            name="disabled",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                threshold=0,  # Would always trigger
            ),
            enabled=False,
        )
        evaluator.add_policy(policy)
        result = evaluator.evaluate("agent-1", "anything")
        assert result.allowed

    def test_alert_policy_does_not_block(self, evaluator):
        policy = MultiAgentPolicy(
            name="alert-only",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                threshold=1,
            ),
            action=MultiAgentAction.ALERT,
        )
        evaluator.add_policy(policy)

        evaluator.record_action(ActionRecord(
            agent_id="agent-1", action="something",
        ))

        result = evaluator.evaluate("agent-2", "something")
        # Alert policy violates but does not block
        assert result.allowed
        assert "alert-only" in result.violated_policies

    def test_multiple_policies_all_must_pass(self, evaluator):
        evaluator.add_policy(MultiAgentPolicy(
            name="p1",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                filter_tool="tool_a",
                threshold=100,  # Very high, won't trigger
            ),
            action=MultiAgentAction.DENY,
        ))
        evaluator.add_policy(MultiAgentPolicy(
            name="p2",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                filter_tool="tool_a",
                threshold=1,  # Will trigger immediately
            ),
            action=MultiAgentAction.DENY,
        ))

        result = evaluator.evaluate("agent-1", "x", "tool_a")
        assert not result.allowed
        assert "p2" in result.violated_policies
        assert "p1" not in result.violated_policies


# ---------------------------------------------------------------------------
# Window Tests
# ---------------------------------------------------------------------------

class TestWindowBehavior:
    def test_old_records_outside_window(self, evaluator):
        policy = MultiAgentPolicy(
            name="short-window",
            condition=CollectiveCondition(
                aggregate=AggregateFunction.COUNT,
                threshold=2,
                window_seconds=0.1,  # 100ms window
            ),
            action=MultiAgentAction.DENY,
        )
        evaluator.add_policy(policy)

        # Record an action
        evaluator.record_action(ActionRecord(
            agent_id="agent-1", action="x",
        ))

        # Wait for window to expire
        time.sleep(0.15)

        # Old record should be outside window
        result = evaluator.evaluate("agent-2", "x")
        assert result.allowed


# ---------------------------------------------------------------------------
# Stats Tests
# ---------------------------------------------------------------------------

class TestStats:
    def test_window_stats(self, evaluator):
        evaluator.record_action(ActionRecord(
            agent_id="agent-1", action="read", tool_name="db",
        ))
        evaluator.record_action(ActionRecord(
            agent_id="agent-2", action="write", tool_name="db",
        ))

        stats = evaluator.get_window_stats(window_seconds=60.0)
        assert stats["total_actions"] == 2
        assert stats["unique_agents"] == 2
        assert "agent-1" in stats["agent_ids"]

    def test_clear_history(self, evaluator):
        evaluator.record_action(ActionRecord(agent_id="a", action="x"))
        assert evaluator.action_count == 1
        evaluator.clear_history()
        assert evaluator.action_count == 0


# ---------------------------------------------------------------------------
# History Eviction Tests
# ---------------------------------------------------------------------------

class TestHistoryEviction:
    def test_max_history_evicts_old(self):
        evaluator = MultiAgentPolicyEvaluator(max_history=5)
        for i in range(10):
            evaluator.record_action(ActionRecord(
                agent_id=f"a-{i}", action="x",
            ))
        assert evaluator.action_count == 5


# ---------------------------------------------------------------------------
# Decision Model Tests
# ---------------------------------------------------------------------------

class TestDecisionModel:
    def test_decision_to_dict(self, evaluator, rate_limit_policy):
        evaluator.add_policy(rate_limit_policy)
        for i in range(3):
            evaluator.record_action(ActionRecord(
                agent_id=f"a-{i}", action="transfer", tool_name="transfer_funds",
            ))

        result = evaluator.evaluate("a-4", "transfer", "transfer_funds")
        d = result.to_dict()
        assert "allowed" in d
        assert "decisions" in d
        assert len(d["decisions"]) == 1
        assert d["decisions"][0]["policy_name"] == "rate-limit-transfers"
