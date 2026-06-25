# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for PolicyEngine per-rule rate limiting.

Covers the bug where ``PolicyEngine.evaluate`` checked ``_is_rate_limited``
but never called ``_increment_rate_limit``, so the per-rule counter stayed at
0 and the limit never fired.
"""

from datetime import timedelta

import pytest

from agentmesh.governance.policy import Policy, PolicyEngine, PolicyRule


AGENT = "did:mesh:tester"
CONTEXT = {"action": {"type": "tool"}}


def _engine_with_limit(limit: str = "2/hour") -> tuple[PolicyEngine, str]:
    """Build an engine with a single allow rule carrying ``limit``."""
    rule = PolicyRule(
        name="rate-limited-tool",
        condition="action.type == 'tool'",
        action="allow",
        limit=limit,
    )
    policy = Policy(
        name="rate-limit-policy",
        agents=["*"],
        rules=[rule],
        default_action="deny",
    )
    engine = PolicyEngine()
    engine.load_policy(policy)
    return engine, rule.name


def test_third_matching_call_is_blocked() -> None:
    """limit='2/hour' allows the first 2 matching calls, blocks the 3rd+."""
    engine, _ = _engine_with_limit("2/hour")

    decisions = [engine.evaluate(AGENT, dict(CONTEXT)) for _ in range(5)]

    # First two consume the window.
    assert decisions[0].allowed is True
    assert decisions[0].rate_limited is False
    assert decisions[1].allowed is True
    assert decisions[1].rate_limited is False

    # (N+1)th and beyond are denied via rate limiting.
    for d in decisions[2:]:
        assert d.allowed is False
        assert d.rate_limited is True
        assert d.action == "deny"
        assert "2/hour" in d.reason


def test_counter_advances_by_one_per_call() -> None:
    """Each non-limited matching evaluation increments the counter once."""
    engine, rule_name = _engine_with_limit("5/hour")

    engine.evaluate(AGENT, dict(CONTEXT))
    assert engine._rate_limits[rule_name]["count"] == 1

    engine.evaluate(AGENT, dict(CONTEXT))
    assert engine._rate_limits[rule_name]["count"] == 2


def test_blocked_call_does_not_over_increment() -> None:
    """Once the limit is hit, blocked calls do not keep incrementing."""
    engine, rule_name = _engine_with_limit("2/hour")

    for _ in range(5):
        engine.evaluate(AGENT, dict(CONTEXT))

    # Counter caps at the limit; blocked calls short-circuit before increment.
    assert engine._rate_limits[rule_name]["count"] == 2


def test_window_rollover_resets_counter() -> None:
    """After the window expires the counter resets and calls are allowed."""
    engine, rule_name = _engine_with_limit("2/hour")

    # Exhaust the window.
    assert engine.evaluate(AGENT, dict(CONTEXT)).allowed is True
    assert engine.evaluate(AGENT, dict(CONTEXT)).allowed is True
    assert engine.evaluate(AGENT, dict(CONTEXT)).rate_limited is True

    # Simulate crossing the window boundary by moving reset_at into the past.
    engine._rate_limits[rule_name]["reset_at"] -= timedelta(hours=2)

    rolled_over = engine.evaluate(AGENT, dict(CONTEXT))
    assert rolled_over.allowed is True
    assert rolled_over.rate_limited is False
    # Fresh window started counting from this call.
    assert engine._rate_limits[rule_name]["count"] == 1


def test_rule_without_limit_never_rate_limited() -> None:
    """A rule with no limit is allowed indefinitely."""
    rule = PolicyRule(
        name="unbounded-tool",
        condition="action.type == 'tool'",
        action="allow",
    )
    policy = Policy(name="no-limit", agents=["*"], rules=[rule], default_action="deny")
    engine = PolicyEngine()
    engine.load_policy(policy)

    for _ in range(10):
        decision = engine.evaluate(AGENT, dict(CONTEXT))
        assert decision.allowed is True
        assert decision.rate_limited is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
