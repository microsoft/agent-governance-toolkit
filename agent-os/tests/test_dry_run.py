# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for dry-run policy wrapper.

Run with: python -m pytest tests/test_dry_run.py -v --tb=short
"""

from datetime import datetime
from typing import Any

import pytest

from agent_os.integrations.base import BaseIntegration, GovernancePolicy
from agent_os.integrations.dry_run import (
    DryRunCollector,
    DryRunDecision,
    DryRunPolicy,
    DryRunResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _StubIntegration(BaseIntegration):
    """Minimal concrete integration for testing."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


# ---------------------------------------------------------------------------
# DryRunResult
# ---------------------------------------------------------------------------

class TestDryRunResult:
    def test_fields(self):
        r = DryRunResult(
            action="tool_call",
            decision=DryRunDecision.ALLOW,
            reason=None,
            policy_name="p1",
        )
        assert r.action == "tool_call"
        assert r.decision == DryRunDecision.ALLOW
        assert r.reason is None
        assert r.policy_name == "p1"
        assert isinstance(r.timestamp, datetime)


# ---------------------------------------------------------------------------
# DryRunCollector
# ---------------------------------------------------------------------------

class TestDryRunCollector:
    def test_empty_summary(self):
        c = DryRunCollector()
        s = c.summary()
        assert s == {"total": 0, "allowed": 0, "denied": 0, "warnings": 0}

    def test_add_and_get(self):
        c = DryRunCollector()
        r = DryRunResult("a", DryRunDecision.ALLOW, None, "p")
        c.add(r)
        assert c.get_results() == [r]

    def test_get_results_returns_copy(self):
        c = DryRunCollector()
        c.add(DryRunResult("a", DryRunDecision.ALLOW, None, "p"))
        results = c.get_results()
        results.clear()
        assert len(c.get_results()) == 1

    def test_summary_counts(self):
        c = DryRunCollector()
        c.add(DryRunResult("a", DryRunDecision.ALLOW, None, "p"))
        c.add(DryRunResult("b", DryRunDecision.DENY, "blocked", "p"))
        c.add(DryRunResult("c", DryRunDecision.WARN, "caution", "p"))
        c.add(DryRunResult("d", DryRunDecision.ALLOW, None, "p"))
        s = c.summary()
        assert s == {"total": 4, "allowed": 2, "denied": 1, "warnings": 1}

    def test_clear(self):
        c = DryRunCollector()
        c.add(DryRunResult("a", DryRunDecision.ALLOW, None, "p"))
        c.clear()
        assert c.get_results() == []
        assert c.summary()["total"] == 0


# ---------------------------------------------------------------------------
# DryRunPolicy – evaluate
# ---------------------------------------------------------------------------

class TestDryRunPolicyEvaluate:
    def test_allow_action(self):
        integration = _StubIntegration(GovernancePolicy())
        drp = DryRunPolicy(integration, policy_name="test")
        ctx = integration.create_context("agent-1")

        result = drp.evaluate("run_tool", ctx, "safe input")

        assert result.decision == DryRunDecision.ALLOW
        assert result.reason is None
        assert result.action == "run_tool"
        assert result.policy_name == "test"

    def test_deny_when_max_tool_calls_exceeded(self):
        policy = GovernancePolicy(max_tool_calls=2)
        integration = _StubIntegration(policy)
        drp = DryRunPolicy(integration, policy_name="strict")
        ctx = integration.create_context("agent-1")
        ctx.call_count = 5  # exceed limit

        result = drp.evaluate("run_tool", ctx, "input")

        assert result.decision == DryRunDecision.DENY
        assert "Max tool calls exceeded" in result.reason

    def test_deny_on_blocked_pattern(self):
        policy = GovernancePolicy(blocked_patterns=["rm -rf"])
        integration = _StubIntegration(policy)
        drp = DryRunPolicy(integration)
        ctx = integration.create_context("agent-1")

        result = drp.evaluate("exec_cmd", ctx, "rm -rf /")

        assert result.decision == DryRunDecision.DENY
        assert "Blocked pattern" in result.reason

    def test_does_not_block_execution(self):
        """Dry-run should record deny but return a result (never raise)."""
        policy = GovernancePolicy(max_tool_calls=1)
        integration = _StubIntegration(policy)
        drp = DryRunPolicy(integration)
        ctx = integration.create_context("agent-1")
        ctx.call_count = 100

        result = drp.evaluate("action", ctx)
        assert result.decision == DryRunDecision.DENY
        # No exception raised – that's the point of dry-run

    def test_results_accumulate(self):
        integration = _StubIntegration(GovernancePolicy(max_tool_calls=1))
        drp = DryRunPolicy(integration)
        ctx = integration.create_context("agent-1")

        drp.evaluate("a1", ctx, "ok")
        ctx.call_count = 5
        drp.evaluate("a2", ctx, "ok")

        results = drp.get_results()
        assert len(results) == 2
        assert results[0].decision == DryRunDecision.ALLOW
        assert results[1].decision == DryRunDecision.DENY


# ---------------------------------------------------------------------------
# DryRunPolicy – evaluate_warn
# ---------------------------------------------------------------------------

class TestDryRunPolicyEvaluateWarn:
    def test_warn(self):
        integration = _StubIntegration(GovernancePolicy())
        drp = DryRunPolicy(integration, policy_name="monitor")
        result = drp.evaluate_warn("high_cost_call", "estimated cost > $1")

        assert result.decision == DryRunDecision.WARN
        assert result.reason == "estimated cost > $1"
        assert result.policy_name == "monitor"

    def test_warn_appears_in_summary(self):
        integration = _StubIntegration(GovernancePolicy())
        drp = DryRunPolicy(integration)
        drp.evaluate_warn("w1", "reason1")
        drp.evaluate_warn("w2", "reason2")
        assert drp.summary()["warnings"] == 2


# ---------------------------------------------------------------------------
# DryRunPolicy – shared collector
# ---------------------------------------------------------------------------

class TestSharedCollector:
    def test_multiple_policies_share_collector(self):
        collector = DryRunCollector()
        i1 = _StubIntegration(GovernancePolicy())
        i2 = _StubIntegration(GovernancePolicy(max_tool_calls=1))

        drp1 = DryRunPolicy(i1, policy_name="p1", collector=collector)
        drp2 = DryRunPolicy(i2, policy_name="p2", collector=collector)

        ctx1 = i1.create_context("a1")
        ctx2 = i2.create_context("a2")
        ctx2.call_count = 5

        drp1.evaluate("ok", ctx1, "input")
        drp2.evaluate("blocked", ctx2, "input")

        assert len(collector.get_results()) == 2
        assert collector.summary()["allowed"] == 1
        assert collector.summary()["denied"] == 1


# ---------------------------------------------------------------------------
# DryRunPolicy – clear / summary delegation
# ---------------------------------------------------------------------------

class TestDryRunPolicyDelegation:
    def test_clear_resets(self):
        integration = _StubIntegration(GovernancePolicy())
        drp = DryRunPolicy(integration)
        ctx = integration.create_context("a")
        drp.evaluate("x", ctx, "data")
        assert drp.summary()["total"] == 1
        drp.clear()
        assert drp.summary()["total"] == 0
        assert drp.get_results() == []


# ---------------------------------------------------------------------------
# Imports from package __init__
# ---------------------------------------------------------------------------

class TestExports:
    def test_importable_from_package(self):
        from agent_os.integrations import (
            DryRunCollector,
            DryRunDecision,
            DryRunPolicy,
            DryRunResult,
        )
        assert DryRunPolicy is not None
        assert DryRunResult is not None
        assert DryRunDecision is not None
        assert DryRunCollector is not None
