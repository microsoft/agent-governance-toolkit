# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Dynamic Policy Conditions (issue #2615).

Covers:
- TimeContext, CostContext, QuotaContext, SystemContext construction
- DynamicContext.to_flat_dict() key naming
- DynamicContext.from_dict() deserialization
- PolicyEvaluator.evaluate() accepting optional dynamic_context
- Time-based policy conditions (block outside business hours)
- Cost-aware policy conditions (deny when budget exhausted)
- Quota-aware policy conditions (block when api_calls_remaining is low)
- Backward compatibility: existing callers without dynamic_context unaffected
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from agent_os.policies.dynamic_context import (
    CostContext,
    DynamicContext,
    QuotaContext,
    SystemContext,
    TimeContext,
)
from agent_os.policies.evaluator import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_policy(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def _load_policy(path: Path) -> PolicyEvaluator:
    doc = PolicyDocument.from_yaml(path)
    return PolicyEvaluator(policies=[doc])


# ---------------------------------------------------------------------------
# TimeContext
# ---------------------------------------------------------------------------


class TestTimeContext:
    def test_defaults(self) -> None:
        ctx = TimeContext()
        assert ctx.hour == 0
        assert ctx.day_of_week == 1
        assert ctx.timezone == "UTC"
        assert ctx.timestamp > 0

    def test_now_utc(self) -> None:
        ctx = TimeContext.now()
        assert 0 <= ctx.hour <= 23
        assert 1 <= ctx.day_of_week <= 7
        assert ctx.timezone == "UTC"

    def test_to_dict_keys(self) -> None:
        ctx = TimeContext(timestamp=1_000_000, hour=14, day_of_week=3, timezone="UTC")
        d = ctx.to_dict()
        assert d == {"timestamp": 1_000_000, "hour": 14, "day_of_week": 3, "timezone": "UTC"}

    def test_now_invalid_timezone_falls_back_to_utc(self) -> None:
        ctx = TimeContext.now("Not/AReal_Zone")
        assert ctx.timezone == "UTC"


# ---------------------------------------------------------------------------
# CostContext
# ---------------------------------------------------------------------------


class TestCostContext:
    def test_defaults(self) -> None:
        ctx = CostContext()
        assert ctx.budget_total == 0.0
        assert ctx.budget_used == 0.0
        assert ctx.budget_remaining == 0.0

    def test_to_dict(self) -> None:
        ctx = CostContext(budget_total=100.0, budget_used=90.0, budget_remaining=10.0)
        d = ctx.to_dict()
        assert d["budget_remaining"] == 10.0
        assert d["budget_total"] == 100.0

    def test_negative_remaining(self) -> None:
        ctx = CostContext(budget_total=100.0, budget_used=110.0, budget_remaining=-10.0)
        assert ctx.budget_remaining == -10.0


# ---------------------------------------------------------------------------
# QuotaContext
# ---------------------------------------------------------------------------


class TestQuotaContext:
    def test_to_dict(self) -> None:
        ctx = QuotaContext(api_calls_remaining=50, rate_limit_remaining=200)
        d = ctx.to_dict()
        assert d["api_calls_remaining"] == 50
        assert d["rate_limit_remaining"] == 200


# ---------------------------------------------------------------------------
# SystemContext
# ---------------------------------------------------------------------------


class TestSystemContext:
    def test_to_dict(self) -> None:
        ctx = SystemContext(load=0.85, error_rate=0.03)
        d = ctx.to_dict()
        assert d["load"] == 0.85
        assert d["error_rate"] == 0.03


# ---------------------------------------------------------------------------
# DynamicContext
# ---------------------------------------------------------------------------


class TestDynamicContextFlatDict:
    def test_empty_context_yields_empty_dict(self) -> None:
        ctx = DynamicContext()
        assert ctx.to_flat_dict() == {}

    def test_time_keys_prefixed(self) -> None:
        ctx = DynamicContext(time=TimeContext(timestamp=100, hour=10, day_of_week=2))
        flat = ctx.to_flat_dict()
        assert flat["context.time.hour"] == 10
        assert flat["context.time.day_of_week"] == 2
        assert flat["context.time.timestamp"] == 100

    def test_cost_keys_prefixed(self) -> None:
        ctx = DynamicContext(cost=CostContext(budget_remaining=5.0))
        flat = ctx.to_flat_dict()
        assert flat["context.cost.budget_remaining"] == 5.0

    def test_quota_keys_prefixed(self) -> None:
        ctx = DynamicContext(quota=QuotaContext(api_calls_remaining=15))
        flat = ctx.to_flat_dict()
        assert flat["context.quota.api_calls_remaining"] == 15

    def test_system_keys_prefixed(self) -> None:
        ctx = DynamicContext(system=SystemContext(load=0.9))
        flat = ctx.to_flat_dict()
        assert flat["context.system.load"] == 0.9

    def test_all_sub_contexts(self) -> None:
        ctx = DynamicContext(
            time=TimeContext(hour=9),
            cost=CostContext(budget_remaining=100.0),
            quota=QuotaContext(api_calls_remaining=50),
            system=SystemContext(load=0.5),
        )
        flat = ctx.to_flat_dict()
        assert "context.time.hour" in flat
        assert "context.cost.budget_remaining" in flat
        assert "context.quota.api_calls_remaining" in flat
        assert "context.system.load" in flat


class TestDynamicContextFromDict:
    def test_from_empty_dict(self) -> None:
        ctx = DynamicContext.from_dict({})
        assert ctx.time is None
        assert ctx.cost is None
        assert ctx.quota is None
        assert ctx.system is None

    def test_from_dict_with_time(self) -> None:
        ctx = DynamicContext.from_dict({
            "time": {"hour": 22, "day_of_week": 6, "timezone": "UTC", "timestamp": 9999}
        })
        assert ctx.time is not None
        assert ctx.time.hour == 22
        assert ctx.time.day_of_week == 6

    def test_from_dict_with_cost(self) -> None:
        ctx = DynamicContext.from_dict({
            "cost": {"budget_total": 1000.0, "budget_used": 980.0, "budget_remaining": 20.0}
        })
        assert ctx.cost is not None
        assert ctx.cost.budget_remaining == 20.0

    def test_from_dict_ignores_unknown_keys(self) -> None:
        ctx = DynamicContext.from_dict({"unknown_key": "ignored", "cost": {"budget_remaining": 5.0}})
        assert ctx.cost is not None
        assert ctx.time is None


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_evaluate_without_dynamic_context(self, tmp_path: Path) -> None:
        """Callers that omit dynamic_context must continue to work unchanged."""
        policy = _write_policy(tmp_path, """\
            version: "1.0"
            name: compat-policy
            rules:
              - name: deny-shell
                condition: {field: action, operator: eq, value: run_shell}
                action: deny
                priority: 100
            defaults:
              action: allow
        """)
        ev = _load_policy(policy)
        # Original call signature — no dynamic_context
        decision = ev.evaluate({"action": "run_shell"})
        assert not decision.allowed
        assert decision.action == "deny"

    def test_existing_rules_unaffected(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path, """\
            version: "1.0"
            name: compat-policy
            rules:
              - name: allow-reads
                condition: {field: action, operator: eq, value: read}
                action: allow
                priority: 50
            defaults:
              action: deny
        """)
        ev = _load_policy(policy)
        assert ev.evaluate({"action": "read"}).allowed
        assert not ev.evaluate({"action": "write"}).allowed

    def test_policy_decision_has_metadata_field(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path, """\
            version: "1.0"
            name: meta-policy
            rules: []
            defaults:
              action: allow
        """)
        ev = _load_policy(policy)
        decision = ev.evaluate({})
        # metadata field exists and defaults to empty dict
        assert hasattr(decision, "metadata")
        assert decision.metadata == {}


# ---------------------------------------------------------------------------
# Time-based conditions
# ---------------------------------------------------------------------------


class TestTimeBasedConditions:
    def _make_evaluator(self, tmp_path: Path) -> PolicyEvaluator:
        policy = _write_policy(tmp_path, """\
            version: "1.0"
            name: time-policy
            rules:
              - name: block-after-hours
                condition:
                  field: "context.time.hour"
                  operator: gte
                  value: 18
                action: deny
                priority: 90
                message: "Operations blocked outside business hours (18:00+)"
              - name: block-weekends
                condition:
                  field: "context.time.day_of_week"
                  operator: gte
                  value: 6
                action: deny
                priority: 80
                message: "Operations blocked on weekends"
            defaults:
              action: allow
        """)
        return _load_policy(policy)

    def test_within_business_hours_allowed(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(time=TimeContext(hour=14, day_of_week=3, timestamp=1000))
        decision = ev.evaluate({"action": "read"}, dynamic_context=dctx)
        assert decision.allowed

    def test_after_hours_denied(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(time=TimeContext(hour=20, day_of_week=2, timestamp=1000))
        decision = ev.evaluate({"action": "read"}, dynamic_context=dctx)
        assert not decision.allowed
        assert decision.matched_rule == "block-after-hours"

    def test_exactly_cutoff_hour_denied(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(time=TimeContext(hour=18, day_of_week=1, timestamp=1000))
        decision = ev.evaluate({"action": "write"}, dynamic_context=dctx)
        assert not decision.allowed

    def test_saturday_denied(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(time=TimeContext(hour=10, day_of_week=6, timestamp=1000))
        decision = ev.evaluate({"action": "read"}, dynamic_context=dctx)
        assert not decision.allowed
        assert decision.matched_rule == "block-weekends"

    def test_no_time_context_falls_through_to_default(self, tmp_path: Path) -> None:
        """When time context is absent, time-based rules do not match."""
        ev = self._make_evaluator(tmp_path)
        # No dynamic_context — time rules cannot match
        decision = ev.evaluate({"action": "read"})
        assert decision.allowed  # default is allow


# ---------------------------------------------------------------------------
# Cost-aware conditions
# ---------------------------------------------------------------------------


class TestCostAwareConditions:
    def _make_evaluator(self, tmp_path: Path) -> PolicyEvaluator:
        policy = _write_policy(tmp_path, """\
            version: "1.0"
            name: cost-policy
            rules:
              - name: deny-budget-exhausted
                condition:
                  field: "context.cost.budget_remaining"
                  operator: lte
                  value: 0
                action: deny
                priority: 100
                message: "Monthly budget exhausted"
              - name: deny-budget-critical
                condition:
                  field: "context.cost.budget_remaining"
                  operator: lt
                  value: 10.0
                action: deny
                priority: 90
                message: "Budget critically low (< 10 units)"
            defaults:
              action: allow
        """)
        return _load_policy(policy)

    def test_budget_healthy_allowed(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(cost=CostContext(
            budget_total=1000.0, budget_used=500.0, budget_remaining=500.0
        ))
        assert ev.evaluate({"action": "web_search"}, dynamic_context=dctx).allowed

    def test_budget_exhausted_denied(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(cost=CostContext(
            budget_total=1000.0, budget_used=1000.0, budget_remaining=0.0
        ))
        decision = ev.evaluate({"action": "web_search"}, dynamic_context=dctx)
        assert not decision.allowed
        assert decision.matched_rule == "deny-budget-exhausted"

    def test_budget_negative_denied(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(cost=CostContext(budget_remaining=-5.0))
        assert not ev.evaluate({}, dynamic_context=dctx).allowed

    def test_budget_critically_low_denied(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(cost=CostContext(budget_remaining=5.0))
        decision = ev.evaluate({"action": "image_generation"}, dynamic_context=dctx)
        assert not decision.allowed
        assert decision.matched_rule == "deny-budget-critical"

    def test_no_cost_context_falls_through(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        # No cost context — cost rules do not match; default allow
        assert ev.evaluate({"action": "read"}).allowed


# ---------------------------------------------------------------------------
# Quota-aware conditions
# ---------------------------------------------------------------------------


class TestQuotaAwareConditions:
    def _make_evaluator(self, tmp_path: Path) -> PolicyEvaluator:
        policy = _write_policy(tmp_path, """\
            version: "1.0"
            name: quota-policy
            rules:
              - name: block-quota-exhausted
                condition:
                  field: "context.quota.api_calls_remaining"
                  operator: lte
                  value: 0
                action: deny
                priority: 100
            defaults:
              action: allow
        """)
        return _load_policy(policy)

    def test_quota_available(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(quota=QuotaContext(api_calls_remaining=500))
        assert ev.evaluate({}, dynamic_context=dctx).allowed

    def test_quota_exhausted(self, tmp_path: Path) -> None:
        ev = self._make_evaluator(tmp_path)
        dctx = DynamicContext(quota=QuotaContext(api_calls_remaining=0))
        decision = ev.evaluate({}, dynamic_context=dctx)
        assert not decision.allowed
        assert decision.matched_rule == "block-quota-exhausted"


# ---------------------------------------------------------------------------
# Combined conditions
# ---------------------------------------------------------------------------


class TestCombinedConditions:
    def test_time_and_cost_combined(self, tmp_path: Path) -> None:
        """After-hours rule fires before budget rule when both match."""
        policy = _write_policy(tmp_path, """\
            version: "1.0"
            name: combined-policy
            rules:
              - name: block-after-hours
                condition:
                  field: "context.time.hour"
                  operator: gte
                  value: 18
                action: deny
                priority: 100
              - name: deny-budget-exhausted
                condition:
                  field: "context.cost.budget_remaining"
                  operator: lte
                  value: 0
                action: deny
                priority: 90
            defaults:
              action: allow
        """)
        ev = _load_policy(policy)
        dctx = DynamicContext(
            time=TimeContext(hour=22, day_of_week=2, timestamp=1000),
            cost=CostContext(budget_remaining=0.0),
        )
        decision = ev.evaluate({"action": "web_search"}, dynamic_context=dctx)
        assert not decision.allowed
        assert decision.matched_rule == "block-after-hours"  # higher priority

    def test_action_context_not_shadowed_by_dynamic(self, tmp_path: Path) -> None:
        """Action-level keys must survive dynamic context merging."""
        policy = _write_policy(tmp_path, """\
            version: "1.0"
            name: shadow-policy
            rules:
              - name: allow-read
                condition: {field: action, operator: eq, value: read}
                action: allow
                priority: 50
            defaults:
              action: deny
        """)
        ev = _load_policy(policy)
        dctx = DynamicContext(time=TimeContext(hour=10))
        decision = ev.evaluate({"action": "read"}, dynamic_context=dctx)
        assert decision.allowed
