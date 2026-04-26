# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for token and cost budget enforcement."""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from agentmesh.governance.budget import (
    BudgetConfig,
    BudgetDecision,
    BudgetTracker,
    _parse_window,
)


# ── BudgetConfig tests ──────────────────────────────────────────────


class TestBudgetConfig:
    def test_defaults(self):
        cfg = BudgetConfig()
        assert cfg.max_tokens == 100_000
        assert cfg.max_cost_usd == 10.0
        assert cfg.window == "1h"

    def test_window_seconds(self):
        assert BudgetConfig(window="1h").window_seconds() == 3600
        assert BudgetConfig(window="24h").window_seconds() == 86400
        assert BudgetConfig(window="7d").window_seconds() == 604800
        assert BudgetConfig(window="30m").window_seconds() == 1800
        assert BudgetConfig(window="60s").window_seconds() == 60

    def test_invalid_window(self):
        with pytest.raises(ValueError, match="Invalid window"):
            BudgetConfig(window="1x").window_seconds()

    def test_parse_window_directly(self):
        assert _parse_window("5m") == 300
        assert _parse_window("2d") == 172800


# ── BudgetTracker basic tracking ────────────────────────────────────


class TestBudgetTrackerTracking:
    def test_record_and_get_usage(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000, max_cost_usd=5.0))
        tracker.record_usage("agent-1", tokens=200, cost_usd=0.50)
        usage = tracker.get_usage("agent-1")
        assert usage["tokens_used"] == 200
        assert usage["cost_used"] == pytest.approx(0.50)
        assert usage["remaining_tokens"] == 800
        assert usage["remaining_cost"] == pytest.approx(4.50)

    def test_accumulates_usage(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000))
        tracker.record_usage("a1", tokens=100)
        tracker.record_usage("a1", tokens=250)
        assert tracker.get_usage("a1")["tokens_used"] == 350

    def test_fresh_agent_usage(self):
        tracker = BudgetTracker(BudgetConfig())
        usage = tracker.get_usage("new-agent")
        assert usage["tokens_used"] == 0
        assert usage["cost_used"] == 0.0


# ── Budget limit enforcement ────────────────────────────────────────


class TestBudgetLimits:
    def test_within_budget(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000, max_cost_usd=5.0))
        tracker.record_usage("a", tokens=500, cost_usd=2.0)
        decision = tracker.check_budget("a")
        assert decision.allowed is True
        assert decision.tokens_remaining == 500
        assert decision.cost_remaining == pytest.approx(3.0)

    def test_token_budget_exceeded(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000))
        tracker.record_usage("a", tokens=1001)
        decision = tracker.check_budget("a")
        assert decision.allowed is False
        assert "token budget exceeded" in decision.reason

    def test_cost_budget_exceeded(self):
        tracker = BudgetTracker(BudgetConfig(max_cost_usd=1.0))
        tracker.record_usage("a", tokens=10, cost_usd=1.50)
        decision = tracker.check_budget("a")
        assert decision.allowed is False
        assert "cost budget exceeded" in decision.reason

    def test_estimated_tokens_causes_deny(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000))
        tracker.record_usage("a", tokens=800)
        decision = tracker.check_budget("a", estimated_tokens=300)
        assert decision.allowed is False
        assert "estimated" in decision.reason

    def test_estimated_tokens_within_budget(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000))
        tracker.record_usage("a", tokens=500)
        decision = tracker.check_budget("a", estimated_tokens=400)
        assert decision.allowed is True

    def test_remaining_never_negative(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=100, max_cost_usd=1.0))
        tracker.record_usage("a", tokens=200, cost_usd=5.0)
        decision = tracker.check_budget("a")
        assert decision.tokens_remaining == 0
        assert decision.cost_remaining == 0.0


# ── Window expiry ───────────────────────────────────────────────────


class TestWindowExpiry:
    def test_window_resets_usage(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000, window="1h"))
        tracker.record_usage("a", tokens=999)

        # Simulate time advancing past the 1h window
        future = time.time() + 3601
        with patch("agentmesh.governance.budget.time.time", return_value=future):
            usage = tracker.get_usage("a")
            assert usage["tokens_used"] == 0
            decision = tracker.check_budget("a")
            assert decision.allowed is True

    def test_window_not_yet_expired(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000, window="1h"))
        tracker.record_usage("a", tokens=999)

        near_future = time.time() + 1800  # only 30 minutes
        with patch("agentmesh.governance.budget.time.time", return_value=near_future):
            usage = tracker.get_usage("a")
            assert usage["tokens_used"] == 999

    def test_window_resets_at_field(self):
        tracker = BudgetTracker(BudgetConfig(window="1h"))
        usage = tracker.get_usage("a")
        assert "window_resets_at" in usage
        assert usage["window_resets_at"] > time.time()


# ── Per-agent isolation ─────────────────────────────────────────────


class TestPerAgentIsolation:
    def test_agents_independent(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000))
        tracker.record_usage("agent-a", tokens=900)
        tracker.record_usage("agent-b", tokens=100)
        assert tracker.get_usage("agent-a")["tokens_used"] == 900
        assert tracker.get_usage("agent-b")["tokens_used"] == 100

    def test_one_agent_denied_other_allowed(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=500))
        tracker.record_usage("heavy", tokens=600)
        tracker.record_usage("light", tokens=50)
        assert not tracker.check_budget("heavy").allowed
        assert tracker.check_budget("light").allowed


# ── Reset tests ─────────────────────────────────────────────────────


class TestReset:
    def test_reset_single_agent(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000))
        tracker.record_usage("a", tokens=500)
        tracker.record_usage("b", tokens=300)
        tracker.reset("a")
        assert tracker.get_usage("a")["tokens_used"] == 0
        assert tracker.get_usage("b")["tokens_used"] == 300

    def test_reset_all_agents(self):
        tracker = BudgetTracker(BudgetConfig(max_tokens=1000))
        tracker.record_usage("a", tokens=500)
        tracker.record_usage("b", tokens=300)
        tracker.reset()
        assert tracker.get_usage("a")["tokens_used"] == 0
        assert tracker.get_usage("b")["tokens_used"] == 0

    def test_reset_nonexistent_agent_no_error(self):
        tracker = BudgetTracker(BudgetConfig())
        tracker.reset("ghost")  # should not raise


# ── BudgetDecision dataclass ────────────────────────────────────────


class TestBudgetDecision:
    def test_fields(self):
        d = BudgetDecision(
            allowed=True, reason="ok", tokens_remaining=500, cost_remaining=2.5
        )
        assert d.allowed is True
        assert d.reason == "ok"
        assert d.tokens_remaining == 500
        assert d.cost_remaining == 2.5
