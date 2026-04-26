# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for TokenBudgetTracker.

Run with: python -m pytest tests/test_token_budget.py -v --tb=short
"""

import threading

import pytest

from agent_os.integrations.base import GovernancePolicy
from agent_os.integrations.token_budget import TokenBudgetStatus, TokenBudgetTracker


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def tracker():
    return TokenBudgetTracker(max_tokens=10_000, warning_threshold=0.8)


@pytest.fixture
def policy_tracker():
    policy = GovernancePolicy(max_tokens=5000)
    return TokenBudgetTracker(policy=policy, warning_threshold=0.8)


# =============================================================================
# Basic usage tracking
# =============================================================================


class TestRecordUsage:
    def test_initial_usage_is_zero(self, tracker):
        status = tracker.get_usage("agent-1")
        assert status.used == 0
        assert status.remaining == 10_000
        assert status.percentage == 0.0
        assert not status.is_warning
        assert not status.is_exceeded

    def test_record_single(self, tracker):
        status = tracker.record_usage("agent-1", prompt_tokens=100, completion_tokens=50)
        assert status.used == 150
        assert status.remaining == 9_850
        assert status.limit == 10_000

    def test_record_accumulates(self, tracker):
        tracker.record_usage("agent-1", 100, 50)
        status = tracker.record_usage("agent-1", 200, 100)
        assert status.used == 450

    def test_agents_are_independent(self, tracker):
        tracker.record_usage("a", 100, 100)
        tracker.record_usage("b", 500, 500)
        assert tracker.get_usage("a").used == 200
        assert tracker.get_usage("b").used == 1000


# =============================================================================
# Warning and exceeded thresholds
# =============================================================================


class TestThresholds:
    def test_warning_at_threshold(self, tracker):
        # 80% of 10_000 = 8_000
        status = tracker.record_usage("a", 4_000, 4_000)
        assert status.is_warning
        assert not status.is_exceeded

    def test_not_warning_below_threshold(self, tracker):
        status = tracker.record_usage("a", 3_000, 3_000)
        assert not status.is_warning

    def test_exceeded_at_limit(self, tracker):
        status = tracker.record_usage("a", 5_000, 5_000)
        assert status.is_exceeded
        assert status.remaining == 0

    def test_exceeded_over_limit(self, tracker):
        status = tracker.record_usage("a", 6_000, 6_000)
        assert status.is_exceeded
        assert status.remaining == 0

    def test_percentage_calculation(self, tracker):
        status = tracker.record_usage("a", 2_500, 2_500)
        assert status.percentage == pytest.approx(0.5)


# =============================================================================
# Warning callback
# =============================================================================


class TestWarningCallback:
    def test_callback_fires_on_crossing(self):
        fired = []
        tracker = TokenBudgetTracker(
            max_tokens=1000,
            warning_threshold=0.8,
            on_warning=lambda aid, s: fired.append((aid, s)),
        )
        tracker.record_usage("a", 400, 400)  # 80% — crosses threshold
        assert len(fired) == 1
        assert fired[0][0] == "a"
        assert fired[0][1].is_warning

    def test_callback_fires_only_once(self):
        fired = []
        tracker = TokenBudgetTracker(
            max_tokens=1000,
            warning_threshold=0.5,
            on_warning=lambda aid, s: fired.append(aid),
        )
        tracker.record_usage("a", 300, 300)  # crosses 50%
        tracker.record_usage("a", 100, 100)  # still above — no second fire
        assert len(fired) == 1


# =============================================================================
# GovernancePolicy integration
# =============================================================================


class TestPolicyIntegration:
    def test_uses_policy_max_tokens(self, policy_tracker):
        status = policy_tracker.get_usage("x")
        assert status.limit == 5000

    def test_policy_overrides_default(self):
        policy = GovernancePolicy(max_tokens=2000)
        tracker = TokenBudgetTracker(max_tokens=99999, policy=policy)
        assert tracker.get_usage("x").limit == 2000


# =============================================================================
# Reset
# =============================================================================


class TestReset:
    def test_reset_clears_usage(self, tracker):
        tracker.record_usage("a", 500, 500)
        tracker.reset("a")
        assert tracker.get_usage("a").used == 0

    def test_reset_unknown_agent_is_noop(self, tracker):
        tracker.reset("nonexistent")  # should not raise


# =============================================================================
# check_budget alias
# =============================================================================


class TestCheckBudget:
    def test_check_budget_same_as_get_usage(self, tracker):
        tracker.record_usage("a", 100, 200)
        assert tracker.check_budget("a") == tracker.get_usage("a")


# =============================================================================
# format_status
# =============================================================================


class TestFormatStatus:
    def test_format_empty(self, tracker):
        out = tracker.format_status("a")
        assert "0%" in out
        assert "0/10,000" in out

    def test_format_partial(self, tracker):
        tracker.record_usage("a", 4_100, 4_100)
        out = tracker.format_status("a")
        assert "82%" in out
        assert "8,200" in out
        assert "10,000" in out

    def test_format_full(self, tracker):
        tracker.record_usage("a", 5_000, 5_000)
        out = tracker.format_status("a")
        assert "100%" in out


# =============================================================================
# Validation
# =============================================================================


class TestValidation:
    def test_invalid_warning_threshold_high(self):
        with pytest.raises(ValueError, match="warning_threshold"):
            TokenBudgetTracker(warning_threshold=1.5)

    def test_invalid_warning_threshold_negative(self):
        with pytest.raises(ValueError, match="warning_threshold"):
            TokenBudgetTracker(warning_threshold=-0.1)

    def test_invalid_max_tokens(self):
        with pytest.raises(ValueError, match="max_tokens"):
            TokenBudgetTracker(max_tokens=0)


# =============================================================================
# Thread safety
# =============================================================================


class TestThreadSafety:
    def test_concurrent_record_usage(self):
        tracker = TokenBudgetTracker(max_tokens=1_000_000)
        errors = []

        def worker():
            try:
                for _ in range(500):
                    tracker.record_usage("shared", 1, 1)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert tracker.get_usage("shared").used == 4000  # 4 threads × 500 × 2


# =============================================================================
# TokenBudgetStatus frozen dataclass
# =============================================================================


class TestTokenBudgetStatus:
    def test_status_is_immutable(self):
        status = TokenBudgetStatus(
            used=100, limit=1000, remaining=900,
            percentage=0.1, is_warning=False, is_exceeded=False,
        )
        with pytest.raises(AttributeError):
            status.used = 999
