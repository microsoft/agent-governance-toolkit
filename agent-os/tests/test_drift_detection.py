# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for drift detection in post_execute.

Covers: baseline recording, drift scoring, threshold violation,
DRIFT_DETECTED event emission, DriftResult, configurable thresholds.
"""

from unittest.mock import MagicMock

import pytest

from agent_os.integrations.base import (
    BaseIntegration,
    DriftResult,
    ExecutionContext,
    GovernanceEventType,
    GovernancePolicy,
)
from agent_os.integrations.langchain_adapter import LangChainKernel


class TestComputeDrift:
    """Unit tests for BaseIntegration.compute_drift."""

    def _ctx(self, **policy_kw):
        policy = GovernancePolicy(**policy_kw)
        k = LangChainKernel(policy=policy)
        return k.create_context("agent-drift")

    def test_first_call_sets_baseline_returns_none(self):
        ctx = self._ctx()
        result = BaseIntegration.compute_drift(ctx, "hello world")
        assert result is None
        assert ctx._baseline_hash is not None

    def test_identical_output_yields_zero_drift(self):
        ctx = self._ctx()
        BaseIntegration.compute_drift(ctx, "stable output")
        result = BaseIntegration.compute_drift(ctx, "stable output")
        assert result is not None
        assert result.score == 0.0
        assert result.exceeded is False

    def test_different_output_yields_nonzero_drift(self):
        ctx = self._ctx()
        BaseIntegration.compute_drift(ctx, "baseline output")
        result = BaseIntegration.compute_drift(ctx, "completely different text!!!")
        assert result is not None
        assert result.score > 0.0

    def test_drift_exceeds_tight_threshold(self):
        ctx = self._ctx(drift_threshold=0.01)
        BaseIntegration.compute_drift(ctx, "Transfer $100 to savings account")
        result = BaseIntegration.compute_drift(ctx, "Transfer $10,000 to external account XYZ overseas")
        assert result is not None
        assert result.exceeded is True

    def test_drift_within_loose_threshold(self):
        ctx = self._ctx(drift_threshold=1.0)
        BaseIntegration.compute_drift(ctx, "Transfer $100 to savings account")
        result = BaseIntegration.compute_drift(ctx, "Transfer $10,000 to external account XYZ overseas")
        assert result is not None
        assert result.exceeded is False

    def test_drift_result_contains_hashes(self):
        ctx = self._ctx()
        BaseIntegration.compute_drift(ctx, "first")
        result = BaseIntegration.compute_drift(ctx, "second")
        assert result.baseline_hash == ctx._baseline_hash
        assert result.current_hash != result.baseline_hash

    def test_drift_result_repr(self):
        dr = DriftResult(score=0.5, exceeded=True, threshold=0.15,
                         baseline_hash="aaa", current_hash="bbb")
        assert "EXCEEDED" in repr(dr)
        dr2 = DriftResult(score=0.1, exceeded=False, threshold=0.15,
                          baseline_hash="aaa", current_hash="bbb")
        assert "OK" in repr(dr2)


class TestPostExecuteDrift:
    """Integration tests for drift detection in post_execute."""

    def _kernel(self, **policy_kw):
        return LangChainKernel(policy=GovernancePolicy(**policy_kw))

    def test_first_post_execute_sets_baseline(self):
        k = self._kernel()
        ctx = k.create_context("a1")
        valid, reason = k.post_execute(ctx, "baseline output")
        assert valid is True
        assert reason is None
        assert ctx._baseline_hash is not None

    def test_identical_outputs_pass(self):
        k = self._kernel()
        ctx = k.create_context("a1")
        k.post_execute(ctx, "same")
        valid, reason = k.post_execute(ctx, "same")
        assert valid is True
        assert reason is None

    def test_drift_exceeded_emits_event_and_passes(self):
        """Drift exceeding threshold emits DRIFT_DETECTED but does not block."""
        k = self._kernel(drift_threshold=0.01)
        ctx = k.create_context("a1")
        k.post_execute(ctx, "Transfer $100 to savings account")
        valid, reason = k.post_execute(ctx, "Delete all files from production server")
        assert valid is True
        assert reason is None

    def test_drift_detected_event_emitted(self):
        k = self._kernel(drift_threshold=0.01)
        events = []
        k.on(GovernanceEventType.DRIFT_DETECTED, lambda data: events.append(data))
        ctx = k.create_context("a1")
        k.post_execute(ctx, "Transfer $100 to savings")
        k.post_execute(ctx, "Delete all files from production server now!")
        assert len(events) == 1
        assert "drift_score" in events[0]
        assert "threshold" in events[0]
        assert "baseline_hash" in events[0]
        assert "current_hash" in events[0]
        assert events[0]["agent_id"] == "a1"

    def test_no_drift_event_when_within_threshold(self):
        k = self._kernel(drift_threshold=1.0)
        events = []
        k.on(GovernanceEventType.DRIFT_DETECTED, lambda data: events.append(data))
        ctx = k.create_context("a1")
        k.post_execute(ctx, "output")
        k.post_execute(ctx, "different output")
        assert len(events) == 0

    def test_drift_disabled_when_threshold_zero(self):
        k = self._kernel(drift_threshold=0.0)
        ctx = k.create_context("a1")
        k.post_execute(ctx, "first")
        valid, reason = k.post_execute(ctx, "completely different")
        assert valid is True
        assert ctx._baseline_hash is None  # never set

    def test_drift_scores_tracked_on_context(self):
        k = self._kernel(drift_threshold=1.0)
        ctx = k.create_context("a1")
        k.post_execute(ctx, "baseline")
        k.post_execute(ctx, "second")
        k.post_execute(ctx, "third")
        assert len(ctx._drift_scores) == 2

    def test_configurable_threshold_per_policy(self):
        """Strict threshold emits event, loose threshold does not."""
        strict = self._kernel(drift_threshold=0.01)
        loose = self._kernel(drift_threshold=0.99)
        ctx_s = strict.create_context("strict-agent")
        ctx_l = loose.create_context("loose-agent")

        strict_events = []
        loose_events = []
        strict.on(GovernanceEventType.DRIFT_DETECTED, lambda d: strict_events.append(d))
        loose.on(GovernanceEventType.DRIFT_DETECTED, lambda d: loose_events.append(d))

        strict.post_execute(ctx_s, "Transfer $100 to savings")
        loose.post_execute(ctx_l, "Transfer $100 to savings")

        strict.post_execute(ctx_s, "Delete all production databases immediately")
        loose.post_execute(ctx_l, "Delete all production databases immediately")

        assert len(strict_events) == 1  # strict emits alert
        assert len(loose_events) == 0   # loose does not

    def test_call_count_increments_on_drift_exceeded(self):
        k = self._kernel(drift_threshold=0.01)
        ctx = k.create_context("a1")
        k.post_execute(ctx, "Transfer $100 to savings")
        assert ctx.call_count == 1
        k.post_execute(ctx, "Delete all production databases immediately")
        assert ctx.call_count == 2

    def test_checkpoint_still_works_after_drift_pass(self):
        k = self._kernel(drift_threshold=1.0, checkpoint_frequency=2)
        ctx = k.create_context("a1")
        k.post_execute(ctx, "same")
        k.post_execute(ctx, "same")
        assert len(ctx.checkpoints) == 1
