# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import pytest

from agent_os.shift_left_metrics import (
    ShiftLeftTracker,
    ViolationRecord,
    ViolationStage,
)


# ---------------------------------------------------------------------------
# ViolationStage enum
# ---------------------------------------------------------------------------


class TestViolationStage:
    def test_stage_values(self) -> None:
        assert ViolationStage.PRE_COMMIT.value == "pre_commit"
        assert ViolationStage.PR_CHECK.value == "pr_check"
        assert ViolationStage.CI_GATE.value == "ci_gate"
        assert ViolationStage.RUNTIME.value == "runtime"


# ---------------------------------------------------------------------------
# ViolationRecord
# ---------------------------------------------------------------------------


class TestViolationRecord:
    def test_defaults(self) -> None:
        rec = ViolationRecord(rule_name="r1", stage=ViolationStage.PR_CHECK)
        assert rec.resolved is False
        assert rec.message == ""
        assert rec.timestamp is not None


# ---------------------------------------------------------------------------
# ShiftLeftTracker - recording
# ---------------------------------------------------------------------------


class TestShiftLeftTrackerRecording:
    def test_record_adds_violation(self) -> None:
        tracker = ShiftLeftTracker()
        rec = tracker.record("no-shell", ViolationStage.PRE_COMMIT)
        assert rec.rule_name == "no-shell"
        assert len(tracker.records) == 1

    def test_record_returns_record(self) -> None:
        tracker = ShiftLeftTracker()
        rec = tracker.record("r1", ViolationStage.CI_GATE, resolved=True, message="fixed")
        assert rec.resolved is True
        assert rec.message == "fixed"

    def test_violations_for_rule(self) -> None:
        tracker = ShiftLeftTracker()
        tracker.record("r1", ViolationStage.PRE_COMMIT)
        tracker.record("r2", ViolationStage.CI_GATE)
        tracker.record("r1", ViolationStage.RUNTIME)
        assert len(tracker.violations_for_rule("r1")) == 2


# ---------------------------------------------------------------------------
# Stage distribution
# ---------------------------------------------------------------------------


class TestStageDistribution:
    def test_empty_tracker(self) -> None:
        tracker = ShiftLeftTracker()
        dist = tracker.stage_distribution()
        assert all(v == 0 for v in dist.values())
        assert len(dist) == 4  # all four stages present

    def test_counts_per_stage(self) -> None:
        tracker = ShiftLeftTracker()
        tracker.record("r1", ViolationStage.PRE_COMMIT)
        tracker.record("r2", ViolationStage.PRE_COMMIT)
        tracker.record("r3", ViolationStage.RUNTIME)
        dist = tracker.stage_distribution()
        assert dist["pre_commit"] == 2
        assert dist["runtime"] == 1
        assert dist["pr_check"] == 0


# ---------------------------------------------------------------------------
# Shift-left score
# ---------------------------------------------------------------------------


class TestShiftLeftScore:
    def test_empty_tracker_score(self) -> None:
        tracker = ShiftLeftTracker()
        assert tracker.shift_left_score() == 0.0

    def test_all_pre_commit_score_is_one(self) -> None:
        tracker = ShiftLeftTracker()
        tracker.record("r1", ViolationStage.PRE_COMMIT)
        tracker.record("r2", ViolationStage.PRE_COMMIT)
        assert tracker.shift_left_score() == pytest.approx(1.0)

    def test_all_runtime_score_is_zero(self) -> None:
        tracker = ShiftLeftTracker()
        tracker.record("r1", ViolationStage.RUNTIME)
        tracker.record("r2", ViolationStage.RUNTIME)
        assert tracker.shift_left_score() == pytest.approx(0.0)

    def test_mixed_stages_score(self) -> None:
        tracker = ShiftLeftTracker()
        tracker.record("r1", ViolationStage.PRE_COMMIT)  # weight 1.0
        tracker.record("r2", ViolationStage.RUNTIME)      # weight 0.0
        assert tracker.shift_left_score() == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Trend report
# ---------------------------------------------------------------------------


class TestTrendReport:
    def test_trend_report_structure(self) -> None:
        tracker = ShiftLeftTracker()
        tracker.record("r1", ViolationStage.PRE_COMMIT, resolved=True)
        tracker.record("r2", ViolationStage.CI_GATE, resolved=False)
        report = tracker.trend_report()
        assert report["total_violations"] == 2
        assert report["resolved"] == 1
        assert report["unresolved"] == 1
        assert "shift_left_score" in report
        assert "stage_distribution" in report
        assert report["resolution_rate"] == pytest.approx(0.5)

    def test_trend_report_empty(self) -> None:
        tracker = ShiftLeftTracker()
        report = tracker.trend_report()
        assert report["total_violations"] == 0
        assert report["resolution_rate"] == 0.0


# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------


class TestClear:
    def test_clear_removes_all_records(self) -> None:
        tracker = ShiftLeftTracker()
        tracker.record("r1", ViolationStage.PRE_COMMIT)
        tracker.record("r2", ViolationStage.RUNTIME)
        tracker.clear()
        assert len(tracker.records) == 0
        assert tracker.shift_left_score() == 0.0