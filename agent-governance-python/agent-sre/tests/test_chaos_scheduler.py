# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for chaos scheduler — scheduling, blackouts, progressive severity, YAML loading."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_sre.chaos.chaos_scheduler import ChaosScheduler
from agent_sre.chaos.loader import load_schedules
from agent_sre.chaos.scheduler import (
    BlackoutWindow,
    ChaosSchedule,
    ProgressiveConfig,
    ScheduleExecution,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MONDAY_9AM = datetime(2025, 1, 6, 9, 0, 0, tzinfo=timezone.utc)  # Monday
MONDAY_3AM = datetime(2025, 1, 6, 3, 0, 0, tzinfo=timezone.utc)
SATURDAY_9AM = datetime(2025, 1, 4, 9, 0, 0, tzinfo=timezone.utc)  # Saturday
WEDNESDAY_2PM = datetime(2025, 1, 8, 14, 0, 0, tzinfo=timezone.utc)  # Wednesday


def _make_schedule(
    schedule_id: str = "s1",
    cron: str = "0 9 * * 1-5",
    enabled: bool = True,
    blackouts: list[BlackoutWindow] | None = None,
    progressive: ProgressiveConfig | None = None,
) -> ChaosSchedule:
    return ChaosSchedule(
        id=schedule_id,
        name="Test Schedule",
        experiment_id="tool-timeout",
        cron_expression=cron,
        enabled=enabled,
        blackout_windows=blackouts or [],
        progressive_config=progressive,
    )


def _make_execution(
    schedule_id: str,
    result: str = "pass",
    severity: float = 0.2,
    resilience: float = 0.8,
    at: datetime | None = None,
) -> ScheduleExecution:
    return ScheduleExecution(
        schedule_id=schedule_id,
        executed_at=at or MONDAY_9AM,
        severity_used=severity,
        result=result,
        resilience_score=resilience,
    )


# ---------------------------------------------------------------------------
# Cron matching
# ---------------------------------------------------------------------------


class TestCronMatching:
    """Cron-based schedule matching using croniter."""

    def test_weekday_9am_matches_monday(self) -> None:
        sched = _make_schedule(cron="0 9 * * 1-5")
        scheduler = ChaosScheduler([sched])
        assert scheduler.should_run("s1", MONDAY_9AM) is True

    def test_weekday_9am_does_not_match_saturday(self) -> None:
        sched = _make_schedule(cron="0 9 * * 1-5")
        scheduler = ChaosScheduler([sched])
        assert scheduler.should_run("s1", SATURDAY_9AM) is False

    def test_every_day_at_10_30(self) -> None:
        sched = _make_schedule(cron="30 10 * * *")
        scheduler = ChaosScheduler([sched])
        at = datetime(2025, 1, 6, 10, 30, 0, tzinfo=timezone.utc)
        assert scheduler.should_run("s1", at) is True

    def test_wrong_hour_does_not_match(self) -> None:
        sched = _make_schedule(cron="0 9 * * 1-5")
        scheduler = ChaosScheduler([sched])
        at = datetime(2025, 1, 6, 10, 0, 0, tzinfo=timezone.utc)
        assert scheduler.should_run("s1", at) is False

    def test_wednesday_2pm_matches(self) -> None:
        sched = _make_schedule(cron="0 14 * * 3")
        scheduler = ChaosScheduler([sched])
        assert scheduler.should_run("s1", WEDNESDAY_2PM) is True


# ---------------------------------------------------------------------------
# Blackout windows
# ---------------------------------------------------------------------------


class TestBlackoutWindows:
    """Blackout windows block chaos execution during protected periods."""

    def test_in_blackout_blocks_execution(self) -> None:
        bw = BlackoutWindow(start="00:00", end="06:00", reason="overnight")
        sched = _make_schedule(cron="0 3 * * 1-5", blackouts=[bw])
        scheduler = ChaosScheduler([sched])
        assert scheduler.is_in_blackout(sched, MONDAY_3AM) is True

    def test_outside_blackout_allows_execution(self) -> None:
        bw = BlackoutWindow(start="17:00", end="23:59", reason="after hours")
        sched = _make_schedule(cron="0 9 * * 1-5", blackouts=[bw])
        scheduler = ChaosScheduler([sched])
        assert scheduler.is_in_blackout(sched, MONDAY_9AM) is False

    def test_midnight_wrap_blackout(self) -> None:
        bw = BlackoutWindow(start="22:00", end="06:00", reason="overnight")
        sched = _make_schedule(blackouts=[bw])
        scheduler = ChaosScheduler([sched])
        assert scheduler.is_in_blackout(sched, MONDAY_3AM) is True

    def test_multiple_blackouts(self) -> None:
        bw1 = BlackoutWindow(start="00:00", end="06:00", reason="overnight")
        bw2 = BlackoutWindow(start="12:00", end="13:00", reason="lunch")
        sched = _make_schedule(blackouts=[bw1, bw2])
        scheduler = ChaosScheduler([sched])
        at_noon = datetime(2025, 1, 6, 12, 30, 0, tzinfo=timezone.utc)
        assert scheduler.is_in_blackout(sched, at_noon) is True

    @pytest.mark.parametrize("second", [0, 30, 59])
    def test_end_minute_is_blocked_to_its_last_second(self, second: int) -> None:
        bw = BlackoutWindow(start="17:00", end="23:59", reason="after hours")
        schedule = _make_schedule(cron="59 23 * * *", blackouts=[bw])
        scheduler = ChaosScheduler([schedule])
        at = datetime(2025, 1, 6, 23, 59, second, tzinfo=timezone.utc)
        assert scheduler.is_in_blackout(schedule, at) is True
        assert scheduler.should_run("s1", at) is False

    def test_midnight_wrap_end_minute_is_blocked(self) -> None:
        bw = BlackoutWindow(start="22:00", end="06:00", reason="overnight")
        at = datetime(2025, 1, 6, 6, 0, 45, tzinfo=timezone.utc)
        assert bw.contains(at) is True

    def test_minute_after_end_is_not_blocked(self) -> None:
        bw = BlackoutWindow(start="12:00", end="13:00", reason="lunch")
        assert bw.contains(datetime(2025, 1, 6, 13, 0, 59, tzinfo=timezone.utc)) is True
        assert bw.contains(datetime(2025, 1, 6, 13, 1, 0, tzinfo=timezone.utc)) is False
        assert bw.contains(datetime(2025, 1, 6, 11, 59, 59, tzinfo=timezone.utc)) is False

    @pytest.mark.parametrize(
        ("start", "end"),
        [
            ("9pm", "11pm"),
            ("21:00", "24:00"),
            ("21:00:00", "23:00:00"),
            ("21-00", "23-00"),
            ("12:60", "13:00"),
            ("", "13:00"),
        ],
    )
    def test_unreadable_bound_is_rejected(self, start: str, end: str) -> None:
        # Such a window used to be accepted and never matched, so chaos
        # ran during the blackout it was meant to prevent.
        with pytest.raises(ValueError):
            BlackoutWindow(start=start, end=end, reason="after hours")

    def test_padded_bound_is_accepted(self) -> None:
        bw = BlackoutWindow(start=" 9:05", end="23:59 ")
        assert bw.contains(datetime(2025, 1, 6, 9, 5, 0)) is True


# ---------------------------------------------------------------------------
# Progressive severity
# ---------------------------------------------------------------------------


class TestProgressiveSeverity:
    """Severity increases after consecutive successes."""

    def test_initial_severity(self) -> None:
        prog = ProgressiveConfig(
            initial_severity=0.2, max_severity=0.8,
            step_increase=0.1, increase_after_success_count=3,
        )
        sched = _make_schedule(progressive=prog)
        scheduler = ChaosScheduler([sched])
        assert scheduler.get_current_severity("s1") == pytest.approx(0.2)

    def test_severity_increases_after_successes(self) -> None:
        prog = ProgressiveConfig(
            initial_severity=0.2, max_severity=0.8,
            step_increase=0.1, increase_after_success_count=3,
        )
        sched = _make_schedule(progressive=prog)
        scheduler = ChaosScheduler([sched])

        for _ in range(3):
            scheduler.record_execution(_make_execution("s1", result="pass"))
        assert scheduler.get_current_severity("s1") == pytest.approx(0.3)

    def test_failure_resets_consecutive_count(self) -> None:
        prog = ProgressiveConfig(
            initial_severity=0.2, max_severity=0.8,
            step_increase=0.1, increase_after_success_count=3,
        )
        sched = _make_schedule(progressive=prog)
        scheduler = ChaosScheduler([sched])

        for _ in range(3):
            scheduler.record_execution(_make_execution("s1", result="pass"))
        scheduler.record_execution(_make_execution("s1", result="fail"))
        # Back to initial after failure breaks the streak
        assert scheduler.get_current_severity("s1") == pytest.approx(0.2)

    def test_severity_capped_at_max(self) -> None:
        prog = ProgressiveConfig(
            initial_severity=0.2, max_severity=0.5,
            step_increase=0.1, increase_after_success_count=1,
        )
        sched = _make_schedule(progressive=prog)
        scheduler = ChaosScheduler([sched])

        for _ in range(20):
            scheduler.record_execution(_make_execution("s1", result="pass"))
        assert scheduler.get_current_severity("s1") == pytest.approx(0.5)

    def test_no_progressive_config_returns_full_severity(self) -> None:
        sched = _make_schedule(progressive=None)
        scheduler = ChaosScheduler([sched])
        assert scheduler.get_current_severity("s1") == 1.0


# ---------------------------------------------------------------------------
# Resilience trend
# ---------------------------------------------------------------------------


class TestResilienceTrend:
    """Resilience trend tracking over execution history."""

    def test_empty_history(self) -> None:
        sched = _make_schedule()
        scheduler = ChaosScheduler([sched])
        assert scheduler.get_resilience_trend("s1") == []

    def test_trend_returns_last_n_scores(self) -> None:
        sched = _make_schedule()
        scheduler = ChaosScheduler([sched])
        scores = [0.5, 0.6, 0.7, 0.8, 0.9]
        for score in scores:
            scheduler.record_execution(
                _make_execution("s1", resilience=score)
            )
        assert scheduler.get_resilience_trend("s1", window=3) == [0.7, 0.8, 0.9]

    def test_trend_with_fewer_than_window(self) -> None:
        sched = _make_schedule()
        scheduler = ChaosScheduler([sched])
        scheduler.record_execution(_make_execution("s1", resilience=0.75))
        assert scheduler.get_resilience_trend("s1", window=10) == [0.75]


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


class TestYAMLLoading:
    """Load schedules from YAML config files."""

    def test_load_example_schedules(self, tmp_path: object) -> None:
        from pathlib import Path

        example = Path(__file__).resolve().parent.parent / "examples" / "chaos" / "schedules.yaml"
        schedules = load_schedules(example)
        assert len(schedules) == 4
        ids = {s.id for s in schedules}
        assert "weekday-tool-timeout" in ids
        assert "disabled-cost-test" in ids

    def test_load_with_progressive_config(self, tmp_path: object) -> None:
        from pathlib import Path

        example = Path(__file__).resolve().parent.parent / "examples" / "chaos" / "schedules.yaml"
        schedules = load_schedules(example)
        weekday = next(s for s in schedules if s.id == "weekday-tool-timeout")
        assert weekday.progressive_config is not None
        assert weekday.progressive_config.initial_severity == 0.2

    def test_load_custom_yaml(self, tmp_path: object) -> None:
        from pathlib import Path

        content = """
schedules:
  - id: custom-1
    name: Custom
    experiment_id: test-exp
    cron_expression: "0 8 * * *"
    enabled: true
"""
        p = Path(str(tmp_path)) / "custom.yaml"
        p.write_text(content)
        schedules = load_schedules(p)
        assert len(schedules) == 1
        assert schedules[0].id == "custom-1"

    def test_load_rejects_unreadable_blackout_bound(self, tmp_path: object) -> None:
        from pathlib import Path

        content = """
schedules:
  - id: custom-1
    name: Custom
    experiment_id: test-exp
    cron_expression: "0 8 * * *"
    blackout_windows:
      - start: "17:00"
        end: "24:00"
"""
        p = Path(str(tmp_path)) / "custom.yaml"
        p.write_text(content)
        with pytest.raises(ValueError, match="hour must be in 0..23"):
            load_schedules(p)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Disabled schedules, unknown IDs, all-blackout."""

    def test_disabled_schedule_never_runs(self) -> None:
        sched = _make_schedule(enabled=False)
        scheduler = ChaosScheduler([sched])
        assert scheduler.should_run("s1", MONDAY_9AM) is False

    def test_unknown_schedule_id(self) -> None:
        scheduler = ChaosScheduler([])
        assert scheduler.should_run("nonexistent", MONDAY_9AM) is False

    def test_unknown_schedule_severity_is_zero(self) -> None:
        scheduler = ChaosScheduler([])
        assert scheduler.get_current_severity("nonexistent") == 0.0

    def test_all_day_blackout(self) -> None:
        bw = BlackoutWindow(start="00:00", end="23:59", reason="full blackout")
        sched = _make_schedule(cron="0 9 * * 1-5", blackouts=[bw])
        scheduler = ChaosScheduler([sched])
        # Schedule matches cron but is blocked by blackout
        assert scheduler.should_run("s1", MONDAY_9AM) is False

    def test_get_due_schedules(self) -> None:
        s1 = _make_schedule(schedule_id="a", cron="0 9 * * 1-5")
        s2 = _make_schedule(schedule_id="b", cron="0 14 * * 3")
        scheduler = ChaosScheduler([s1, s2])
        due = scheduler.get_due_schedules(MONDAY_9AM)
        ids = {s.id for s in due}
        assert "a" in ids
        assert "b" not in ids  # Wednesday-only schedule
