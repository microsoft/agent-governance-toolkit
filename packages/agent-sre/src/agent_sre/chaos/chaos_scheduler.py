# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Chaos scheduler — cron-based scheduling with blackout windows.

Supports cron-based schedule matching, blackout window enforcement,
and progressive severity escalation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from croniter import croniter

if TYPE_CHECKING:
    from agent_sre.chaos.scheduler import (
        ChaosSchedule,
        ScheduleExecution,
    )


class ChaosScheduler:
    """Manages chaos experiment schedules with cron matching and blackout windows."""

    def __init__(self, schedules: list[ChaosSchedule] | None = None) -> None:
        self._schedules: dict[str, ChaosSchedule] = {
            s.id: s for s in (schedules or [])
        }
        self._executions: dict[str, list[ScheduleExecution]] = {}

    def should_run(self, schedule_id: str, now: datetime | None = None) -> bool:
        """Check if a schedule should fire at the given time.

        Evaluates the cron expression against the current time,
        checks that the schedule is enabled, and verifies it is
        not in a blackout window.

        Args:
            schedule_id: Identifier of the schedule to check.
            now: Point in time to evaluate. Defaults to UTC now.

        Returns:
            True if the schedule's cron expression matches *now*,
            the schedule is enabled, and *now* is not inside a
            blackout window. False otherwise.
        """
        schedule = self._schedules.get(schedule_id)
        if schedule is None:
            return False

        if not schedule.enabled:
            return False

        now = now or datetime.now(tz=timezone.utc)

        # Check blackout first
        if self.is_in_blackout(schedule, now):
            return False

        # Use croniter.match to check if 'now' matches the cron expression
        return croniter.match(schedule.cron_expression, now)

    def get_due_schedules(self, now: datetime | None = None) -> list[ChaosSchedule]:
        """Return all schedules that are due to run at the given time.

        Args:
            now: Point in time to evaluate. Defaults to UTC now.

        Returns:
            List of enabled ChaosSchedule objects whose cron expression
            matches *now* and that are not in a blackout window.
        """
        now = now or datetime.now(tz=timezone.utc)
        return [
            schedule
            for schedule in self._schedules.values()
            if self.should_run(schedule.id, now)
        ]

    def is_in_blackout(self, schedule: ChaosSchedule, now: datetime | None = None) -> bool:
        """Check if the current time falls within any blackout window.

        Args:
            schedule: The schedule whose blackout windows to check.
            now: Point in time to evaluate. Defaults to UTC now.

        Returns:
            True if *now* falls inside any of the schedule's
            blackout windows (supports midnight-wrap).
        """
        now = now or datetime.now(tz=timezone.utc)
        return any(bw.contains(now) for bw in schedule.blackout_windows)

    def get_current_severity(self, schedule_id: str) -> float:
        """Compute current severity based on progressive config and execution history."""
        schedule = self._schedules.get(schedule_id)
        if schedule is None:
            return 0.0

        config = schedule.progressive_config
        if config is None:
            return 1.0

        history = self._executions.get(schedule_id, [])
        consecutive_successes = 0
        for ex in reversed(history):
            if ex.result == "pass":
                consecutive_successes += 1
            else:
                break

        steps = consecutive_successes // config.increase_after_success_count
        severity = config.initial_severity + steps * config.step_increase
        return min(severity, config.max_severity)

    def record_execution(self, execution: ScheduleExecution) -> None:
        """Record an execution result."""
        self._executions.setdefault(execution.schedule_id, []).append(execution)

    def get_resilience_trend(self, schedule_id: str, window: int = 10) -> list[float]:
        """Return the last N fault impact scores for a schedule."""
        history = self._executions.get(schedule_id, [])
        return [ex.resilience_score for ex in history[-window:]]
