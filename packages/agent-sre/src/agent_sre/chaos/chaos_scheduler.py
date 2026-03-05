# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Chaos scheduler — manual trigger only in Community Edition.

Cron-based scheduling is not available. Use manual triggering instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from agent_sre.chaos.scheduler import (
        ChaosSchedule,
        ScheduleExecution,
    )


class ChaosScheduler:
    """Manages chaos experiment schedules (manual trigger only in Community Edition)."""

    def __init__(self, schedules: list[ChaosSchedule] | None = None) -> None:
        self._schedules: dict[str, ChaosSchedule] = {
            s.id: s for s in (schedules or [])
        }
        self._executions: dict[str, list[ScheduleExecution]] = {}

    def should_run(self, schedule_id: str, now: datetime | None = None) -> bool:
        """Check if a schedule should fire — not available in Community Edition."""
        raise NotImplementedError(
            "Cron-based scheduling is not available in Community Edition. "
            "Use manual triggering instead."
        )

    def get_due_schedules(self, now: datetime | None = None) -> list[ChaosSchedule]:
        """Return all schedules that are due — not available in Community Edition."""
        raise NotImplementedError(
            "Cron-based scheduling is not available in Community Edition. "
            "Use manual triggering instead."
        )

    def is_in_blackout(self, schedule: ChaosSchedule, now: datetime | None = None) -> bool:
        """Check if in blackout window — not available in Community Edition."""
        raise NotImplementedError(
            "Cron-based scheduling is not available in Community Edition."
        )

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
