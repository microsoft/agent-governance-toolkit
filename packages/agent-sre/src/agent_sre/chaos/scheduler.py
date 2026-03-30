# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Chaos schedule models — data models for schedule configuration."""

from __future__ import annotations

from datetime import datetime, time

from pydantic import BaseModel, Field


class BlackoutWindow(BaseModel):
    """Time window during which chaos experiments must not run."""

    start: str  # HH:MM or cron-like pattern
    end: str  # HH:MM or cron-like pattern
    reason: str = ""

    def contains(self, now: datetime) -> bool:
        """Check if the given datetime falls within this blackout window."""
        try:
            start_time = _parse_time(self.start)
            end_time = _parse_time(self.end)
        except ValueError:
            return False

        current_time = now.time()
        if start_time <= end_time:
            return start_time <= current_time <= end_time
        # Wraps midnight (e.g. 22:00 - 06:00)
        return current_time >= start_time or current_time <= end_time


class ProgressiveConfig(BaseModel):
    """Configuration for progressively increasing chaos severity."""

    initial_severity: float = Field(default=0.1, ge=0.0, le=1.0)
    max_severity: float = Field(default=1.0, ge=0.0, le=1.0)
    step_increase: float = Field(default=0.1, ge=0.0, le=1.0)
    increase_after_success_count: int = Field(default=3, ge=1)


class ChaosSchedule(BaseModel):
    """A scheduled chaos experiment with cron timing and safety controls."""

    id: str
    name: str
    experiment_id: str
    cron_expression: str
    enabled: bool = True
    blackout_windows: list[BlackoutWindow] = Field(default_factory=list)
    progressive_config: ProgressiveConfig | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class ScheduleExecution(BaseModel):
    """Record of a single chaos schedule execution."""

    schedule_id: str
    executed_at: datetime
    severity_used: float = Field(ge=0.0, le=1.0)
    result: str  # "pass" or "fail"
    resilience_score: float = Field(ge=0.0, le=1.0)


def _parse_time(value: str) -> time:
    """Parse HH:MM string to a time object."""
    parts = value.strip().split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid time format: {value}")
    return time(int(parts[0]), int(parts[1]))
