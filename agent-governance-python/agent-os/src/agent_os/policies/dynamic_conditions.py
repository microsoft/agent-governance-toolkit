# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from agent_os.policies.schema import DynamicConditionType, PolicyRule


def _parse_hhmm(value: str) -> tuple[int, int]:
    parts = value.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid HH:MM time value: {value}")
    hour = int(parts[0])
    minute = int(parts[1])
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        raise ValueError(f"Invalid HH:MM time value: {value}")
    return hour, minute


def _parse_window_seconds(value: str) -> int:
    if not value:
        raise ValueError("Window string is required")
    unit = value[-1]
    amount = int(value[:-1])
    if amount <= 0:
        raise ValueError("Window amount must be > 0")
    if unit == "m":
        return amount * 60
    if unit == "h":
        return amount * 3600
    if unit == "d":
        return amount * 86400
    raise ValueError(f"Unsupported window unit in: {value}")


def _coerce_timestamp(value: object | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        # Accept either RFC3339-like values or trailing Z timestamps.
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    raise ValueError(f"Unsupported timestamp type: {type(value)!r}")


@dataclass
class _WindowState:
    window_start_epoch: int
    value: float


class DynamicBudgetTracker:
    """Thread-safe in-memory per-rule budget tracker for v1 dynamic conditions."""

    def __init__(self) -> None:
        self._lock = Lock()
        # V1 limitation: budget state is process-local only. No persistence or
        # cross-worker coordination is provided by this tracker.
        self._state: dict[str, _WindowState] = {}

    def consume(
        self,
        *,
        rule_name: str,
        metric_name: str,
        window_seconds: int,
        current_timestamp: datetime,
        amount: float,
        limit: float,
    ) -> bool:
        bucket_start = int(current_timestamp.timestamp()) // window_seconds * window_seconds
        bucket_key = f"{rule_name}:{metric_name}:{window_seconds}"
        with self._lock:
            # V1 limitation: retention follows rollover behavior only.
            # Eviction, durability, and production-grade accounting are
            # intentionally deferred outside v1 scope.
            previous = self._state.get(bucket_key)
            if previous is None or previous.window_start_epoch != bucket_start:
                previous = _WindowState(window_start_epoch=bucket_start, value=0.0)
            next_value = previous.value + amount
            self._state[bucket_key] = _WindowState(
                window_start_epoch=bucket_start,
                value=next_value,
            )
            return next_value <= limit


class DynamicConditionEvaluator:
    """Evaluates optional v1 dynamic conditions for rules.

    This evaluator is additive: if a rule has no dynamic condition, it returns True.
    """

    def __init__(self, budget_tracker: DynamicBudgetTracker | None = None) -> None:
        self._budget_tracker = budget_tracker or DynamicBudgetTracker()

    def evaluate(self, rule: PolicyRule, dynamic_context: dict | None = None) -> bool:
        condition = rule.dynamic_condition
        if condition is None:
            return True
        context = dynamic_context or {}
        try:
            if condition.type == DynamicConditionType.TIME_WINDOW:
                return self._evaluate_time_window(
                    condition.timezone,
                    condition.start_time,
                    condition.end_time,
                    condition.days_of_week,
                    context,
                )
            if condition.type == DynamicConditionType.DAY_OF_WEEK:
                return self._evaluate_day_of_week(
                    condition.timezone,
                    condition.days_of_week,
                    context,
                )
            if condition.type == DynamicConditionType.TOKEN_COUNT_PER_WINDOW:
                return self._evaluate_budget_window(
                    rule_name=rule.name,
                    metric_name="token_count",
                    window=condition.window,
                    limit=float(condition.limit),
                    context=context,
                )
            if condition.type == DynamicConditionType.COST_PER_WINDOW:
                return self._evaluate_budget_window(
                    rule_name=rule.name,
                    metric_name="cost",
                    window=condition.window,
                    limit=float(condition.limit),
                    context=context,
                )
            return False
        except ValueError:
            return False

    def _resolve_local_time(self, timezone: str | None, context: dict) -> datetime:
        tz_name = timezone or "UTC"
        if tz_name.upper() == "UTC":
            tzinfo = UTC
        else:
            try:
                tzinfo = ZoneInfo(tz_name)
            except ZoneInfoNotFoundError as exc:
                raise ValueError(f"Unknown timezone: {tz_name}") from exc

        ts_source = context.get("timestamp")
        utc_now = _coerce_timestamp(ts_source)
        return utc_now.astimezone(tzinfo)

    def _evaluate_day_of_week(self, timezone: str | None, days_of_week: list[int] | None, context: dict) -> bool:
        if not days_of_week:
            return False
        local_time = self._resolve_local_time(timezone, context)
        return local_time.isoweekday() in days_of_week

    def _evaluate_time_window(
        self,
        timezone: str | None,
        start_time: str | None,
        end_time: str | None,
        days_of_week: list[int] | None,
        context: dict,
    ) -> bool:
        if start_time is None or end_time is None:
            return False
        local_time = self._resolve_local_time(timezone, context)
        if days_of_week and local_time.isoweekday() not in days_of_week:
            return False

        start_hour, start_minute = _parse_hhmm(start_time)
        end_hour, end_minute = _parse_hhmm(end_time)
        current_minutes = local_time.hour * 60 + local_time.minute
        start_minutes = start_hour * 60 + start_minute
        end_minutes = end_hour * 60 + end_minute

        # Inclusive start, exclusive end. If start>end, the window wraps midnight.
        if start_minutes <= end_minutes:
            return start_minutes <= current_minutes < end_minutes
        return current_minutes >= start_minutes or current_minutes < end_minutes

    def _evaluate_budget_window(
        self,
        *,
        rule_name: str,
        metric_name: str,
        window: str | None,
        limit: float,
        context: dict,
    ) -> bool:
        if not window:
            return False
        window_seconds = _parse_window_seconds(window)
        budget = context.get("budget") or {}
        amount = budget.get(metric_name, 0)
        try:
            amount_value = float(amount)
        except (TypeError, ValueError):
            return False
        current_timestamp = _coerce_timestamp(context.get("timestamp"))
        return self._budget_tracker.consume(
            rule_name=rule_name,
            metric_name=metric_name,
            window_seconds=window_seconds,
            current_timestamp=current_timestamp,
            amount=amount_value,
            limit=limit,
        )
