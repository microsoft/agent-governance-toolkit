# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Dynamic policy context for Agent-OS governance.

Carries runtime-dependent information such as the current time, session cost,
API quota, and system load. Hosts can project these values into ACS snapshots::

    context.time.hour
    context.cost.budget_remaining
    context.quota.api_calls_remaining
    context.system.load

Dynamic context is host-owned and strictly additive.
"""

from __future__ import annotations

import time as _time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class TimeContext:
    """Temporal context for time-based policy conditions.

    Attributes:
        timestamp: Unix epoch seconds (UTC).
        hour: Hour of day in the requested timezone (0-23).
        day_of_week: ISO weekday - 1 = Monday, 7 = Sunday.
        timezone: IANA timezone name used for local fields (default UTC).
    """

    timestamp: int = field(default_factory=lambda: int(_time.time()))
    hour: int = field(default=0)
    day_of_week: int = field(default=1)
    timezone: str = "UTC"

    @classmethod
    def now(cls, tz_name: str = "UTC") -> TimeContext:
        """Build a TimeContext for the current moment."""
        ts = int(_time.time())
        try:
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
            try:
                tz = ZoneInfo(tz_name)
            except ZoneInfoNotFoundError:
                tz = timezone.utc
                tz_name = "UTC"
        except ImportError:
            tz = timezone.utc
            tz_name = "UTC"

        now = datetime.fromtimestamp(ts, tz=tz)
        return cls(
            timestamp=ts,
            hour=now.hour,
            day_of_week=now.isoweekday(),
            timezone=tz_name,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "hour": self.hour,
            "day_of_week": self.day_of_week,
            "timezone": self.timezone,
        }


@dataclass
class CostContext:
    """Budget / cost context for cost-aware policy conditions.

    Attributes:
        budget_total: Total allocated budget (currency-neutral units).
        budget_used: Amount spent so far this period.
        budget_remaining: Remaining budget (total - used).
    """

    budget_total: float = 0.0
    budget_used: float = 0.0
    budget_remaining: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_total": self.budget_total,
            "budget_used": self.budget_used,
            "budget_remaining": self.budget_remaining,
        }


@dataclass
class QuotaContext:
    """API quota context for rate-limit-aware policy conditions.

    Attributes:
        api_calls_remaining: Remaining API calls in the current window.
        rate_limit_remaining: Remaining requests before hitting the rate limit.
    """

    api_calls_remaining: int = 0
    rate_limit_remaining: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_calls_remaining": self.api_calls_remaining,
            "rate_limit_remaining": self.rate_limit_remaining,
        }


@dataclass
class SystemContext:
    """System health context for load-adaptive policy conditions.

    Attributes:
        load: Normalised CPU / resource load (0.0 = idle, 1.0 = fully loaded).
        error_rate: Fraction of recent requests that resulted in errors (0.0-1.0).
    """

    load: float = 0.0
    error_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "load": self.load,
            "error_rate": self.error_rate,
        }


@dataclass
class DynamicContext:
    """Runtime context injected into policy evaluation alongside action properties.

    All sub-contexts are optional.  When a sub-context is omitted (None),
    its dot-notation fields are absent from the merged evaluation context
    and rules referencing them will not match, preserving backward compat.

    Usage::

        ctx = DynamicContext(
            time=TimeContext.now("America/New_York"),
            cost=CostContext(budget_total=1000.0, budget_used=950.0, budget_remaining=50.0),
        )
        decision = evaluator.evaluate(action_context, dynamic_context=ctx)

    Merged evaluation dict contains all action context keys at the top
    level plus prefixed dynamic keys::

        context.time.hour
        context.time.day_of_week
        context.time.timestamp
        context.time.timezone
        context.cost.budget_total
        context.cost.budget_used
        context.cost.budget_remaining
        context.quota.api_calls_remaining
        context.quota.rate_limit_remaining
        context.system.load
        context.system.error_rate
    """

    time: TimeContext | None = None
    cost: CostContext | None = None
    quota: QuotaContext | None = None
    system: SystemContext | None = None

    def to_flat_dict(self) -> dict[str, Any]:
        """Return a flat dict of prefixed keys for merging into the action context.

        Only sub-contexts that are not None are included so that missing
        context does not shadow action-context fields with the same name.
        """
        flat: dict[str, Any] = {}
        if self.time is not None:
            for k, v in self.time.to_dict().items():
                flat[f"context.time.{k}"] = v
        if self.cost is not None:
            for k, v in self.cost.to_dict().items():
                flat[f"context.cost.{k}"] = v
        if self.quota is not None:
            for k, v in self.quota.to_dict().items():
                flat[f"context.quota.{k}"] = v
        if self.system is not None:
            for k, v in self.system.to_dict().items():
                flat[f"context.system.{k}"] = v
        return flat

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DynamicContext:
        """Build a DynamicContext from a plain dict (e.g. from JSON/YAML config).

        Unknown keys are silently ignored for forward compatibility.
        """
        time_ctx: TimeContext | None = None
        cost_ctx: CostContext | None = None
        quota_ctx: QuotaContext | None = None
        system_ctx: SystemContext | None = None

        if "time" in data and isinstance(data["time"], dict):
            t = data["time"]
            time_ctx = TimeContext(
                timestamp=int(t.get("timestamp", int(_time.time()))),
                hour=int(t.get("hour", 0)),
                day_of_week=int(t.get("day_of_week", 1)),
                timezone=str(t.get("timezone", "UTC")),
            )

        if "cost" in data and isinstance(data["cost"], dict):
            c = data["cost"]
            cost_ctx = CostContext(
                budget_total=float(c.get("budget_total", 0.0)),
                budget_used=float(c.get("budget_used", 0.0)),
                budget_remaining=float(c.get("budget_remaining", 0.0)),
            )

        if "quota" in data and isinstance(data["quota"], dict):
            q = data["quota"]
            quota_ctx = QuotaContext(
                api_calls_remaining=int(q.get("api_calls_remaining", 0)),
                rate_limit_remaining=int(q.get("rate_limit_remaining", 0)),
            )

        if "system" in data and isinstance(data["system"], dict):
            s = data["system"]
            system_ctx = SystemContext(
                load=float(s.get("load", 0.0)),
                error_rate=float(s.get("error_rate", 0.0)),
            )

        return cls(time=time_ctx, cost=cost_ctx, quota=quota_ctx, system=system_ctx)
