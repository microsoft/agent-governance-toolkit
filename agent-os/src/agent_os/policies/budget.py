# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Budget policy rules for token, cost, and tool-call limits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class BudgetPolicy:
    """Resource consumption limits for a governed task."""

    max_tokens: Optional[int] = None
    max_tool_calls: Optional[int] = None
    max_cost_usd: Optional[float] = None
    max_duration_seconds: Optional[float] = None


@dataclass
class BudgetTracker:
    """Tracks resource consumption against a BudgetPolicy.

    Example::

        policy = BudgetPolicy(max_tokens=8000, max_tool_calls=20)
        tracker = BudgetTracker(policy)
        tracker.record_tokens(1500)
        tracker.record_tool_call()
        if tracker.is_exceeded():
            print(tracker.exceeded_reasons())
    """

    policy: BudgetPolicy
    tokens_used: int = 0
    tool_calls_used: int = 0
    cost_usd_used: float = 0.0
    duration_seconds_used: float = 0.0

    def record_tokens(self, count: int) -> None:
        self.tokens_used += count

    def record_tool_call(self) -> None:
        self.tool_calls_used += 1

    def record_cost(self, amount: float) -> None:
        self.cost_usd_used += amount

    def record_duration(self, seconds: float) -> None:
        self.duration_seconds_used += seconds

    def is_exceeded(self) -> bool:
        return len(self.exceeded_reasons()) > 0

    def exceeded_reasons(self) -> list[str]:
        reasons = []
        p = self.policy
        if p.max_tokens is not None and self.tokens_used > p.max_tokens:
            reasons.append(f"tokens: {self.tokens_used}/{p.max_tokens}")
        if p.max_tool_calls is not None and self.tool_calls_used > p.max_tool_calls:
            reasons.append(f"tool_calls: {self.tool_calls_used}/{p.max_tool_calls}")
        if p.max_cost_usd is not None and self.cost_usd_used > p.max_cost_usd:
            reasons.append(f"cost: ${self.cost_usd_used:.2f}/${p.max_cost_usd:.2f}")
        if p.max_duration_seconds is not None and self.duration_seconds_used > p.max_duration_seconds:
            reasons.append(f"duration: {self.duration_seconds_used:.1f}s/{p.max_duration_seconds:.1f}s")
        return reasons

    def remaining(self) -> dict[str, float | int | None]:
        p = self.policy
        return {
            "tokens": (p.max_tokens - self.tokens_used) if p.max_tokens else None,
            "tool_calls": (p.max_tool_calls - self.tool_calls_used) if p.max_tool_calls else None,
            "cost_usd": round(p.max_cost_usd - self.cost_usd_used, 4) if p.max_cost_usd else None,
            "duration_seconds": round(p.max_duration_seconds - self.duration_seconds_used, 1) if p.max_duration_seconds else None,
        }

    def utilization(self) -> dict[str, float | None]:
        p = self.policy
        return {
            "tokens": round(self.tokens_used / p.max_tokens, 3) if p.max_tokens else None,
            "tool_calls": round(self.tool_calls_used / p.max_tool_calls, 3) if p.max_tool_calls else None,
            "cost_usd": round(self.cost_usd_used / p.max_cost_usd, 3) if p.max_cost_usd else None,
            "duration_seconds": round(self.duration_seconds_used / p.max_duration_seconds, 3) if p.max_duration_seconds else None,
        }
