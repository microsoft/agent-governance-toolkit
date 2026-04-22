# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Context Budget Scheduler — token budget as a kernel primitive.

Makes the "Scale by Subtraction" philosophy (90 % lookup, 10 % reasoning)
concrete and enforced.  The kernel owns the budget; agents cannot exceed it.

Closes #207.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

class AgentSignal(Enum):
    """Kernel signals for context budget enforcement."""

    SIGSTOP = auto()    # Budget exceeded — halt the agent
    SIGWARN = auto()    # Budget nearing limit
    SIGRESUME = auto()  # Budget replenished


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ContextWindow:
    """An allocated context window for an agent task."""

    agent_id: str
    task: str
    lookup_budget: int       # tokens for retrieval / facts
    reasoning_budget: int    # tokens for LLM reasoning
    total: int               # lookup + reasoning
    created_at: float = field(default_factory=time.time)

    @property
    def lookup_ratio(self) -> float:
        return self.lookup_budget / self.total if self.total else 0.0

    @property
    def reasoning_ratio(self) -> float:
        return self.reasoning_budget / self.total if self.total else 0.0


class ContextPriority(Enum):
    """Task priority levels for context allocation."""

    CRITICAL = 3   # Gets full allocation even if pool is tight
    HIGH = 2
    NORMAL = 1
    LOW = 0        # Smallest possible allocation


@dataclass
class UsageRecord:
    """Tracks actual token usage by an agent."""

    agent_id: str
    window: ContextWindow
    lookup_used: int = 0
    reasoning_used: int = 0
    started_at: float = field(default_factory=time.time)
    stopped: bool = False
    stop_reason: str | None = None

    @property
    def total_used(self) -> int:
        return self.lookup_used + self.reasoning_used

    @property
    def remaining(self) -> int:
        return max(0, self.window.total - self.total_used)

    @property
    def utilization(self) -> float:
        return self.total_used / self.window.total if self.window.total else 0.0


# ---------------------------------------------------------------------------
# Budget Exceeded Error
# ---------------------------------------------------------------------------

class BudgetExceeded(Exception):
    """Raised when an agent exceeds its context budget."""

    def __init__(self, agent_id: str, budget: int, used: int) -> None:
        self.agent_id = agent_id
        self.budget = budget
        self.used = used
        super().__init__(
            f"Agent {agent_id} exceeded context budget: {used}/{budget} tokens"
        )


# ---------------------------------------------------------------------------
# Context Budget Scheduler
# ---------------------------------------------------------------------------

# Default minimum context sizes per priority (tokens)
_MIN_CONTEXT: dict[ContextPriority, int] = {
    ContextPriority.CRITICAL: 4000,
    ContextPriority.HIGH: 2000,
    ContextPriority.NORMAL: 1000,
    ContextPriority.LOW: 500,
}


class ContextScheduler:
    """
    Kernel primitive that governs how context budget is allocated.

    Like CPU scheduling but for token budgets.  Enforces the 90/10
    (lookup/reasoning) split and emits SIGSTOP when an agent goes
    over budget.

    Parameters
    ----------
    total_budget : int
        Global token pool (shared across all active agents).
    lookup_ratio : float
        Fraction of each allocation devoted to lookup (default 0.90).
    warn_threshold : float
        Fraction of budget at which SIGWARN fires (default 0.85).
    """

    def __init__(
        self,
        total_budget: int = 8000,
        lookup_ratio: float = 0.90,
        warn_threshold: float = 0.85,
    ) -> None:
        if not 0.0 < lookup_ratio < 1.0:
            raise ValueError("lookup_ratio must be between 0 and 1 exclusive")
        if total_budget < 1:
            raise ValueError("total_budget must be positive")

        self.total_budget = total_budget
        self.lookup_ratio = lookup_ratio
        self.warn_threshold = warn_threshold

        self._active: dict[str, UsageRecord] = {}
        self._history: list[UsageRecord] = []
        self._signal_handlers: dict[AgentSignal, list[Callable]] = {
            s: [] for s in AgentSignal
        }

    # -- Allocation -----------------------------------------------------------

    def allocate(
        self,
        agent_id: str,
        task: str,
        priority: ContextPriority = ContextPriority.NORMAL,
        max_tokens: int | None = None,
    ) -> ContextWindow:
        """
        Allocate a context window for *agent_id*.

        The scheduler decides the actual size based on remaining pool
        capacity and the task priority.
        """
        available = self._available_tokens()
        minimum = _MIN_CONTEXT[priority]

        if max_tokens is not None:
            desired = min(max_tokens, available)
        else:
            # Scale by priority
            desired = min(
                int(self.total_budget * (0.25 + 0.25 * priority.value)),
                available,
            )

        # Ensure at least the minimum (or whatever is left),
        # but never exceed an explicit max_tokens cap.
        if max_tokens is not None:
            allocated = min(desired, max_tokens)
        else:
            allocated = max(minimum, desired) if available >= minimum else available

        lookup = int(allocated * self.lookup_ratio)
        reasoning = allocated - lookup

        window = ContextWindow(
            agent_id=agent_id,
            task=task,
            lookup_budget=lookup,
            reasoning_budget=reasoning,
            total=allocated,
        )

        self._active[agent_id] = UsageRecord(agent_id=agent_id, window=window)
        return window

    # -- Usage tracking -------------------------------------------------------

    def record_usage(
        self,
        agent_id: str,
        lookup_tokens: int = 0,
        reasoning_tokens: int = 0,
    ) -> UsageRecord:
        """
        Record token usage for an active allocation.

        Emits SIGWARN or SIGSTOP as thresholds are crossed.
        """
        rec = self._active.get(agent_id)
        if rec is None:
            raise KeyError(f"No active allocation for agent {agent_id}")
        if rec.stopped:
            raise BudgetExceeded(agent_id, rec.window.total, rec.total_used)

        rec.lookup_used += lookup_tokens
        rec.reasoning_used += reasoning_tokens

        # Check thresholds
        utilization = rec.utilization
        if utilization >= 1.0:
            rec.stopped = True
            rec.stop_reason = "budget_exceeded"
            self._emit(AgentSignal.SIGSTOP, agent_id)
            raise BudgetExceeded(agent_id, rec.window.total, rec.total_used)
        elif utilization >= self.warn_threshold:
            self._emit(AgentSignal.SIGWARN, agent_id)

        return rec

    def release(self, agent_id: str) -> UsageRecord | None:
        """Release an allocation and move it to history."""
        rec = self._active.pop(agent_id, None)
        if rec is not None:
            self._history.append(rec)
        return rec

    # -- Queries --------------------------------------------------------------

    def get_usage(self, agent_id: str) -> UsageRecord | None:
        return self._active.get(agent_id)

    @property
    def active_agents(self) -> list[str]:
        return list(self._active.keys())

    @property
    def active_count(self) -> int:
        return len(self._active)

    def _available_tokens(self) -> int:
        used = sum(r.window.total for r in self._active.values())
        return max(0, self.total_budget - used)

    @property
    def available_tokens(self) -> int:
        return self._available_tokens()

    @property
    def utilization(self) -> float:
        """Global pool utilization (0.0 – 1.0)."""
        allocated = sum(r.window.total for r in self._active.values())
        return allocated / self.total_budget if self.total_budget else 0.0

    def get_health_report(self) -> dict[str, Any]:
        """Return a summary of scheduler state."""
        return {
            "total_budget": self.total_budget,
            "available": self._available_tokens(),
            "utilization": round(self.utilization, 3),
            "active_agents": self.active_count,
            "lookup_ratio": self.lookup_ratio,
            "agents": {
                aid: {
                    "task": r.window.task,
                    "allocated": r.window.total,
                    "used": r.total_used,
                    "remaining": r.remaining,
                    "stopped": r.stopped,
                }
                for aid, r in self._active.items()
            },
            "history_count": len(self._history),
        }

    # -- Signal system --------------------------------------------------------

    def on_signal(self, signal: AgentSignal, handler: Callable) -> None:
        """Register a handler for *signal*."""
        self._signal_handlers[signal].append(handler)

    def _emit(self, signal: AgentSignal, agent_id: str) -> None:
        for handler in self._signal_handlers[signal]:
            try:
                handler(agent_id, signal)
            except Exception:  # noqa: S110 — best-effort signal handler invocation
                pass
