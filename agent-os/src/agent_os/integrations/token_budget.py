# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Token Budget Tracking with Warnings

Tracks token usage per agent and fires warnings when approaching limits.
Integrates with GovernancePolicy for budget configuration.
"""

import threading
from dataclasses import dataclass
from typing import Callable, Optional

from .base import GovernancePolicy


@dataclass(frozen=True)
class TokenBudgetStatus:
    """Snapshot of an agent's token budget status."""
    used: int
    limit: int
    remaining: int
    percentage: float
    is_warning: bool
    is_exceeded: bool


@dataclass
class _AgentUsage:
    """Internal mutable record of per-agent token consumption."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class TokenBudgetTracker:
    """Thread-safe token budget tracker with configurable warning thresholds.

    Args:
        max_tokens: Global default budget. Overridden per-agent by GovernancePolicy.
        warning_threshold: Fraction of budget (0.0-1.0) at which ``is_warning`` activates.
        policy: Optional GovernancePolicy whose ``max_tokens`` is used as the default limit.
        on_warning: Optional callback ``(agent_id, status)`` fired when a warning threshold is crossed.
    """

    def __init__(
        self,
        max_tokens: int = 4096,
        warning_threshold: float = 0.8,
        policy: Optional[GovernancePolicy] = None,
        on_warning: Optional[Callable[[str, TokenBudgetStatus], None]] = None,
    ) -> None:
        if not 0.0 <= warning_threshold <= 1.0:
            raise ValueError("warning_threshold must be between 0.0 and 1.0")
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        self._max_tokens = policy.max_tokens if policy is not None else max_tokens
        self._warning_threshold = warning_threshold
        self._on_warning = on_warning
        self._lock = threading.Lock()
        self._usage: dict[str, _AgentUsage] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_usage(
        self, agent_id: str, prompt_tokens: int, completion_tokens: int
    ) -> TokenBudgetStatus:
        """Record token consumption and return the updated status.

        Fires the ``on_warning`` callback the first time the warning
        threshold is crossed for a given recording.
        """
        with self._lock:
            usage = self._usage.setdefault(agent_id, _AgentUsage())
            was_warning = usage.total_tokens >= self._max_tokens * self._warning_threshold

            usage.prompt_tokens += prompt_tokens
            usage.completion_tokens += completion_tokens
            usage.total_tokens += prompt_tokens + completion_tokens

            status = self._build_status(usage)

        # Fire callback outside the lock to avoid deadlocks
        if status.is_warning and not was_warning and self._on_warning is not None:
            self._on_warning(agent_id, status)

        return status

    def get_usage(self, agent_id: str) -> TokenBudgetStatus:
        """Return current budget status for *agent_id*."""
        with self._lock:
            usage = self._usage.get(agent_id, _AgentUsage())
            return self._build_status(usage)

    def check_budget(self, agent_id: str) -> TokenBudgetStatus:
        """Alias for :meth:`get_usage` – check whether budget is healthy."""
        return self.get_usage(agent_id)

    def reset(self, agent_id: str) -> None:
        """Reset all tracked usage for *agent_id*."""
        with self._lock:
            self._usage.pop(agent_id, None)

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def format_status(self, agent_id: str) -> str:
        """Return a CLI-friendly progress bar, e.g. ``[████████░░] 82% (8,200/10,000 tokens)``."""
        status = self.get_usage(agent_id)
        filled = round(status.percentage / 10)
        bar = "█" * filled + "░" * (10 - filled)
        pct = round(status.percentage * 100)
        return f"[{bar}] {pct}% ({status.used:,}/{status.limit:,} tokens)"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_status(self, usage: _AgentUsage) -> TokenBudgetStatus:
        used = usage.total_tokens
        remaining = max(self._max_tokens - used, 0)
        pct = used / self._max_tokens if self._max_tokens else 0.0
        return TokenBudgetStatus(
            used=used,
            limit=self._max_tokens,
            remaining=remaining,
            percentage=pct,
            is_warning=pct >= self._warning_threshold,
            is_exceeded=used >= self._max_tokens,
        )
