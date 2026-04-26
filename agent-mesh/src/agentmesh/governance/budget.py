# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Token and cost budget enforcement as a policy rule type.

Tracks per-agent token and monetary spend against configurable limits
within rolling time windows, and returns allow/deny decisions before
each LLM call.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional


_WINDOW_RE = re.compile(r"^(\d+)([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_window(window: str) -> float:
    """Convert a human-friendly window string to seconds."""
    m = _WINDOW_RE.match(window.strip())
    if not m:
        raise ValueError(
            f"Invalid window format {window!r}; expected e.g. '1h', '24h', '7d'"
        )
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


@dataclass
class BudgetConfig:
    """Budget limits for a single enforcement scope."""

    max_tokens: int = 100_000
    max_cost_usd: float = 10.0
    window: str = "1h"

    def window_seconds(self) -> float:
        return _parse_window(self.window)


@dataclass
class BudgetDecision:
    """Result of a budget check."""

    allowed: bool
    reason: str
    tokens_remaining: int
    cost_remaining: float


@dataclass
class _AgentUsage:
    """Internal mutable record for a single agent's usage."""

    tokens_used: int = 0
    cost_used: float = 0.0
    window_start: float = field(default_factory=time.time)


class BudgetTracker:
    """Tracks token/cost usage per agent and enforces limits.

    Usage is accumulated in a rolling window.  When the window expires
    the counters are automatically reset on the next access.
    """

    def __init__(self, config: BudgetConfig) -> None:
        self.config = config
        self._agents: dict[str, _AgentUsage] = {}
        self._window_secs = config.window_seconds()

    def _get_usage(self, agent_id: str) -> _AgentUsage:
        """Return the usage record, resetting if the window has expired."""
        now = time.time()
        usage = self._agents.get(agent_id)
        if usage is None:
            usage = _AgentUsage(window_start=now)
            self._agents[agent_id] = usage
            return usage
        if now - usage.window_start >= self._window_secs:
            usage.tokens_used = 0
            usage.cost_used = 0.0
            usage.window_start = now
        return usage

    def record_usage(
        self, agent_id: str, tokens: int, cost_usd: float = 0.0
    ) -> None:
        """Record that *agent_id* consumed *tokens* and *cost_usd*."""
        usage = self._get_usage(agent_id)
        usage.tokens_used += tokens
        usage.cost_used += cost_usd

    def check_budget(
        self, agent_id: str, estimated_tokens: int = 0
    ) -> BudgetDecision:
        """Check whether *agent_id* may proceed with an additional call.

        If *estimated_tokens* is provided, the check verifies that the
        agent would still be within budget after consuming that many tokens.
        """
        usage = self._get_usage(agent_id)
        projected_tokens = usage.tokens_used + estimated_tokens
        tokens_remaining = self.config.max_tokens - usage.tokens_used
        cost_remaining = self.config.max_cost_usd - usage.cost_used

        if projected_tokens > self.config.max_tokens:
            return BudgetDecision(
                allowed=False,
                reason=(
                    f"token budget exceeded: {projected_tokens} "
                    f"(used {usage.tokens_used} + estimated {estimated_tokens}) "
                    f"> limit {self.config.max_tokens}"
                ),
                tokens_remaining=max(tokens_remaining, 0),
                cost_remaining=max(cost_remaining, 0.0),
            )
        if usage.cost_used > self.config.max_cost_usd:
            return BudgetDecision(
                allowed=False,
                reason=(
                    f"cost budget exceeded: ${usage.cost_used:.4f} "
                    f"> limit ${self.config.max_cost_usd:.2f}"
                ),
                tokens_remaining=max(tokens_remaining, 0),
                cost_remaining=max(cost_remaining, 0.0),
            )
        return BudgetDecision(
            allowed=True,
            reason="within budget",
            tokens_remaining=max(tokens_remaining, 0),
            cost_remaining=max(cost_remaining, 0.0),
        )

    def get_usage(self, agent_id: str) -> dict:
        """Return a snapshot of current usage for *agent_id*."""
        usage = self._get_usage(agent_id)
        return {
            "tokens_used": usage.tokens_used,
            "cost_used": usage.cost_used,
            "remaining_tokens": max(
                self.config.max_tokens - usage.tokens_used, 0
            ),
            "remaining_cost": max(
                self.config.max_cost_usd - usage.cost_used, 0.0
            ),
            "window_resets_at": usage.window_start + self._window_secs,
        }

    def reset(self, agent_id: Optional[str] = None) -> None:
        """Reset usage counters.

        If *agent_id* is provided only that agent's counters are cleared;
        otherwise all agents are reset.
        """
        if agent_id is not None:
            self._agents.pop(agent_id, None)
        else:
            self._agents.clear()
