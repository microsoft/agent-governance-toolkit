# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Task outcome recording for RewardEngine trust scoring.

Provides severity-based scoring with diminishing returns and
time-based recovery for agent trust management.

Example::

    recorder = TaskOutcomeRecorder()
    recorder.record(agent_id="a1", outcome="success")
    recorder.record(agent_id="a1", outcome="failure", severity=0.8)
    score = recorder.get_score("a1")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TaskOutcome:
    """A recorded task outcome."""

    agent_id: str
    outcome: str  # "success" | "failure"
    severity: float = 0.5
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentScoreState:
    """Running score state for an agent."""

    score: float = 0.7  # Start at neutral-positive
    total_tasks: int = 0
    successes: int = 0
    failures: int = 0
    last_updated: float = field(default_factory=time.time)


class TaskOutcomeRecorder:
    """Records task outcomes and computes trust scores.

    Features:
    - Success boost with diminishing returns
    - Severity-based failure penalties
    - Time-based recovery (scores drift toward neutral over time)
    - Per-agent score tracking
    """

    def __init__(
        self,
        success_boost: float = 0.05,
        failure_base_penalty: float = 0.1,
        recovery_rate: float = 0.01,
        recovery_interval_seconds: float = 3600.0,
        min_score: float = 0.0,
        max_score: float = 1.0,
    ) -> None:
        self.success_boost = success_boost
        self.failure_base_penalty = failure_base_penalty
        self.recovery_rate = recovery_rate
        self.recovery_interval = recovery_interval_seconds
        self.min_score = min_score
        self.max_score = max_score
        self._agents: dict[str, AgentScoreState] = {}
        self._history: list[TaskOutcome] = []

    def record(
        self,
        agent_id: str,
        outcome: str,
        severity: float = 0.5,
        **metadata: Any,
    ) -> float:
        """Record a task outcome and return updated score.

        Args:
            agent_id: The agent identifier.
            outcome: "success" or "failure".
            severity: 0.0-1.0, how severe (for failures) or impactful (for successes).
            **metadata: Additional context.

        Returns:
            Updated trust score for the agent.
        """
        state = self._agents.setdefault(agent_id, AgentScoreState())

        # Apply time-based recovery first
        self._apply_recovery(state)

        state.total_tasks += 1
        entry = TaskOutcome(
            agent_id=agent_id,
            outcome=outcome,
            severity=severity,
            metadata=metadata,
        )
        self._history.append(entry)

        if outcome == "success":
            state.successes += 1
            # Diminishing returns: boost decreases as score approaches max
            headroom = self.max_score - state.score
            boost = self.success_boost * severity * (headroom / self.max_score)
            state.score = min(self.max_score, state.score + boost)
        elif outcome == "failure":
            state.failures += 1
            penalty = self.failure_base_penalty * severity
            state.score = max(self.min_score, state.score - penalty)

        state.last_updated = time.time()
        return state.score

    def get_score(self, agent_id: str) -> float:
        """Get current trust score for an agent."""
        state = self._agents.get(agent_id)
        if state is None:
            return 0.7  # Default for unknown agents
        self._apply_recovery(state)
        return round(state.score, 4)

    def get_stats(self, agent_id: str) -> dict[str, Any]:
        """Get detailed stats for an agent."""
        state = self._agents.get(agent_id)
        if state is None:
            return {"agent_id": agent_id, "score": 0.7, "total_tasks": 0}
        return {
            "agent_id": agent_id,
            "score": round(state.score, 4),
            "total_tasks": state.total_tasks,
            "successes": state.successes,
            "failures": state.failures,
            "success_rate": round(state.successes / max(1, state.total_tasks), 3),
        }

    def _apply_recovery(self, state: AgentScoreState) -> None:
        """Apply time-based score recovery toward neutral (0.7)."""
        elapsed = time.time() - state.last_updated
        intervals = elapsed / self.recovery_interval
        if intervals > 0 and state.score < 0.7:
            recovery = self.recovery_rate * intervals
            state.score = min(0.7, state.score + recovery)
            state.last_updated = time.time()
