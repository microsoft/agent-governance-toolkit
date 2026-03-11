"""TrustGate component for Haystack pipelines.

Trust scoring with decay, success/failure tracking, and routing
decisions (pass / review / block).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    from haystack import component
except ImportError:  # pragma: no cover
    class _ComponentShim:
        def __call__(self, cls):
            return cls

        @staticmethod
        def input_types(**kwargs):
            def decorator(func):
                return func
            return decorator

        @staticmethod
        def output_types(**kwargs):
            def decorator(func):
                return func
            return decorator

    component = _ComponentShim()  # type: ignore[assignment]


@dataclass
class AgentTrustRecord:
    """Internal trust state for a single agent."""

    score: float = 0.5
    successes: int = 0
    failures: int = 0
    last_update: float = field(default_factory=time.time)


@component
class TrustGate:
    """Evaluates agent trust scores and routes actions accordingly.

    Maintains per-agent trust records with time-based decay.
    Actions are routed to *pass*, *review*, or *block* based on
    configurable thresholds.
    """

    def __init__(
        self,
        pass_threshold: float = 0.7,
        review_threshold: float = 0.4,
        reward: float = 0.05,
        penalty: float = 0.10,
        decay_rate: float = 0.01,
    ) -> None:
        self.pass_threshold = pass_threshold
        self.review_threshold = review_threshold
        self.reward = reward
        self.penalty = penalty
        self.decay_rate = decay_rate
        self._records: Dict[str, AgentTrustRecord] = {}

    # ── Trust management ──────────────────────────────────────────

    def _get_record(self, agent_id: str) -> AgentTrustRecord:
        if agent_id not in self._records:
            self._records[agent_id] = AgentTrustRecord()
        return self._records[agent_id]

    def record_success(self, agent_id: str) -> float:
        """Record a successful action and return the updated score."""
        rec = self._get_record(agent_id)
        rec.successes += 1
        rec.score = min(rec.score + self.reward, 1.0)
        rec.last_update = time.time()
        return rec.score

    def record_failure(self, agent_id: str) -> float:
        """Record a failed action and return the updated score."""
        rec = self._get_record(agent_id)
        rec.failures += 1
        rec.score = max(rec.score - self.penalty, 0.0)
        rec.last_update = time.time()
        return rec.score

    def apply_decay(self, agent_id: str) -> float:
        """Apply time-based decay to an agent's trust score."""
        rec = self._get_record(agent_id)
        elapsed_hours = (time.time() - rec.last_update) / 3600.0
        decay = self.decay_rate * elapsed_hours
        rec.score = max(rec.score - decay, 0.0)
        return rec.score

    def get_score(self, agent_id: str) -> float:
        """Return the current trust score for *agent_id*."""
        return self._get_record(agent_id).score

    # ── Component interface ───────────────────────────────────────

    @component.input_types(agent_id=str, min_score=Optional[float])
    @component.output_types(trusted=bool, score=float, action=str)
    def run(
        self,
        agent_id: str,
        min_score: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Evaluate trust for *agent_id*.

        Returns ``trusted`` (bool), ``score`` (float), and ``action``
        ("pass", "review", or "block").
        """
        self.apply_decay(agent_id)
        score = self.get_score(agent_id)
        threshold = min_score if min_score is not None else self.pass_threshold

        if score >= threshold:
            action = "pass"
            trusted = True
        elif score >= self.review_threshold:
            action = "review"
            trusted = False
        else:
            action = "block"
            trusted = False

        return {"trusted": trusted, "score": round(score, 4), "action": action}
