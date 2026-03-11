"""Multi-dimensional trust scoring for agents."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class TrustScore:
    """A multi-dimensional trust score for an agent."""

    agent_id: str
    overall: float = 1.0
    reliability: float = 1.0
    capability: float = 1.0
    security: float = 1.0
    compliance: float = 1.0
    history: float = 1.0
    last_updated: float = field(default_factory=time.time)

    def __post_init__(self):
        for attr in ("overall", "reliability", "capability", "security", "compliance", "history"):
            val = getattr(self, attr)
            if not 0.0 <= val <= 1.0:
                raise ValueError(f"{attr} must be between 0.0 and 1.0, got {val}")

    def compute_overall(self, weights: Optional[Dict[str, float]] = None) -> float:
        """Compute weighted overall score from dimensions."""
        w = weights or {
            "reliability": 0.25,
            "capability": 0.20,
            "security": 0.25,
            "compliance": 0.20,
            "history": 0.10,
        }
        total_weight = sum(w.values())
        self.overall = sum(
            getattr(self, dim) * weight for dim, weight in w.items()
        ) / total_weight
        self.last_updated = time.time()
        return self.overall

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "overall": round(self.overall, 4),
            "reliability": round(self.reliability, 4),
            "capability": round(self.capability, 4),
            "security": round(self.security, 4),
            "compliance": round(self.compliance, 4),
            "history": round(self.history, 4),
            "last_updated": self.last_updated,
        }


class TrustScorer:
    """Manages trust scores for multiple agents."""

    def __init__(self, default_score: float = 1.0, decay_rate: float = 0.01):
        self._scores: Dict[str, TrustScore] = {}
        self._default_score = default_score
        self._decay_rate = decay_rate

    def get_score(self, agent_id: str) -> TrustScore:
        """Get or create a trust score for an agent."""
        if agent_id not in self._scores:
            self._scores[agent_id] = TrustScore(
                agent_id=agent_id,
                overall=self._default_score,
                reliability=self._default_score,
                capability=self._default_score,
                security=self._default_score,
                compliance=self._default_score,
                history=self._default_score,
            )
        return self._scores[agent_id]

    def record_success(self, agent_id: str, dimension: str = "reliability", boost: float = 0.02):
        """Record a successful interaction, boosting trust."""
        score = self.get_score(agent_id)
        current = getattr(score, dimension, score.reliability)
        setattr(score, dimension, min(1.0, current + boost))
        score.compute_overall()

    def record_failure(self, agent_id: str, dimension: str = "reliability", penalty: float = 0.1):
        """Record a failure, reducing trust."""
        score = self.get_score(agent_id)
        current = getattr(score, dimension, score.reliability)
        setattr(score, dimension, max(0.0, current - penalty))
        score.compute_overall()

    def check_trust(self, agent_id: str, min_score: float = 0.5) -> bool:
        """Check if an agent meets the minimum trust threshold."""
        return self.get_score(agent_id).overall >= min_score

    def apply_decay(self, agent_id: str):
        """Apply time-based decay to trust scores."""
        score = self.get_score(agent_id)
        elapsed = time.time() - score.last_updated
        decay = self._decay_rate * (elapsed / 3600)  # decay per hour
        for dim in ("reliability", "capability", "security", "compliance", "history"):
            current = getattr(score, dim)
            setattr(score, dim, max(0.0, current - decay))
        score.compute_overall()

    def get_all_scores(self) -> Dict[str, TrustScore]:
        return dict(self._scores)
