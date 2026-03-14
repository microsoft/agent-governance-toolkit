"""Trust scoring for PydanticAI agents.

Basic trust score tracking with overall score and threshold validation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class TrustScore:
    """Trust score for an agent. Overall score is 0.0-1.0."""

    overall: float = 0.5
    reliability: float = 0.5
    capability: float = 0.5
    security: float = 0.5
    compliance: float = 0.5
    history: float = 0.5
    last_updated: float = field(default_factory=time.time)

    _WEIGHTS = {
        "reliability": 0.25,
        "capability": 0.20,
        "security": 0.25,
        "compliance": 0.15,
        "history": 0.15,
    }

    def compute_overall(self) -> float:
        self.overall = sum(
            getattr(self, dim) * w for dim, w in self._WEIGHTS.items()
        )
        return self.overall

    def to_dict(self) -> Dict[str, float]:
        return {
            "overall": self.overall,
            "reliability": self.reliability,
            "capability": self.capability,
            "security": self.security,
            "compliance": self.compliance,
            "history": self.history,
        }


class TrustScorer:
    """Manages trust scores for multiple agents."""

    def __init__(
        self,
        reward_rate: float = 0.05,
        penalty_rate: float = 0.10,
        decay_rate: float = 0.01,
    ) -> None:
        self._scores: Dict[str, TrustScore] = {}
        self.reward_rate = reward_rate
        self.penalty_rate = penalty_rate
        self.decay_rate = decay_rate

    def get_score(self, agent_id: str) -> TrustScore:
        if agent_id not in self._scores:
            self._scores[agent_id] = TrustScore()
        return self._scores[agent_id]

    def record_success(self, agent_id: str, dimensions: Optional[List[str]] = None) -> TrustScore:
        score = self.get_score(agent_id)
        dims = dimensions or ["overall"]
        for dim in dims:
            current = getattr(score, dim, None)
            if current is not None:
                setattr(score, dim, min(current + self.reward_rate, 1.0))
        score.last_updated = time.time()
        return score

    def record_failure(self, agent_id: str, dimensions: Optional[List[str]] = None) -> TrustScore:
        score = self.get_score(agent_id)
        dims = dimensions or ["overall"]
        for dim in dims:
            current = getattr(score, dim, None)
            if current is not None:
                setattr(score, dim, max(current - self.penalty_rate, 0.0))
        score.last_updated = time.time()
        return score

    def apply_decay(self, agent_id: str, hours_elapsed: float) -> TrustScore:
        score = self.get_score(agent_id)
        decay = self.decay_rate * hours_elapsed
        for dim in ("reliability", "capability", "security", "compliance", "history"):
            current = getattr(score, dim)
            setattr(score, dim, max(current - decay, 0.0))
        score.overall = max(score.overall - decay, 0.0)
        score.last_updated = time.time()
        return score

    def check_trust(self, agent_id: str, min_overall: float = 0.3, min_dimensions: Optional[Dict[str, float]] = None) -> bool:
        score = self.get_score(agent_id)
        if score.overall < min_overall:
            return False
        if min_dimensions:
            for dim, threshold in min_dimensions.items():
                if getattr(score, dim, 0.0) < threshold:
                    return False
        return True
