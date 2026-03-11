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
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, float]:
        return {"overall": self.overall}


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
        score.overall = min(score.overall + self.reward_rate, 1.0)
        score.last_updated = time.time()
        return score

    def record_failure(self, agent_id: str, dimensions: Optional[List[str]] = None) -> TrustScore:
        score = self.get_score(agent_id)
        score.overall = max(score.overall - self.penalty_rate, 0.0)
        score.last_updated = time.time()
        return score

    def check_trust(self, agent_id: str, min_overall: float = 0.3, min_dimensions: Optional[Dict[str, float]] = None) -> bool:
        score = self.get_score(agent_id)
        return score.overall >= min_overall
