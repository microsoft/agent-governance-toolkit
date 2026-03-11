"""Trust-based routing component for Langflow flows.

Routes agent actions to one of three outputs based on trust score:
trusted (proceed), review (human review), or blocked (deny).
Uses decay-based trust with asymmetric reward/penalty.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RouteDecision(Enum):
    """Routing decision based on trust score."""

    TRUSTED = "trusted"
    REVIEW = "review"
    BLOCKED = "blocked"


@dataclass
class TrustScore:
    """Multi-dimensional trust score for an agent."""

    overall: float = 0.5
    reliability: float = 0.5
    capability: float = 0.5
    security: float = 0.5
    compliance: float = 0.5
    history: float = 0.5
    last_updated: float = field(default_factory=time.time)

    _WEIGHTS: Dict[str, float] = field(
        default_factory=lambda: {
            "reliability": 0.25,
            "capability": 0.20,
            "security": 0.25,
            "compliance": 0.20,
            "history": 0.10,
        },
        repr=False,
    )

    def compute_overall(self) -> float:
        """Compute weighted overall score from dimensions."""
        total = 0.0
        for dim, weight in self._WEIGHTS.items():
            total += getattr(self, dim) * weight
        self.overall = round(min(max(total, 0.0), 1.0), 4)
        self.last_updated = time.time()
        return self.overall

    def to_dict(self) -> Dict[str, float]:
        """Serialize to dictionary."""
        return {
            "overall": self.overall,
            "reliability": self.reliability,
            "capability": self.capability,
            "security": self.security,
            "compliance": self.compliance,
            "history": self.history,
        }


@dataclass
class RouteResult:
    """Result of trust-based routing."""

    decision: RouteDecision
    trust_score: float
    agent_id: str
    payload: Any = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "decision": self.decision.value,
            "trust_score": self.trust_score,
            "agent_id": self.agent_id,
            "reason": self.reason,
        }


class TrustRouter:
    """Routes flow based on agent trust score.

    Three outputs:
    - trusted_output: agent trust >= trusted_threshold
    - review_output: review_threshold <= trust < trusted_threshold
    - blocked_output: trust < review_threshold

    Configurable thresholds and asymmetric reward/penalty rates.
    """

    display_name = "Trust Router"
    description = "Routes actions based on agent trust scores"
    icon = "route"

    def __init__(
        self,
        trusted_threshold: float = 0.7,
        review_threshold: float = 0.3,
        reward_rate: float = 0.05,
        penalty_rate: float = 0.10,
        decay_rate: float = 0.01,
    ) -> None:
        if review_threshold >= trusted_threshold:
            raise ValueError(
                f"review_threshold ({review_threshold}) must be less than "
                f"trusted_threshold ({trusted_threshold})"
            )
        self.trusted_threshold = trusted_threshold
        self.review_threshold = review_threshold
        self.reward_rate = reward_rate
        self.penalty_rate = penalty_rate
        self.decay_rate = decay_rate
        self._scores: Dict[str, TrustScore] = {}

    def get_score(self, agent_id: str) -> TrustScore:
        """Get or create trust score for an agent."""
        if agent_id not in self._scores:
            self._scores[agent_id] = TrustScore()
            self._scores[agent_id].compute_overall()
        return self._scores[agent_id]

    def route(self, agent_id: str, payload: Any = None) -> RouteResult:
        """Route based on current trust score."""
        score = self.get_score(agent_id)
        trust = score.overall

        if trust >= self.trusted_threshold:
            decision = RouteDecision.TRUSTED
            reason = f"Trust {trust:.4f} >= trusted threshold {self.trusted_threshold}"
        elif trust >= self.review_threshold:
            decision = RouteDecision.REVIEW
            reason = (
                f"Trust {trust:.4f} between review ({self.review_threshold}) "
                f"and trusted ({self.trusted_threshold}) thresholds"
            )
        else:
            decision = RouteDecision.BLOCKED
            reason = f"Trust {trust:.4f} < review threshold {self.review_threshold}"

        return RouteResult(
            decision=decision,
            trust_score=trust,
            agent_id=agent_id,
            payload=payload,
            reason=reason,
        )

    def record_success(
        self,
        agent_id: str,
        dimensions: Optional[List[str]] = None,
    ) -> TrustScore:
        """Record a successful action, boosting specified dimensions."""
        score = self.get_score(agent_id)
        dims = dimensions or ["reliability"]
        for dim in dims:
            if hasattr(score, dim) and dim not in ("overall", "last_updated", "_WEIGHTS"):
                current = getattr(score, dim)
                new_val = min(current + self.reward_rate, 1.0)
                setattr(score, dim, round(new_val, 4))
        score.compute_overall()
        return score

    def record_failure(
        self,
        agent_id: str,
        dimensions: Optional[List[str]] = None,
    ) -> TrustScore:
        """Record a failed action, penalizing specified dimensions."""
        score = self.get_score(agent_id)
        dims = dimensions or ["reliability"]
        for dim in dims:
            if hasattr(score, dim) and dim not in ("overall", "last_updated", "_WEIGHTS"):
                current = getattr(score, dim)
                new_val = max(current - self.penalty_rate, 0.0)
                setattr(score, dim, round(new_val, 4))
        score.compute_overall()
        return score

    def apply_decay(self, agent_id: str, hours_elapsed: float = 1.0) -> TrustScore:
        """Apply time-based decay to trust scores."""
        score = self.get_score(agent_id)
        decay = self.decay_rate * hours_elapsed
        for dim in ["reliability", "capability", "security", "compliance", "history"]:
            current = getattr(score, dim)
            new_val = max(current - decay, 0.0)
            setattr(score, dim, round(new_val, 4))
        score.compute_overall()
        return score

    def get_trusted_output(self, result: RouteResult) -> Optional[Any]:
        """Get payload if decision is TRUSTED, else None."""
        return result.payload if result.decision == RouteDecision.TRUSTED else None

    def get_review_output(self, result: RouteResult) -> Optional[Any]:
        """Get payload if decision is REVIEW, else None."""
        return result.payload if result.decision == RouteDecision.REVIEW else None

    def get_blocked_output(self, result: RouteResult) -> Optional[Any]:
        """Get payload if decision is BLOCKED, else None."""
        return result.payload if result.decision == RouteDecision.BLOCKED else None
