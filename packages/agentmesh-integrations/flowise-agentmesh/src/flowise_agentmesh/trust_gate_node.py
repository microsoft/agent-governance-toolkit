"""Trust-scored routing node for Flowise flows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class TrustResult:
    """Result of trust gate evaluation."""

    agent_id: str
    trust_score: float
    tier: str  # "trusted", "review", or "blocked"
    routed_to: str  # output port name


class TrustGateNode:
    """Routes agents to trust tiers based on score thresholds.

    Outputs one of three tiers:
    - trusted: score >= min_trust_score
    - review: review_threshold <= score < min_trust_score
    - blocked: score < review_threshold
    """

    def __init__(
        self,
        min_trust_score: float = 0.7,
        review_threshold: float = 0.4,
    ) -> None:
        if review_threshold > min_trust_score:
            raise ValueError("review_threshold must be <= min_trust_score")
        self.min_trust_score = min_trust_score
        self.review_threshold = review_threshold

    def evaluate(self, agent_id: str, trust_score: float) -> TrustResult:
        """Evaluate an agent's trust score and determine routing tier."""
        score = max(0.0, min(1.0, trust_score))

        if score >= self.min_trust_score:
            tier = "trusted"
        elif score >= self.review_threshold:
            tier = "review"
        else:
            tier = "blocked"

        return TrustResult(
            agent_id=agent_id,
            trust_score=score,
            tier=tier,
            routed_to=tier,
        )

    def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Flowise-compatible run method."""
        result = self.evaluate(
            agent_id=input_data.get("agent_id", "unknown"),
            trust_score=float(input_data.get("trust_score", 0.0)),
        )
        return {
            "agent_id": result.agent_id,
            "trust_score": result.trust_score,
            "tier": result.tier,
            "routed_to": result.routed_to,
            "output": input_data if result.tier != "blocked" else None,
        }
