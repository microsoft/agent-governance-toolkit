"""Risk scoring for ungoverned and shadow agents.

Scores agents based on governance posture: no identity, unknown owner,
broad permissions, no audit trail, and time since first seen.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .models import (
    AgentStatus,
    DiscoveredAgent,
    RiskAssessment,
    RiskLevel,
)


class RiskScorer:
    """Score the risk of discovered agents based on governance posture.

    Risk factors:
    - No registered identity (DID/SPIFFE)
    - No assigned owner
    - Shadow status (discovered but not registered)
    - Low confidence detection (potential false positive noise)
    - Agent type with high blast radius (e.g., full code execution)
    - Long time unregistered since first seen
    """

    # Agent types with higher inherent risk
    HIGH_RISK_TYPES = {"autogen", "crewai", "langchain", "openai-agents"}
    MEDIUM_RISK_TYPES = {"mcp-server", "semantic-kernel", "pydantic-ai"}

    def score(self, agent: DiscoveredAgent) -> RiskAssessment:
        """Compute risk assessment for a discovered agent."""
        factors: list[str] = []
        score = 0.0

        # No governance identity
        if not agent.did and not agent.spiffe_id:
            score += 30.0
            factors.append("No cryptographic identity (DID/SPIFFE)")

        # No owner
        if not agent.owner:
            score += 20.0
            factors.append("No assigned owner")

        # Shadow / unregistered status
        if agent.status in (AgentStatus.SHADOW, AgentStatus.UNREGISTERED):
            score += 20.0
            factors.append(f"Agent status: {agent.status.value}")

        # Agent type risk
        if agent.agent_type in self.HIGH_RISK_TYPES:
            score += 15.0
            factors.append(f"High-risk agent type: {agent.agent_type}")
        elif agent.agent_type in self.MEDIUM_RISK_TYPES:
            score += 10.0
            factors.append(f"Medium-risk agent type: {agent.agent_type}")

        # Time ungoverned — agents unseen for a long time are riskier
        days_since_first_seen = (
            datetime.now(timezone.utc) - agent.first_seen_at
        ).total_seconds() / 86400
        if days_since_first_seen > 30:
            score += 10.0
            factors.append(f"Ungoverned for {int(days_since_first_seen)} days")
        elif days_since_first_seen > 7:
            score += 5.0
            factors.append(f"Ungoverned for {int(days_since_first_seen)} days")

        # Low confidence penalty (noisy findings are less actionable but still risky)
        if agent.confidence < 0.5:
            score -= 10.0
            factors.append("Low detection confidence — may be false positive")

        # Clamp to 0-100
        score = max(0.0, min(100.0, score))

        # Determine level
        if score >= 75:
            level = RiskLevel.CRITICAL
        elif score >= 50:
            level = RiskLevel.HIGH
        elif score >= 25:
            level = RiskLevel.MEDIUM
        elif score >= 10:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.INFO

        return RiskAssessment(
            level=level,
            score=score,
            factors=factors,
        )
