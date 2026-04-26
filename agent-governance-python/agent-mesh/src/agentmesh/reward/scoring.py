# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reward Scoring

Multi-dimensional scoring with trust scores and reward signals.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from enum import Enum

from agentmesh.constants import (
    TIER_PROBATIONARY_THRESHOLD,
    TIER_STANDARD_THRESHOLD,
    TIER_TRUSTED_THRESHOLD,
    TIER_VERIFIED_PARTNER_THRESHOLD,
    TRUST_REVOCATION_THRESHOLD,
    TRUST_SCORE_DEFAULT,
    TRUST_SCORE_MAX,
)
from agentmesh.exceptions import TrustError


class DimensionType(str, Enum):
    """The 5 reward dimensions."""
    POLICY_COMPLIANCE = "policy_compliance"
    RESOURCE_EFFICIENCY = "resource_efficiency"
    OUTPUT_QUALITY = "output_quality"
    SECURITY_POSTURE = "security_posture"
    COLLABORATION_HEALTH = "collaboration_health"


class RewardSignal(BaseModel):
    """
    A single reward signal.

    Signals feed into dimension scores which aggregate to trust scores.
    """

    dimension: DimensionType
    value: float = Field(..., ge=0.0, le=1.0, description="0=bad, 1=good")

    # Source
    source: str = Field(..., description="Where this signal came from")

    # Context
    details: Optional[str] = None
    trace_id: Optional[str] = None

    # Timing
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Weight (for importance)
    weight: float = Field(default=1.0, ge=0.0)


class RewardDimension(BaseModel):
    """Score for a single dimension."""

    name: str
    score: float = Field(default=50.0, ge=0.0, le=100.0)

    # Signal statistics
    signal_count: int = Field(default=0)
    positive_signals: int = Field(default=0)
    negative_signals: int = Field(default=0)

    # Trend
    previous_score: Optional[float] = None
    trend: str = "stable"  # improving, degrading, stable

    # Last update
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def add_signal(self, signal: RewardSignal) -> None:
        """Add a signal and update score."""
        self.signal_count += 1

        if signal.value >= 0.5:
            self.positive_signals += 1
        else:
            self.negative_signals += 1

        # Update score (exponential moving average)
        alpha = 0.1  # Smoothing factor
        self.previous_score = self.score
        self.score = self.score * (1 - alpha) + (signal.value * 100) * alpha

        # Update trend
        if self.previous_score is not None:
            diff = self.score - self.previous_score
            if diff > 5:
                self.trend = "improving"
            elif diff < -5:
                self.trend = "degrading"
            else:
                self.trend = "stable"

        self.updated_at = datetime.utcnow()


class TrustScore(BaseModel):
    """
    Complete trust score for an agent.

    Aggregates all dimension scores into a single 0-1000 score.
    """

    agent_did: str

    # Total score (0-1000)
    total_score: int = Field(default=TRUST_SCORE_DEFAULT, ge=0, le=1000)

    # Trust tier
    tier: str = "standard"  # verified_partner, trusted, standard, probationary, untrusted

    # Dimension breakdown
    dimensions: dict[str, RewardDimension] = Field(default_factory=dict)

    # Timestamps
    calculated_at: datetime = Field(default_factory=datetime.utcnow)

    # History
    previous_score: Optional[int] = None
    score_change: int = 0

    model_config = {"validate_assignment": True}

    @field_validator("agent_did")
    @classmethod
    def validate_agent_did(cls, v: str) -> str:
        if not v or not v.strip():
            raise TrustError("agent_did must not be empty")
        if not v.startswith("did:mesh:"):
            raise TrustError(
                f"agent_did must match 'did:mesh:' pattern, got: {v}"
            )
        return v

    def __init__(self, **data):
        super().__init__(**data)
        self._update_tier()

    def _update_tier(self) -> None:
        """Update tier based on score."""
        if self.total_score >= TIER_VERIFIED_PARTNER_THRESHOLD:
            self.tier = "verified_partner"
        elif self.total_score >= TIER_TRUSTED_THRESHOLD:
            self.tier = "trusted"
        elif self.total_score >= TIER_STANDARD_THRESHOLD:
            self.tier = "standard"
        elif self.total_score >= TIER_PROBATIONARY_THRESHOLD:
            self.tier = "probationary"
        else:
            self.tier = "untrusted"

    def update(self, new_score: int, dimensions: dict[str, RewardDimension]) -> None:
        """Update the trust score."""
        self.previous_score = self.total_score
        self.total_score = max(0, min(TRUST_SCORE_MAX, new_score))
        self.score_change = self.total_score - (self.previous_score or 0)
        self.dimensions = dimensions
        self.calculated_at = datetime.utcnow()
        self._update_tier()

    def meets_threshold(self, threshold: int) -> bool:
        """Check if score meets a threshold."""
        return self.total_score >= threshold

    def to_dict(self) -> dict:
        """Export as dictionary."""
        return {
            "agent_did": self.agent_did,
            "total_score": self.total_score,
            "tier": self.tier,
            "dimensions": {
                name: {
                    "score": dim.score,
                    "trend": dim.trend,
                    "signal_count": dim.signal_count,
                }
                for name, dim in self.dimensions.items()
            },
            "calculated_at": self.calculated_at.isoformat(),
        }


class ScoreThresholds(BaseModel):
    """Configurable score thresholds."""

    # Tier thresholds
    verified_partner: int = TIER_VERIFIED_PARTNER_THRESHOLD
    trusted: int = TIER_TRUSTED_THRESHOLD
    standard: int = TIER_STANDARD_THRESHOLD
    probationary: int = TIER_PROBATIONARY_THRESHOLD

    # Action thresholds
    allow_threshold: int = TIER_STANDARD_THRESHOLD
    warn_threshold: int = 400
    revocation_threshold: int = TRUST_REVOCATION_THRESHOLD

    def get_tier(self, score: int) -> str:
        """Get tier for a score."""
        if score >= self.verified_partner:
            return "verified_partner"
        elif score >= self.trusted:
            return "trusted"
        elif score >= self.standard:
            return "standard"
        elif score >= self.probationary:
            return "probationary"
        else:
            return "untrusted"

    def should_allow(self, score: int) -> bool:
        """Check if score should allow actions."""
        return score >= self.allow_threshold

    def should_warn(self, score: int) -> bool:
        """Check if score should trigger warning."""
        return score < self.warn_threshold

    def should_revoke(self, score: int) -> bool:
        """Check if score should trigger revocation."""
        return score < self.revocation_threshold
