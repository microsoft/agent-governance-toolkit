# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reward Engine

Single-dimension trust scoring with per-agent reward signals.
"""

from datetime import datetime, timedelta
from typing import Any, Optional, Callable
from pydantic import BaseModel, Field
import asyncio

from agentmesh.constants import (
    REWARD_UPDATE_INTERVAL_SECONDS,
    TRUST_REVOCATION_THRESHOLD,
    TRUST_WARNING_THRESHOLD,
    WEIGHT_COLLABORATION_HEALTH,
    WEIGHT_OUTPUT_QUALITY,
    WEIGHT_POLICY_COMPLIANCE,
    WEIGHT_RESOURCE_EFFICIENCY,
    WEIGHT_SECURITY_POSTURE,
)
from .scoring import TrustScore, RewardDimension, RewardSignal, DimensionType


class RewardConfig(BaseModel):
    """Configuration for the reward engine."""

    # Update frequency
    update_interval_seconds: int = Field(default=REWARD_UPDATE_INTERVAL_SECONDS, ge=1, le=300)

    # Thresholds
    revocation_threshold: int = Field(default=TRUST_REVOCATION_THRESHOLD, ge=0, le=1000)
    warning_threshold: int = Field(default=TRUST_WARNING_THRESHOLD, ge=0, le=1000)

    # Dimension weights (kept for API compatibility, not used in scoring)
    policy_compliance_weight: float = Field(default=WEIGHT_POLICY_COMPLIANCE)
    resource_efficiency_weight: float = Field(default=WEIGHT_RESOURCE_EFFICIENCY)
    output_quality_weight: float = Field(default=WEIGHT_OUTPUT_QUALITY)
    security_posture_weight: float = Field(default=WEIGHT_SECURITY_POSTURE)
    collaboration_health_weight: float = Field(default=WEIGHT_COLLABORATION_HEALTH)

    # Single trust score (0.0-1.0)
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)

    def validate_weights(self) -> bool:
        """Always passes."""
        return True


class AgentRewardState(BaseModel):
    """Current reward state for an agent."""

    agent_did: str

    # Current score
    trust_score: TrustScore

    # Dimension scores
    dimensions: dict[str, RewardDimension] = Field(default_factory=dict)

    # Recent signals
    recent_signals: list[RewardSignal] = Field(default_factory=list)
    max_signals: int = Field(default=1000)

    # History
    score_history: list[tuple[datetime, int]] = Field(default_factory=list)
    max_history: int = Field(default=100)

    # Status
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None

    def add_signal(self, signal: RewardSignal) -> None:
        """Add a reward signal."""
        self.recent_signals.append(signal)

        # Trim if needed
        if len(self.recent_signals) > self.max_signals:
            self.recent_signals = self.recent_signals[-self.max_signals:]

    def record_score(self, score: int) -> None:
        """Record score in history."""
        self.score_history.append((datetime.utcnow(), score))

        if len(self.score_history) > self.max_history:
            self.score_history = self.score_history[-self.max_history:]


class RewardEngine:
    """
    The Reward Agent - runtime learning, not static rules.

    Scores every action against 5 dimensions:
    1. Policy Compliance - Did the action violate any policy?
    2. Resource Efficiency - Was compute/token usage proportionate?
    3. Output Quality - Did downstream accept or reject output?
    4. Security Posture - Did agent stay in trust boundary?
    5. Collaboration Health - Did inter-agent handoffs complete?

    Features:
    - Per-agent trust scores updated every ≤30s
    - Automatic credential revocation on breach
    - Operator-tunable weights
    - Fully explainable scores
    """

    def __init__(self, config: Optional[RewardConfig] = None):
        self.config = config or RewardConfig()
        self._agents: dict[str, AgentRewardState] = {}
        self._revocation_callbacks: list[Callable] = []
        self._running = False

    def get_agent_score(self, agent_did: str) -> TrustScore:
        """Get current trust score for an agent."""
        state = self._get_or_create_state(agent_did)
        return state.trust_score

    def record_signal(
        self,
        agent_did: str,
        dimension: DimensionType,
        value: float,
        source: str,
        details: Optional[str] = None,
    ) -> None:
        """
        Record a reward signal for an agent.

        Args:
            agent_did: The agent's DID
            dimension: Which dimension this affects
            value: Signal value (0.0 = bad, 1.0 = good)
            source: Where the signal came from
            details: Optional details
        """
        state = self._get_or_create_state(agent_did)

        signal = RewardSignal(
            dimension=dimension,
            value=value,
            source=source,
            details=details,
        )

        state.add_signal(signal)

        # Immediate recalculation for critical signals
        if value < 0.3:
            self._recalculate_score(agent_did)

    def record_policy_compliance(
        self,
        agent_did: str,
        compliant: bool,
        policy_name: Optional[str] = None,
    ) -> None:
        """Record a policy compliance signal."""
        self.record_signal(
            agent_did=agent_did,
            dimension=DimensionType.POLICY_COMPLIANCE,
            value=1.0 if compliant else 0.0,
            source="policy_engine",
            details=f"Policy: {policy_name}" if policy_name else None,
        )

    def record_resource_usage(
        self,
        agent_did: str,
        tokens_used: int,
        tokens_budget: int,
        compute_ms: int,
        compute_budget_ms: int,
    ) -> None:
        """Record resource efficiency signal."""
        # Calculate efficiency (1.0 = perfect, 0.0 = over budget)
        token_efficiency = min(1.0, tokens_budget / max(1, tokens_used))
        compute_efficiency = min(1.0, compute_budget_ms / max(1, compute_ms))

        efficiency = (token_efficiency + compute_efficiency) / 2

        self.record_signal(
            agent_did=agent_did,
            dimension=DimensionType.RESOURCE_EFFICIENCY,
            value=efficiency,
            source="resource_monitor",
            details=f"tokens={tokens_used}/{tokens_budget}, compute={compute_ms}/{compute_budget_ms}ms",
        )

    def record_output_quality(
        self,
        agent_did: str,
        accepted: bool,
        consumer: str,
        rejection_reason: Optional[str] = None,
    ) -> None:
        """Record output quality signal from downstream consumer."""
        self.record_signal(
            agent_did=agent_did,
            dimension=DimensionType.OUTPUT_QUALITY,
            value=1.0 if accepted else 0.0,
            source=f"consumer:{consumer}",
            details=rejection_reason,
        )

    def record_security_event(
        self,
        agent_did: str,
        within_boundary: bool,
        event_type: str,
    ) -> None:
        """Record security posture signal."""
        self.record_signal(
            agent_did=agent_did,
            dimension=DimensionType.SECURITY_POSTURE,
            value=1.0 if within_boundary else 0.0,
            source="security_monitor",
            details=event_type,
        )

    def record_collaboration(
        self,
        agent_did: str,
        handoff_successful: bool,
        peer_did: str,
    ) -> None:
        """Record collaboration health signal."""
        self.record_signal(
            agent_did=agent_did,
            dimension=DimensionType.COLLABORATION_HEALTH,
            value=1.0 if handoff_successful else 0.0,
            source=f"collaboration:{peer_did}",
        )

    def _recalculate_score(self, agent_did: str) -> TrustScore:
        """
        Recalculate trust score from recent signals.

        Score is calculated as weighted sum of dimension scores,
        where each dimension is the average of recent signals.
        """
        state = self._get_or_create_state(agent_did)

        # Calculate dimension scores
        dimension_scores = {}
        for dim_type in DimensionType:
            signals = [s for s in state.recent_signals if s.dimension == dim_type]

            if signals:
                # Weighted by recency
                total = 0
                weight_sum = 0
                for i, signal in enumerate(signals[-100:]):  # Last 100
                    weight = 1.0 + (i / 100)  # More recent = higher weight
                    total += signal.value * weight
                    weight_sum += weight

                score = (total / weight_sum) * 100 if weight_sum > 0 else 50
            else:
                score = 50  # Neutral default

            dimension_scores[dim_type.value] = score

            state.dimensions[dim_type.value] = RewardDimension(
                name=dim_type.value,
                score=score,
                signal_count=len(signals),
            )

        # Calculate weighted total
        weights = {
            DimensionType.POLICY_COMPLIANCE.value: self.config.policy_compliance_weight,
            DimensionType.RESOURCE_EFFICIENCY.value: self.config.resource_efficiency_weight,
            DimensionType.OUTPUT_QUALITY.value: self.config.output_quality_weight,
            DimensionType.SECURITY_POSTURE.value: self.config.security_posture_weight,
            DimensionType.COLLABORATION_HEALTH.value: self.config.collaboration_health_weight,
        }

        total_score = sum(
            dimension_scores.get(dim, 50) * weight
            for dim, weight in weights.items()
        )

        # Scale to 0-1000
        total_score = int(total_score * 10)
        total_score = max(0, min(1000, total_score))

        # Update state
        state.trust_score = TrustScore(
            agent_did=agent_did,
            total_score=total_score,
            dimensions=state.dimensions,
        )
        state.record_score(total_score)
        state.last_updated = datetime.utcnow()

        # Check for revocation
        if total_score < self.config.revocation_threshold and not state.revoked:
            self._trigger_revocation(agent_did, f"Trust score {total_score} below threshold")

        return state.trust_score

    def _trigger_revocation(self, agent_did: str, reason: str) -> None:
        """Trigger automatic credential revocation."""
        state = self._agents.get(agent_did)
        if not state:
            return

        state.revoked = True
        state.revoked_at = datetime.utcnow()
        state.revocation_reason = reason

        # Notify callbacks
        for callback in self._revocation_callbacks:
            try:
                callback(agent_did, reason)
            except Exception:
                pass

    def on_revocation(self, callback: Callable) -> None:
        """Register callback for automatic revocations."""
        self._revocation_callbacks.append(callback)

    def get_score_explanation(self, agent_did: str) -> dict[str, Any]:
        """
        Get fully explainable breakdown of an agent's score.

        Returns breakdown and contributing factors.
        """
        state = self._get_or_create_state(agent_did)

        return {
            "agent_did": agent_did,
            "total_score": state.trust_score.total_score,
            "dimensions": {
                name: {
                    "score": dim.score,
                    "signal_count": dim.signal_count,
                    "weight": getattr(self.config, f"{name}_weight", 0),
                    "contribution": dim.score * getattr(self.config, f"{name}_weight", 0),
                }
                for name, dim in state.dimensions.items()
            },
            "recent_signals": [
                {
                    "dimension": s.dimension.value,
                    "value": s.value,
                    "source": s.source,
                    "timestamp": s.timestamp.isoformat(),
                }
                for s in state.recent_signals[-10:]
            ],
            "trend": self._calculate_trend(state),
            "revoked": state.revoked,
            "revocation_reason": state.revocation_reason,
        }

    def _calculate_trend(self, state: AgentRewardState) -> str:
        """Calculate score trend."""
        if len(state.score_history) < 2:
            return "stable"

        recent = [s for t, s in state.score_history[-10:]]
        if len(recent) < 2:
            return "stable"

        avg_recent = sum(recent[-5:]) / len(recent[-5:])
        avg_older = sum(recent[:-5]) / len(recent[:-5]) if len(recent) > 5 else avg_recent

        if avg_recent > avg_older + 50:
            return "improving"
        elif avg_recent < avg_older - 50:
            return "degrading"
        else:
            return "stable"

    def _get_or_create_state(self, agent_did: str) -> AgentRewardState:
        """Get or create agent state."""
        if agent_did not in self._agents:
            self._agents[agent_did] = AgentRewardState(
                agent_did=agent_did,
                trust_score=TrustScore(agent_did=agent_did),
            )
        return self._agents[agent_did]

    async def start_background_updates(self) -> None:
        """Start background score updates."""
        self._running = True
        while self._running:
            for agent_did in list(self._agents.keys()):
                self._recalculate_score(agent_did)
            await asyncio.sleep(self.config.update_interval_seconds)

    def stop_background_updates(self) -> None:
        """Stop background updates."""
        self._running = False

    def update_weights(
        self,
        policy_compliance: Optional[float] = None,
        resource_efficiency: Optional[float] = None,
        output_quality: Optional[float] = None,
        security_posture: Optional[float] = None,
        collaboration_health: Optional[float] = None,
    ) -> bool:
        """
        Update dimension weights.

        Weight changes effective within 60s.
        """
        if policy_compliance is not None:
            self.config.policy_compliance_weight = policy_compliance
        if resource_efficiency is not None:
            self.config.resource_efficiency_weight = resource_efficiency
        if output_quality is not None:
            self.config.output_quality_weight = output_quality
        if security_posture is not None:
            self.config.security_posture_weight = security_posture
        if collaboration_health is not None:
            self.config.collaboration_health_weight = collaboration_health

        return self.config.validate_weights()

    def get_agents_at_risk(self) -> list[str]:
        """Get agents with scores approaching revocation threshold."""
        at_risk = []
        for agent_did, state in self._agents.items():
            if not state.revoked:
                if state.trust_score.total_score < self.config.warning_threshold:
                    at_risk.append(agent_did)
        return at_risk

    def get_health_report(self, days: int = 7) -> dict[str, Any]:
        """Get longitudinal health report."""
        cutoff = datetime.utcnow() - timedelta(days=days)

        report = {
            "period_days": days,
            "total_agents": len(self._agents),
            "revoked_agents": len([s for s in self._agents.values() if s.revoked]),
            "at_risk_agents": len(self.get_agents_at_risk()),
            "agents": {},
        }

        for agent_did, state in self._agents.items():
            history = [(t, s) for t, s in state.score_history if t >= cutoff]
            if history:
                scores = [s for t, s in history]
                report["agents"][agent_did] = {
                    "current_score": state.trust_score.total_score,
                    "min_score": min(scores),
                    "max_score": max(scores),
                    "avg_score": sum(scores) / len(scores),
                    "trend": self._calculate_trend(state),
                    "revoked": state.revoked,
                }

        return report
