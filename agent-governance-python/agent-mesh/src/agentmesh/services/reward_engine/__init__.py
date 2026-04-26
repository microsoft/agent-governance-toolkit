# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reward Engine Service

Async worker that processes agent signals and updates trust scores.

Wraps the core RewardEngine to provide:
- Convenience methods for common signal types
- Batch processing
- Agent score lookups with formatting
- Revocation monitoring
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from agentmesh.reward.engine import RewardEngine, RewardConfig, AgentRewardState  # noqa: F401
from agentmesh.reward.scoring import DimensionType, TrustScore, RewardSignal


class RewardService:
    """
    Service layer for the reward engine.

    Wraps RewardEngine with a higher-level API for:
    - Recording common signal patterns
    - Querying agent scores
    - Monitoring trust thresholds
    - Batch score recalculation
    """

    def __init__(self, config: Optional[RewardConfig] = None) -> None:
        self._engine = RewardEngine(config)

    @property
    def engine(self) -> RewardEngine:
        """Access the underlying RewardEngine."""
        return self._engine

    def get_score(self, agent_did: str) -> TrustScore:
        """Get the current trust score for an agent."""
        return self._engine.get_agent_score(agent_did)

    def get_score_value(self, agent_did: str) -> float:
        """Get the numeric trust score (0-1000) for an agent."""
        return self._engine.get_agent_score(agent_did).total_score

    def record_task_success(self, agent_did: str, task_id: str = "") -> None:
        """Record a successful task completion."""
        self._engine.record_policy_compliance(agent_did, compliant=True)
        self._engine.record_output_quality(agent_did, accepted=True, consumer="system")

    def record_task_failure(self, agent_did: str, reason: str = "") -> None:
        """Record a task failure."""
        self._engine.record_output_quality(
            agent_did, accepted=False, consumer="system", rejection_reason=reason,
        )

    def record_policy_violation(self, agent_did: str, policy_name: str = "") -> None:
        """Record a policy violation (negative signal)."""
        self._engine.record_policy_compliance(agent_did, compliant=False, policy_name=policy_name)

    def record_handshake(self, agent_did: str, peer_did: str, success: bool) -> None:
        """Record a trust handshake outcome."""
        self._engine.record_collaboration(agent_did, handoff_successful=success, peer_did=peer_did)

    def record_security_event(self, agent_did: str, within_boundary: bool, event_type: str = "") -> None:
        """Record a security posture signal."""
        self._engine.record_security_event(agent_did, within_boundary=within_boundary, event_type=event_type)

    def on_revocation(self, callback: Callable) -> None:
        """Register a callback for when an agent's trust is revoked."""
        self._engine._revocation_callbacks.append(callback)

    def is_trusted(self, agent_did: str, threshold: float = 500.0) -> bool:
        """Check if an agent meets a minimum trust threshold."""
        return self.get_score_value(agent_did) >= threshold

    def agents_below_threshold(self, threshold: float = 300.0) -> list[str]:
        """Get agents with trust scores below a threshold."""
        return [
            did for did, state in self._engine._agents.items()
            if state.trust_score.total_score < threshold
        ]

    def recalculate_all(self) -> dict[str, float]:
        """Recalculate trust scores for all known agents."""
        results = {}
        for agent_did in list(self._engine._agents.keys()):
            score = self._engine._recalculate_score(agent_did)
            results[agent_did] = score.total_score
        return results

    def summary(self) -> dict[str, Any]:
        """Get reward engine summary statistics."""
        agents = self._engine._agents
        scores = [s.trust_score.total_score for s in agents.values()]
        return {
            "total_agents": len(agents),
            "avg_score": sum(scores) / len(scores) if scores else 0.0,
            "min_score": min(scores) if scores else 0.0,
            "max_score": max(scores) if scores else 0.0,
        }


__all__ = [
    "RewardService",
    "RewardEngine",
    "RewardConfig",
    "DimensionType",
    "TrustScore",
    "RewardSignal",
]
