"""
Trust Gate — policy enforcement for A2A task negotiations.

Evaluates incoming A2A task requests against AgentMesh trust policies:
- Minimum trust score thresholds
- Skill-level access control
- Rate limiting per source agent
- DID allow/deny lists
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from a2a_agentmesh.agent_card import AgentCard
from a2a_agentmesh.task import TaskEnvelope, TaskState


@dataclass
class TrustPolicy:
    """Policy configuration for the trust gate."""

    min_trust_score: int = 100
    max_requests_per_minute: int = 60
    allowed_dids: List[str] = field(default_factory=list)
    blocked_dids: List[str] = field(default_factory=list)
    skill_trust_overrides: Dict[str, int] = field(default_factory=dict)
    require_did: bool = True


@dataclass
class TrustResult:
    """Result of a trust evaluation."""

    allowed: bool
    reason: str = ""
    trust_score: int = 0
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "trust_score": self.trust_score,
        }


class TrustGate:
    """
    Evaluates A2A task requests against trust policies.

    Usage:
        gate = TrustGate(policy=TrustPolicy(min_trust_score=200))
        result = gate.evaluate(task_envelope)
        if not result.allowed:
            task_envelope.fail(result.reason)
    """

    def __init__(self, policy: Optional[TrustPolicy] = None) -> None:
        self.policy = policy or TrustPolicy()
        self._rate_tracker: Dict[str, List[float]] = {}
        self._evaluation_log: List[TrustResult] = []

    def evaluate(self, envelope: TaskEnvelope) -> TrustResult:
        """
        Evaluate a task envelope against trust policies.

        Checks (in order):
        1. Source DID is present (if required)
        2. Source DID is not blocked
        3. Source DID is in allow list (if allow list is non-empty)
        4. Trust score meets minimum (or skill-specific override)
        5. Rate limit not exceeded
        """
        # 1. DID required
        if self.policy.require_did and not envelope.source_did:
            result = TrustResult(
                allowed=False,
                reason="Source agent DID is required",
                trust_score=0,
            )
            self._evaluation_log.append(result)
            return result

        # 2. Blocked DID
        if envelope.source_did in self.policy.blocked_dids:
            result = TrustResult(
                allowed=False,
                reason=f"Agent {envelope.source_did} is blocked",
                trust_score=envelope.source_trust_score,
            )
            self._evaluation_log.append(result)
            return result

        # 3. Allow list
        if self.policy.allowed_dids and envelope.source_did not in self.policy.allowed_dids:
            result = TrustResult(
                allowed=False,
                reason=f"Agent {envelope.source_did} not in allow list",
                trust_score=envelope.source_trust_score,
            )
            self._evaluation_log.append(result)
            return result

        # 4. Trust score
        min_score = self.policy.skill_trust_overrides.get(
            envelope.skill_id, self.policy.min_trust_score
        )
        if envelope.source_trust_score < min_score:
            result = TrustResult(
                allowed=False,
                reason=(
                    f"Trust score {envelope.source_trust_score} below "
                    f"minimum {min_score} for skill '{envelope.skill_id}'"
                ),
                trust_score=envelope.source_trust_score,
            )
            self._evaluation_log.append(result)
            return result

        # 5. Rate limit
        now = time.time()
        window_start = now - 60
        did = envelope.source_did
        if did:
            timestamps = self._rate_tracker.get(did, [])
            timestamps = [t for t in timestamps if t > window_start]
            if len(timestamps) >= self.policy.max_requests_per_minute:
                result = TrustResult(
                    allowed=False,
                    reason=f"Rate limit exceeded ({self.policy.max_requests_per_minute}/min)",
                    trust_score=envelope.source_trust_score,
                )
                self._evaluation_log.append(result)
                return result
            timestamps.append(now)
            self._rate_tracker[did] = timestamps

        # All checks passed
        result = TrustResult(
            allowed=True,
            reason="Trust verified",
            trust_score=envelope.source_trust_score,
        )
        self._evaluation_log.append(result)
        return result

    def evaluate_and_gate(self, envelope: TaskEnvelope) -> TrustResult:
        """
        Evaluate and auto-fail the task if trust check fails.

        Returns the TrustResult. If denied, the envelope is transitioned
        to FAILED state with the denial reason.
        """
        result = self.evaluate(envelope)
        if not result.allowed:
            envelope.fail(result.reason)
        return result

    def get_evaluation_log(self) -> List[TrustResult]:
        """Return all evaluation results."""
        return list(self._evaluation_log)

    def clear_rate_limits(self) -> None:
        """Clear rate limit tracking."""
        self._rate_tracker.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Return gate statistics."""
        total = len(self._evaluation_log)
        allowed = sum(1 for r in self._evaluation_log if r.allowed)
        return {
            "total_evaluations": total,
            "allowed": allowed,
            "denied": total - allowed,
            "tracked_agents": len(self._rate_tracker),
        }
