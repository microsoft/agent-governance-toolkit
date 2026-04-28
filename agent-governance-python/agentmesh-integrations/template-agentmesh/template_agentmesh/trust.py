# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust layer for agent governance.

This module provides the core trust primitives: agent identity, action gating,
and trust score tracking. It has zero external dependencies and can be tested
without the target framework SDK installed.

Rename this module and customize it for your framework. The three extension
points are:

1. AgentProfile — add framework-specific fields (e.g., model name, tool list)
2. ActionGuard.check() — add framework-specific validation logic
3. TrustTracker — adjust reward/penalty or add persistence
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentProfile:
    """Identity and trust state for a governed agent.

    Attributes:
        did: Decentralized identifier in ``did:mesh:`` format.
        name: Human-readable agent name.
        capabilities: Verified capabilities this agent possesses.
        trust_score: Trust level on a 0-1000 scale. Default 500 (neutral).
        status: Lifecycle state — ``active``, ``suspended``, or ``revoked``.
        metadata: Arbitrary key-value pairs for framework-specific data.
    """

    did: str
    name: str
    capabilities: list[str] = field(default_factory=list)
    trust_score: int = 500
    status: str = "active"
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_capability(self, capability: str) -> bool:
        """Check whether this agent has a single capability."""
        return capability in self.capabilities

    def has_all_capabilities(self, required: list[str]) -> bool:
        """Check whether this agent has every capability in the list."""
        return all(c in self.capabilities for c in required)

    def has_any_capability(self, required: list[str]) -> bool:
        """Check whether this agent has at least one capability in the list."""
        return any(c in self.capabilities for c in required)


@dataclass
class ActionResult:
    """Outcome of a trust-gated action check.

    Attributes:
        allowed: Whether the action is permitted.
        agent_did: DID of the agent that was checked.
        action: Name of the action that was evaluated.
        reason: Human-readable explanation (populated on denial).
        trust_score: Agent's trust score at evaluation time.
        timestamp: Unix timestamp of the evaluation.
    """

    allowed: bool
    agent_did: str
    action: str
    reason: str = ""
    trust_score: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary for logging or JSON export."""
        return {
            "allowed": self.allowed,
            "agent_did": self.agent_did,
            "action": self.action,
            "reason": self.reason,
            "trust_score": self.trust_score,
            "timestamp": self.timestamp,
        }


class ActionGuard:
    """Trust-gated action enforcement.

    Checks agent trust score, status, and capabilities before allowing an
    action. Supports per-action minimum trust thresholds for sensitive
    operations and a hard-block list for forbidden actions.

    Args:
        min_trust_score: Global minimum trust score required (0-1000).
        sensitive_actions: Mapping of action names to their elevated
            trust thresholds. Overrides ``min_trust_score`` per action.
        blocked_actions: Actions that are always denied regardless of
            trust score.
    """

    def __init__(
        self,
        min_trust_score: int = 500,
        sensitive_actions: dict[str, int] | None = None,
        blocked_actions: list[str] | None = None,
    ) -> None:
        self.min_trust_score = min_trust_score
        self.sensitive_actions: dict[str, int] = sensitive_actions or {}
        self.blocked_actions: list[str] = blocked_actions or []

    def check(
        self,
        agent: AgentProfile,
        action: str,
        required_capabilities: list[str] | None = None,
    ) -> ActionResult:
        """Evaluate whether an agent may perform an action.

        Checks are applied in order: blocked list, agent status, trust
        threshold, then capabilities. The first failing check produces
        the denial reason.

        Args:
            agent: The agent requesting the action.
            action: Name of the action to evaluate.
            required_capabilities: Capabilities the agent must possess.
                If ``None``, no capability check is performed.

        Returns:
            An ``ActionResult`` indicating whether the action is allowed.
        """
        # Hard block
        if action in self.blocked_actions:
            return ActionResult(
                allowed=False,
                agent_did=agent.did,
                action=action,
                reason=f"Action '{action}' is blocked by policy",
                trust_score=agent.trust_score,
            )

        # Status check
        if agent.status != "active":
            return ActionResult(
                allowed=False,
                agent_did=agent.did,
                action=action,
                reason=f"Agent status is '{agent.status}'",
                trust_score=agent.trust_score,
            )

        # Trust threshold (per-action or global)
        threshold = self.sensitive_actions.get(action, self.min_trust_score)
        if agent.trust_score < threshold:
            return ActionResult(
                allowed=False,
                agent_did=agent.did,
                action=action,
                reason=f"Trust score {agent.trust_score} below threshold {threshold}",
                trust_score=agent.trust_score,
            )

        # Capability check
        if required_capabilities and not agent.has_all_capabilities(required_capabilities):
            missing = [c for c in required_capabilities if not agent.has_capability(c)]
            return ActionResult(
                allowed=False,
                agent_did=agent.did,
                action=action,
                reason=f"Missing capabilities: {missing}",
                trust_score=agent.trust_score,
            )

        return ActionResult(
            allowed=True,
            agent_did=agent.did,
            action=action,
            trust_score=agent.trust_score,
        )


class TrustTracker:
    """Records agent outcomes and adjusts trust scores.

    Uses asymmetric reward/penalty: small reward for success, large penalty
    for failure. This matches the pattern in ``crewai-agentmesh``.

    Scores are clamped to [0, 1000].

    Args:
        reward: Points added on success. Default 10.
        penalty: Points subtracted on failure. Default 50.
    """

    def __init__(self, reward: int = 10, penalty: int = 50) -> None:
        self.reward = reward
        self.penalty = penalty
        self._history: list[dict[str, Any]] = []

    def record_success(self, agent: AgentProfile, action: str) -> int:
        """Reward an agent for a successful action.

        Args:
            agent: The agent to reward. Its ``trust_score`` is modified
                in place.
            action: Name of the action that succeeded.

        Returns:
            The agent's new trust score.
        """
        agent.trust_score = min(1000, agent.trust_score + self.reward)
        self._history.append({
            "did": agent.did,
            "action": action,
            "outcome": "success",
            "new_score": agent.trust_score,
            "timestamp": time.time(),
        })
        return agent.trust_score

    def record_failure(self, agent: AgentProfile, action: str) -> int:
        """Penalize an agent for a failed action.

        Args:
            agent: The agent to penalize. Its ``trust_score`` is modified
                in place.
            action: Name of the action that failed.

        Returns:
            The agent's new trust score.
        """
        agent.trust_score = max(0, agent.trust_score - self.penalty)
        self._history.append({
            "did": agent.did,
            "action": action,
            "outcome": "failure",
            "new_score": agent.trust_score,
            "timestamp": time.time(),
        })
        return agent.trust_score

    def get_history(self, did: str | None = None) -> list[dict[str, Any]]:
        """Return trust history, optionally filtered by agent DID.

        Args:
            did: If provided, return only entries for this agent.

        Returns:
            List of history records (copies, not references).
        """
        if did:
            return [h for h in self._history if h["did"] == did]
        return list(self._history)
