# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""CrewAI trust-aware agent wrapper.

Provides a wrapper/mixin pattern for CrewAI agents that enforces
AgentMesh trust verification before inter-agent delegation.
CrewAI is an optional dependency.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from agentmesh.exceptions import TrustViolationError

logger = logging.getLogger(__name__)


@runtime_checkable
class TrustStore(Protocol):
    """Protocol for trust score storage backends."""

    def get_trust_score(self, agent_did: str) -> int:
        """Return current trust score (0–1000) for an agent."""
        ...

    def record_interaction(self, agent_did: str, *, success: bool) -> None:
        """Record an interaction outcome for trust updates."""
        ...


@dataclass
class InteractionRecord:
    """Record of a delegation or task execution for audit purposes."""

    from_did: str
    to_did: str
    timestamp: datetime
    success: bool
    event: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class InMemoryTrustStore:
    """Simple in-memory trust store for testing and development."""

    # V33: Rate-limit trust updates to prevent inflation via rapid success spam
    MAX_UPDATES_PER_MINUTE = 10

    def __init__(self, default_score: int = 500) -> None:
        self._scores: Dict[str, int] = {}
        self._default_score = default_score
        self._update_times: Dict[str, list] = {}

    def get_trust_score(self, agent_did: str) -> int:
        return self._scores.get(agent_did, self._default_score)

    def set_trust_score(self, agent_did: str, score: int) -> None:
        self._scores[agent_did] = max(0, min(1000, score))

    def record_interaction(self, agent_did: str, *, success: bool) -> None:
        from datetime import datetime as _dt
        now = _dt.utcnow()
        # V33: Enforce rate limit on score updates
        times = self._update_times.setdefault(agent_did, [])
        cutoff = now.timestamp() - 60
        times[:] = [t for t in times if t > cutoff]
        if len(times) >= self.MAX_UPDATES_PER_MINUTE:
            return  # silently drop — rate limited
        times.append(now.timestamp())

        current = self.get_trust_score(agent_did)
        delta = 5 if success else -10
        self.set_trust_score(agent_did, current + delta)


class TrustAwareAgent:
    """Wrapper that adds AgentMesh trust verification to CrewAI agents.

    Uses a wrapper/mixin pattern so CrewAI does not need to be installed.
    When CrewAI is available, the inner ``crewai_agent`` is used for
    actual task execution; otherwise only trust operations are available.

    Args:
        agent_did: The DID of this agent (e.g. ``did:mesh:abc123``).
        min_trust_score: Minimum trust score (0–1000) required for delegation.
        trust_store: Optional trust store backend. Uses InMemoryTrustStore if None.
        **kwargs: Forwarded to CrewAI Agent constructor when crewai is installed.

    Example::

        from agentmesh.integrations.crewai import TrustAwareAgent

        agent = TrustAwareAgent(
            agent_did="did:mesh:abc123",
            min_trust_score=600,
            role="Researcher",
            goal="Find relevant papers",
        )
    """

    def __init__(
        self,
        agent_did: str,
        min_trust_score: int = 500,
        trust_store: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        self.agent_did = agent_did
        self.min_trust_score = min_trust_score
        self.trust_store: Any = trust_store or InMemoryTrustStore()
        self._interactions: List[InteractionRecord] = []
        self._crewai_kwargs = kwargs
        self.crewai_agent: Any = None

        try:
            from crewai import Agent as CrewAIAgent

            self.crewai_agent = CrewAIAgent(**kwargs)
        except ImportError:
            logger.debug("crewai not installed; trust-only mode active")

    def verify_peer(self, peer_did: str) -> bool:
        """Check if a peer agent meets the trust threshold.

        Args:
            peer_did: DID of the peer agent to verify.

        Returns:
            True if the peer's trust score meets the minimum threshold.
        """
        score = self.trust_store.get_trust_score(peer_did)
        return score >= self.min_trust_score

    def execute_with_trust(self, task: Any, context: Any = None) -> Any:
        """Execute a task with trust verification for any delegation.

        Verifies this agent's own trust score before execution and
        records the interaction outcome.

        Args:
            task: The task to execute (CrewAI Task or plain description).
            context: Optional context for task execution.

        Returns:
            Task execution result.

        Raises:
            TrustViolationError: If this agent's trust score is below threshold.
        """
        score = self.trust_store.get_trust_score(self.agent_did)
        if score < self.min_trust_score:
            self._record(self.agent_did, self.agent_did, "execute", success=False)
            raise TrustViolationError(
                f"Agent {self.agent_did} trust score {score} "
                f"below required {self.min_trust_score} for task execution"
            )

        try:
            if self.crewai_agent is not None:
                result = self.crewai_agent.execute_task(task, context)
            else:
                result = {"status": "executed", "task": str(task), "agent": self.agent_did}
            self._record(self.agent_did, self.agent_did, "execute", success=True)
            return result
        except Exception as exc:
            self._record(self.agent_did, self.agent_did, "execute", success=False)
            raise exc

    def delegate_with_trust(self, task: Any, peer_did: str) -> Any:
        """Delegate a task to a peer only if the peer is trusted.

        Args:
            task: The task to delegate.
            peer_did: DID of the peer agent to delegate to.

        Returns:
            Delegation result.

        Raises:
            TrustViolationError: If the peer's trust score is below threshold.
        """
        score = self.trust_store.get_trust_score(peer_did)
        if score < self.min_trust_score:
            self._record(self.agent_did, peer_did, "delegate", success=False)
            raise TrustViolationError(
                f"Peer {peer_did} trust score {score} "
                f"below required {self.min_trust_score} for delegation"
            )

        self._record(self.agent_did, peer_did, "delegate", success=True)
        return {"status": "delegated", "task": str(task), "from": self.agent_did, "to": peer_did}

    def get_trust_report(self) -> dict:
        """Get trust status summary for this agent.

        Returns:
            Dictionary with agent DID, current score, threshold,
            interaction counts, and full interaction history.
        """
        successes = sum(1 for r in self._interactions if r.success)
        failures = len(self._interactions) - successes
        return {
            "agent_did": self.agent_did,
            "current_score": self.trust_store.get_trust_score(self.agent_did),
            "min_trust_score": self.min_trust_score,
            "total_interactions": len(self._interactions),
            "successes": successes,
            "failures": failures,
            "interactions": [
                {
                    "from": r.from_did,
                    "to": r.to_did,
                    "event": r.event,
                    "success": r.success,
                    "timestamp": r.timestamp.isoformat(),
                }
                for r in self._interactions
            ],
        }

    def _record(
        self, from_did: str, to_did: str, event: str, *, success: bool
    ) -> None:
        """Record an interaction and update the trust store."""
        self._interactions.append(
            InteractionRecord(
                from_did=from_did,
                to_did=to_did,
                timestamp=datetime.now(timezone.utc),
                success=success,
                event=event,
            )
        )
        self.trust_store.record_interaction(to_did, success=success)
