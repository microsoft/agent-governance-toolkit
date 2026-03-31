# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""LangChain callback handler for AgentMesh trust verification.

Provides automatic trust verification before tool execution and
interaction recording for trust score updates.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from agentmesh.exceptions import TrustVerificationError

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler
    except ImportError:

        class BaseCallbackHandler:  # type: ignore[no-redef]
            """Fallback when langchain is not installed."""

            pass


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
    """Record of a chain/tool interaction for audit purposes."""

    agent_did: str
    event: str
    timestamp: datetime
    success: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class InMemoryTrustStore:
    """Simple in-memory trust store for testing and development."""

    def __init__(self, default_score: int = 500) -> None:
        self._scores: Dict[str, int] = {}
        self._default_score = default_score

    def get_trust_score(self, agent_did: str) -> int:
        return self._scores.get(agent_did, self._default_score)

    def set_trust_score(self, agent_did: str, score: int) -> None:
        self._scores[agent_did] = max(0, min(1000, score))

    def record_interaction(self, agent_did: str, *, success: bool) -> None:
        current = self.get_trust_score(agent_did)
        delta = 5 if success else -10
        self.set_trust_score(agent_did, current + delta)


class AgentMeshTrustCallback(BaseCallbackHandler):  # type: ignore[misc]
    """LangChain callback handler that enforces AgentMesh trust verification.

    Verifies agent trust scores before tool execution and records
    interaction outcomes for trust score updates.

    Args:
        agent_did: The DID of the agent using this callback.
        min_trust_score: Minimum trust score (0–1000) required for tool execution.
        trust_store: Optional trust store backend. Uses InMemoryTrustStore if None.

    Example::

        from agentmesh.integrations.langchain import AgentMeshTrustCallback

        callback = AgentMeshTrustCallback(
            agent_did="did:mesh:abc123",
            min_trust_score=500,
        )
        # Attach to a LangChain chain or agent
        chain.invoke(input, config={"callbacks": [callback]})
    """

    def __init__(
        self,
        agent_did: str,
        min_trust_score: int = 500,
        trust_store: Optional[Any] = None,
    ) -> None:
        super().__init__()
        self.agent_did = agent_did
        self.min_trust_score = min_trust_score
        self.trust_store: Any = trust_store or InMemoryTrustStore()
        self._interactions: List[InteractionRecord] = []

    def _verify_trust(self, context: str) -> int:
        """Check agent trust score against threshold.

        Args:
            context: Description of the operation being verified.

        Returns:
            The current trust score.

        Raises:
            TrustVerificationError: If trust score is below the minimum.
        """
        score = self.trust_store.get_trust_score(self.agent_did)
        if score < self.min_trust_score:
            raise TrustVerificationError(
                f"Agent {self.agent_did} trust score {score} "
                f"below required {self.min_trust_score} for {context}"
            )
        return score

    def _record(self, event: str, *, success: bool, **metadata: Any) -> None:
        """Record an interaction and update the trust store."""
        self._interactions.append(
            InteractionRecord(
                agent_did=self.agent_did,
                event=event,
                timestamp=datetime.now(timezone.utc),
                success=success,
                metadata=metadata,
            )
        )
        self.trust_store.record_interaction(self.agent_did, success=success)

    # ── Tool callbacks ──────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Verify agent trust before tool execution."""
        tool_name = serialized.get("name", "unknown")
        score = self._verify_trust(f"tool:{tool_name}")
        logger.info(
            "Trust verified for tool %s (agent=%s, score=%d)",
            tool_name,
            self.agent_did,
            score,
        )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Record successful tool execution."""
        self._record("tool_end", success=True, output_preview=str(output)[:200])

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Record tool failure."""
        self._record("tool_error", success=False, error=str(error))

    # ── Chain callbacks ─────────────────────────────────────────────

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Log chain start with agent DID."""
        chain_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        logger.info(
            "Chain started: %s (agent=%s)",
            chain_name,
            self.agent_did,
        )

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        """Record successful chain interaction."""
        self._record("chain_end", success=True)

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        """Record failed chain interaction and update trust."""
        self._record("chain_error", success=False, error=str(error))

    # ── LLM callbacks ───────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Optional trust check before LLM calls."""
        model = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        score = self._verify_trust(f"llm:{model}")
        logger.info(
            "Trust verified for LLM %s (agent=%s, score=%d)",
            model,
            self.agent_did,
            score,
        )

    # ── Inspection ──────────────────────────────────────────────────

    def get_interactions(self) -> List[InteractionRecord]:
        """Return a copy of the interaction audit log."""
        return self._interactions.copy()

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics for this callback."""
        successes = sum(1 for r in self._interactions if r.success)
        failures = len(self._interactions) - successes
        return {
            "agent_did": self.agent_did,
            "min_trust_score": self.min_trust_score,
            "total_interactions": len(self._interactions),
            "successes": successes,
            "failures": failures,
            "current_score": self.trust_store.get_trust_score(self.agent_did),
        }
