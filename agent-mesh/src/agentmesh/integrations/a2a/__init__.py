# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
A2A Protocol Integration for AgentMesh
=======================================

Provides A2A Agent Cards and trust-gated task delegation using the
AI Card standard for identity verification.

Identity is handled by AI Card (https://github.com/agent-card/ai-card),
not embedded directly in A2A Agent Cards. The A2A integration focuses
on task delegation, state management, and protocol-level concerns.

Example:
    >>> from agentmesh.integrations.a2a import A2AAgentCard, A2ATrustProvider
    >>> from agentmesh.identity import AgentIdentity
    >>>
    >>> identity = AgentIdentity.create(
    ...     name="sql-agent",
    ...     sponsor="human@example.com",
    ...     capabilities=["execute:sql", "read:database"],
    ... )
    >>> card = A2AAgentCard.from_identity(identity, url="https://agent.example.com")
    >>>
    >>> # Standard A2A Agent Card JSON (identity via AI Card)
    >>> card.to_json()
"""

from __future__ import annotations

import json
import logging
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from enum import Enum

from agentmesh.integrations.ai_card.schema import AICard, AICardService

logger = logging.getLogger(__name__)


class A2ATaskState(Enum):
    """A2A Protocol task states."""
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input_required"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass
class A2AAgentCard:
    """
    A2A Agent Card backed by AI Card for identity.

    Standard A2A fields (name, url, skills, capabilities) live here.
    Cryptographic identity (DID, signing, trust scores) is delegated
    to the underlying AICard instance.
    """
    # Standard A2A fields
    name: str
    description: str
    url: str
    version: str = "1.0.0"
    skills: List[Dict[str, Any]] = field(default_factory=list)
    authentication: Dict[str, Any] = field(default_factory=dict)

    # AI Card provides identity, trust, and verifiable metadata
    ai_card: Optional[AICard] = None

    @property
    def agent_did(self) -> str:
        """Agent DID from AI Card identity."""
        if self.ai_card and self.ai_card.identity:
            return self.ai_card.identity.did
        return ""

    @property
    def trust_score(self) -> float:
        """Trust score from AI Card verifiable metadata."""
        if self.ai_card:
            return self.ai_card.verifiable.trust_score
        return 0.0

    @property
    def capabilities(self) -> List[str]:
        """Capabilities from AI Card attestations."""
        if self.ai_card:
            return list(self.ai_card.verifiable.capability_attestations.keys())
        return []

    @classmethod
    def from_identity(
        cls,
        identity: Any,
        url: str,
        description: str = "",
        skills: Optional[List[Dict[str, Any]]] = None,
    ) -> "A2AAgentCard":
        """Create an A2A Agent Card from an AgentIdentity.

        Identity is stored in an AICard; the A2A card references it.

        Args:
            identity: An ``AgentIdentity`` with a private key.
            url: A2A service endpoint URL.
            description: Agent description.
            skills: A2A skill definitions.

        Returns:
            An ``A2AAgentCard`` with a signed AI Card.
        """
        a2a_service = AICardService(
            protocol="a2a",
            url=url,
            metadata={"skills": skills or [], "version": "1.0.0"},
        )
        ai_card = AICard.from_identity(
            identity,
            description=description or f"AgentMesh agent: {identity.did}",
            services=[a2a_service],
        )

        return cls(
            name=identity.name if hasattr(identity, "name") else str(identity.did),
            description=description or f"AgentMesh agent: {identity.did}",
            url=url,
            skills=skills or [],
            authentication={"schemes": ["ai-card", "bearer"]},
            ai_card=ai_card,
        )

    def to_json(self, indent: int = 2) -> str:
        """Export as A2A-compatible JSON.

        Identity is referenced via ``ai_card_url`` pointing to the
        agent's ``/.well-known/ai-card.json`` endpoint rather than
        embedded directly.
        """
        data: Dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "url": self.url,
            "version": self.version,
            "capabilities": {
                "streaming": True,
                "pushNotifications": False,
                "stateTransitionHistory": True,
            },
            "skills": self.skills,
            "authentication": self.authentication,
        }

        # Reference AI Card for identity instead of embedding
        if self.ai_card and self.ai_card.identity:
            data["ai_card_url"] = f"{self.url}/.well-known/ai-card.json"
            data["agent_did"] = self.agent_did

        return json.dumps(data, indent=indent)

    def to_dict(self) -> Dict[str, Any]:
        """Export as dictionary."""
        return json.loads(self.to_json())

    def verify_signature(self) -> bool:
        """Verify identity via the underlying AI Card signature."""
        if not self.ai_card:
            return False
        return self.ai_card.verify_signature()


@dataclass
class A2ATask:
    """A2A Protocol task with trust metadata."""
    task_id: str
    session_id: str
    state: A2ATaskState
    message: Dict[str, Any]

    # Trust metadata
    requester_did: str = ""
    executor_did: str = ""
    trust_verified: bool = False
    trust_level: str = "untrusted"

    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class A2ATrustProvider:
    """
    Trust provider for A2A Protocol interactions.

    Verifies agent identity via AI Card before allowing task delegation.
    """

    def __init__(
        self,
        identity: Any,
        trust_bridge: Any = None,
        min_trust_score: float = 0.3,
    ):
        self.identity = identity
        self.trust_bridge = trust_bridge
        self.min_trust_score = min_trust_score
        self._verified_peers: Dict[str, datetime] = {}
        self._verification_cache_ttl = timedelta(minutes=15)

    async def verify_peer(
        self,
        peer_did: str,
        peer_card: Optional[A2AAgentCard] = None,
    ) -> bool:
        """Verify peer agent before task interaction.

        Verification uses the AI Card attached to the peer's A2A card.

        Args:
            peer_did: Peer agent's DID.
            peer_card: Optional peer's A2A Agent Card.

        Returns:
            True if peer is trusted.
        """
        now = datetime.now(timezone.utc)

        # Check cache
        if peer_did in self._verified_peers:
            cached_time = self._verified_peers[peer_did]
            if now - cached_time < self._verification_cache_ttl:
                logger.debug(f"Using cached trust for {peer_did}")
                return True

        # Verify via AI Card
        if peer_card:
            if not peer_card.verify_signature():
                logger.warning(f"AI Card signature invalid for {peer_did}")
                return False

            if peer_card.trust_score < self.min_trust_score:
                logger.warning(
                    f"Peer {peer_did} trust score {peer_card.trust_score} "
                    f"below minimum {self.min_trust_score}"
                )
                return False

        # Use TrustBridge for handshake if available
        if self.trust_bridge and hasattr(self.trust_bridge, "verify_peer"):
            try:
                result = await self.trust_bridge.verify_peer(peer_did)
                if not result:
                    logger.warning(f"TrustBridge verification failed for {peer_did}")
                    return False
            except Exception as e:
                logger.error(f"Trust verification error: {e}")
                return False

        # Cache successful verification
        self._verified_peers[peer_did] = now
        logger.info(f"Verified trust for peer {peer_did}")
        return True

    async def create_task(
        self,
        peer_did: str,
        message: Dict[str, Any],
        peer_card: Optional[A2AAgentCard] = None,
    ) -> Optional[A2ATask]:
        """Create A2A task with trust verification.

        Args:
            peer_did: Target agent DID.
            message: Task message.
            peer_card: Optional target's A2A Agent Card.

        Returns:
            ``A2ATask`` if trust verified, ``None`` otherwise.
        """
        if not await self.verify_peer(peer_did, peer_card):
            logger.warning(f"Cannot create task - peer {peer_did} not trusted")
            return None

        task_id = hashlib.sha256(
            f"{self.identity.did}:{peer_did}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        task = A2ATask(
            task_id=task_id,
            session_id=f"session-{task_id}",
            state=A2ATaskState.SUBMITTED,
            message=message,
            requester_did=str(self.identity.did) if hasattr(self.identity, "did") else "",
            executor_did=peer_did,
            trust_verified=True,
            trust_level="verified",
        )

        logger.info(f"Created A2A task {task_id} for peer {peer_did}")
        return task

    def get_trust_footer(self) -> Dict[str, Any]:
        """Get trust verification footer for A2A messages."""
        return {
            "trust": {
                "verifier_did": str(self.identity.did) if hasattr(self.identity, "did") else "",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "min_trust_score": self.min_trust_score,
                "verification_method": "ai-card",
            }
        }


# Convenience exports
__all__ = [
    "A2AAgentCard",
    "A2ATask",
    "A2ATaskState",
    "A2ATrustProvider",
]
