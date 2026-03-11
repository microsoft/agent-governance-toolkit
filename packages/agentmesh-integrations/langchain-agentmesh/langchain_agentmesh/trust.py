"""Trust verification and handshake protocols for AgentMesh.

This module provides trust verification between agents, including
agent cards, handshakes, and scope chains.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from langchain_agentmesh.identity import VerificationIdentity, VerificationSignature, UserContext


@dataclass
class TrustPolicy:
    """Policy configuration for trust verification."""

    require_verification: bool = True
    min_trust_score: float = 0.7
    allowed_capabilities: Optional[List[str]] = None
    audit_all_calls: bool = False
    block_unverified: bool = True
    cache_ttl_seconds: int = 900  # 15 minutes


@dataclass
class TrustVerificationResult:
    """Result of a trust verification operation."""

    trusted: bool
    trust_score: float
    reason: str
    verified_capabilities: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class TrustedAgentCard:
    """Agent card containing identity and trust information.

    Used for agent discovery and verification in multi-agent systems.
    """

    name: str
    description: str
    capabilities: List[str]
    identity: Optional[VerificationIdentity] = None
    trust_score: float = 1.0
    card_signature: Optional[VerificationSignature] = None
    scope_chain: Optional[List["Delegation"]] = None
    user_context: Optional[UserContext] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def _get_signable_content(self) -> str:
        """Get deterministic content for signing."""
        content = {
            "name": self.name,
            "description": self.description,
            "capabilities": sorted(self.capabilities),
            "trust_score": self.trust_score,
            "identity_did": self.identity.did if self.identity else None,
            "identity_public_key": self.identity.public_key if self.identity else None,
        }
        return json.dumps(content, sort_keys=True, separators=(",", ":"))

    def sign(self, identity: VerificationIdentity) -> None:
        """Cryptographically sign this card with the given identity.

        Args:
            identity: The identity to sign with (must have private key)
        """
        self.identity = identity.public_identity()
        signable = self._get_signable_content()
        self.card_signature = identity.sign(signable)

    def verify_signature(self) -> bool:
        """Verify the card's signature is valid.

        Returns:
            True if signature is valid, False otherwise
        """
        if not self.identity or not self.card_signature:
            return False

        signable = self._get_signable_content()
        return self.identity.verify_signature(signable, self.card_signature)

    def to_json(self) -> Dict[str, Any]:
        """Serialize card to JSON-compatible dictionary."""
        result = {
            "name": self.name,
            "description": self.description,
            "capabilities": self.capabilities,
            "trust_score": self.trust_score,
            "metadata": self.metadata,
        }

        if self.identity:
            result["identity"] = self.identity.to_dict()

        if self.card_signature:
            result["card_signature"] = self.card_signature.to_dict()

        if self.scope_chain:
            result["scope_chain"] = [d.to_dict() for d in self.scope_chain]

        if self.user_context:
            result["user_context"] = self.user_context.to_dict()

        return result

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "TrustedAgentCard":
        """Deserialize card from JSON dictionary."""
        identity = None
        if "identity" in data:
            identity = VerificationIdentity.from_dict(data["identity"])

        card_signature = None
        if "card_signature" in data:
            card_signature = VerificationSignature.from_dict(data["card_signature"])

        scope_chain = None
        if "scope_chain" in data:
            scope_chain = [Delegation.from_dict(d) for d in data["scope_chain"]]

        user_context = None
        if "user_context" in data:
            user_context = UserContext.from_dict(data["user_context"])

        return cls(
            name=data["name"],
            description=data.get("description", ""),
            capabilities=data.get("capabilities", []),
            identity=identity,
            trust_score=data.get("trust_score", 1.0),
            card_signature=card_signature,
            scope_chain=scope_chain,
            user_context=user_context,
            metadata=data.get("metadata", {}),
        )


@dataclass
class Delegation:
    """A delegation of capabilities from one agent to another."""

    delegator: str  # DID of the delegating agent
    delegatee: str  # DID of the receiving agent
    capabilities: List[str]
    signature: Optional[VerificationSignature] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize delegation to dictionary."""
        result = {
            "delegator": self.delegator,
            "delegatee": self.delegatee,
            "capabilities": self.capabilities,
            "created_at": self.created_at.isoformat(),
        }
        if self.signature:
            result["signature"] = self.signature.to_dict()
        if self.expires_at:
            result["expires_at"] = self.expires_at.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Delegation":
        """Deserialize delegation from dictionary."""
        signature = None
        if "signature" in data:
            signature = VerificationSignature.from_dict(data["signature"])

        expires_at = None
        if "expires_at" in data:
            expires_at = datetime.fromisoformat(data["expires_at"])

        return cls(
            delegator=data["delegator"],
            delegatee=data["delegatee"],
            capabilities=data.get("capabilities", []),
            signature=signature,
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=expires_at,
        )


class TrustHandshake:
    """Handles trust verification between agents."""

    def __init__(
        self,
        my_identity: VerificationIdentity,
        policy: Optional[TrustPolicy] = None,
    ):
        """Initialize handshake handler.

        Args:
            my_identity: This agent's identity
            policy: Trust policy to apply (uses defaults if not provided)
        """
        self.my_identity = my_identity
        self.policy = policy or TrustPolicy()
        self._verified_peers: Dict[str, tuple[TrustVerificationResult, datetime]] = {}
        self._cache_ttl = timedelta(seconds=self.policy.cache_ttl_seconds)

    def _get_cached_result(self, did: str) -> Optional[TrustVerificationResult]:
        """Get cached verification result if still valid."""
        if did in self._verified_peers:
            result, timestamp = self._verified_peers[did]
            if datetime.now(timezone.utc) - timestamp < self._cache_ttl:
                return result
            del self._verified_peers[did]
        return None

    def _cache_result(self, did: str, result: TrustVerificationResult) -> None:
        """Cache a verification result."""
        self._verified_peers[did] = (result, datetime.now(timezone.utc))

    def verify_peer(
        self,
        peer_card: TrustedAgentCard,
        required_capabilities: Optional[List[str]] = None,
        min_trust_score: Optional[float] = None,
    ) -> TrustVerificationResult:
        """Verify a peer agent's trustworthiness.

        Args:
            peer_card: The peer's agent card
            required_capabilities: Capabilities the peer must have
            min_trust_score: Minimum trust score required

        Returns:
            TrustVerificationResult with verification status
        """
        warnings: List[str] = []
        min_score = min_trust_score or self.policy.min_trust_score

        # Check for cached result
        if peer_card.identity:
            cached = self._get_cached_result(peer_card.identity.did)
            if cached:
                return cached

        # Verify identity exists
        if not peer_card.identity:
            return TrustVerificationResult(
                trusted=False,
                trust_score=0.0,
                reason="No cryptographic identity provided",
            )

        # Verify DID format
        if not peer_card.identity.did.startswith("did:verification:"):
            return TrustVerificationResult(
                trusted=False,
                trust_score=0.0,
                reason="Invalid DID format",
            )

        # Verify card signature
        if not peer_card.verify_signature():
            return TrustVerificationResult(
                trusted=False,
                trust_score=0.0,
                reason="Card signature verification failed",
            )

        # Check trust score
        if peer_card.trust_score < min_score:
            return TrustVerificationResult(
                trusted=False,
                trust_score=peer_card.trust_score,
                reason=f"Trust score {peer_card.trust_score} below minimum {min_score}",
            )

        # Verify capabilities
        verified_caps = peer_card.capabilities.copy()
        if required_capabilities:
            missing = set(required_capabilities) - set(peer_card.capabilities)
            if missing:
                return TrustVerificationResult(
                    trusted=False,
                    trust_score=peer_card.trust_score,
                    reason=f"Missing required capabilities: {missing}",
                    verified_capabilities=verified_caps,
                )

        # Check scope chain if present
        if peer_card.scope_chain:
            # TODO: A full cryptographic verification of the scope chain is needed.
            # This should verify the signature of each delegation and the integrity of the
            # entire chain. The current check for expiration is insufficient.
            warnings.append(
                "Scope chain is present but its cryptographic validity is not verified."
            )

        # All checks passed
        result = TrustVerificationResult(
            trusted=True,
            trust_score=peer_card.trust_score,
            reason="Verification successful",
            verified_capabilities=verified_caps,
            warnings=warnings,
        )

        # Cache result
        self._cache_result(peer_card.identity.did, result)

        return result

    def clear_cache(self) -> None:
        """Clear all cached verification results."""
        self._verified_peers.clear()


class DelegationChain:
    """Manages a chain of trust delegations."""

    def __init__(self, root_identity: VerificationIdentity):
        """Initialize scope chain.

        Args:
            root_identity: The root authority identity
        """
        self.root_identity = root_identity
        self.delegations: List[Delegation] = []
        self._known_identities: Dict[str, VerificationIdentity] = {
            root_identity.did: root_identity
        }

    def add_delegation(
        self,
        delegatee: TrustedAgentCard,
        capabilities: List[str],
        expires_in_hours: Optional[int] = None,
        delegator_identity: Optional[VerificationIdentity] = None,
    ) -> Delegation:
        """Add a delegation to the chain.

        Args:
            delegatee: The agent receiving the delegation
            capabilities: Capabilities being delegated
            expires_in_hours: Optional expiration time
            delegator_identity: Identity of delegator (root if not specified)

        Returns:
            The created Delegation

        Raises:
            ValueError: If delegatee lacks identity
        """
        if not delegatee.identity:
            raise ValueError("Delegatee must have a VerificationIdentity to be part of a delegation")

        delegator = delegator_identity or self.root_identity
        delegatee_did = delegatee.identity.did

        expires_at = None
        if expires_in_hours:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

        # Create delegation data for signing
        delegation_data = json.dumps({
            "delegator": delegator.did,
            "delegatee": delegatee_did,
            "capabilities": sorted(capabilities),
            "expires_at": expires_at.isoformat() if expires_at else None,
        }, sort_keys=True)

        # Sign with delegator's identity
        signature = delegator.sign(delegation_data)

        delegation = Delegation(
            delegator=delegator.did,
            delegatee=delegatee_did,
            capabilities=capabilities,
            signature=signature,
            expires_at=expires_at,
        )

        self.delegations.append(delegation)

        # Track known identities
        self._known_identities[delegatee_did] = delegatee.identity

        return delegation

    def verify(self) -> bool:
        """Verify the entire scope chain.

        Returns:
            True if chain is valid, False otherwise
        """
        if not self.delegations:
            return True

        for i, delegation in enumerate(self.delegations):
            # Check expiration
            if delegation.expires_at and delegation.expires_at < datetime.now(timezone.utc):
                return False

            # Verify signature
            if not delegation.signature:
                return False

            # Get delegator identity
            delegator_identity = self._known_identities.get(delegation.delegator)
            if not delegator_identity:
                return False

            # Verify delegation signature
            delegation_data = json.dumps({
                "delegator": delegation.delegator,
                "delegatee": delegation.delegatee,
                "capabilities": sorted(delegation.capabilities),
                "expires_at": delegation.expires_at.isoformat() if delegation.expires_at else None,
            }, sort_keys=True)

            if not delegator_identity.verify_signature(delegation_data, delegation.signature):
                return False

            # Verify chain linkage (except for first delegation from root)
            if i > 0:
                prev_delegation = self.delegations[i - 1]
                if delegation.delegator != prev_delegation.delegatee:
                    return False

        return True

    def get_delegated_capabilities(self, agent_did: str) -> List[str]:
        """Get capabilities delegated to an agent.

        Args:
            agent_did: The agent's DID

        Returns:
            List of delegated capabilities
        """
        capabilities: List[str] = []
        for delegation in self.delegations:
            if delegation.delegatee == agent_did:
                # Check if delegation is still valid
                if delegation.expires_at and delegation.expires_at < datetime.now(timezone.utc):
                    continue
                capabilities.extend(delegation.capabilities)
        return list(set(capabilities))


class AgentDirectory:
    """Local directory for discovering trusted agents.

    Provides a framework-level registry so agents can find each other
    by DID or capability without a centralized service dependency.
    Pairs with the core AgentMesh Registry for production deployments.
    """

    def __init__(self) -> None:
        self._cards: Dict[str, TrustedAgentCard] = {}  # did -> card

    def register(self, card: TrustedAgentCard) -> bool:
        """Register an agent card after verifying its signature.

        Args:
            card: The agent card to register

        Returns:
            True if registered, False if signature verification failed
        """
        if not card.identity:
            return False
        if not card.verify_signature():
            return False
        self._cards[card.identity.did] = card
        return True

    def find_by_did(self, did: str) -> Optional[TrustedAgentCard]:
        """Look up an agent by DID.

        Args:
            did: The agent's decentralized identifier

        Returns:
            The agent card if found, None otherwise
        """
        return self._cards.get(did)

    def find_by_capability(self, capability: str) -> List[TrustedAgentCard]:
        """Find all agents that advertise a specific capability.

        Args:
            capability: The capability to search for

        Returns:
            List of agent cards with the capability
        """
        return [
            card for card in self._cards.values()
            if capability in card.capabilities
        ]

    def list_trusted(self, min_trust_score: float = 0.7) -> List[TrustedAgentCard]:
        """List all agents above a minimum trust score.

        Args:
            min_trust_score: Minimum trust score threshold

        Returns:
            List of trusted agent cards
        """
        return [
            card for card in self._cards.values()
            if card.trust_score >= min_trust_score
        ]

    def remove(self, did: str) -> bool:
        """Remove an agent from the directory.

        Args:
            did: The agent's DID

        Returns:
            True if removed, False if not found
        """
        if did in self._cards:
            del self._cards[did]
            return True
        return False

    def count(self) -> int:
        """Return number of registered agents."""
        return len(self._cards)
