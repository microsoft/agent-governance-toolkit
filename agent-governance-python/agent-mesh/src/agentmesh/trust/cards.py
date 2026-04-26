# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trusted Agent Cards

Agent cards for discovery and verification with cryptographic signing.
Based on learnings from A2A Protocol integration review.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import json

from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.identity.revocation import RevocationList


class TrustedAgentCard(BaseModel):
    """
    Agent card for discovery and verification.

    Cards are cryptographically signed to prevent impersonation.
    Based on A2A Protocol's agent card extension pattern.
    """

    # Basic info
    name: str = Field(..., description="Agent name")
    description: str = Field(default="", description="Agent description")
    capabilities: List[str] = Field(default_factory=list)

    # Identity (public info only)
    agent_did: Optional[str] = Field(None, description="Agent DID")
    public_key: Optional[str] = Field(None, description="Public key for verification")

    # Trust metadata
    trust_score: float = Field(default=1.0, ge=0.0, le=1.0)

    # Cryptographic signature over card content
    card_signature: Optional[str] = Field(None, description="Signature over card content")
    signature_timestamp: Optional[datetime] = None

    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def _get_signable_content(self) -> str:
        """Get deterministic content for signing."""
        content = {
            "name": self.name,
            "description": self.description,
            "capabilities": sorted(self.capabilities),
            "trust_score": self.trust_score,
            "agent_did": self.agent_did,
            "public_key": self.public_key,
        }
        return json.dumps(content, sort_keys=True, separators=(",", ":"))

    def sign(self, identity: AgentIdentity) -> None:
        """
        Cryptographically sign this card with the given identity.

        The signature covers the card's core content to prevent tampering.
        After signing, the card can be verified by anyone with the public key.

        Args:
            identity: The identity to sign with (must have private key)
        """
        self.agent_did = str(identity.did)
        self.public_key = identity.public_key

        signable = self._get_signable_content()
        self.card_signature = identity.sign(signable.encode())
        self.signature_timestamp = datetime.now(timezone.utc)

    def verify_signature(self, identity: Optional[AgentIdentity] = None) -> bool:
        """
        Verify the card's signature is valid.

        Args:
            identity: Optional identity to verify against. If not provided,
                     uses the public key embedded in the card.

        Returns:
            True if signature is valid, False otherwise
        """
        if not self.card_signature or not self.public_key:
            return False

        signable = self._get_signable_content()

        if identity:
            return identity.verify_signature(signable.encode(), self.card_signature)

        # Verify using embedded public key
        # This requires reconstructing a minimal identity for verification
        from cryptography.hazmat.primitives.asymmetric import ed25519
        import base64

        try:
            public_key_bytes = base64.b64decode(self.public_key)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            signature_bytes = base64.b64decode(self.card_signature)
            public_key.verify(signature_bytes, signable.encode())
            return True
        except Exception:
            return False

    @classmethod
    def from_identity(cls, identity: AgentIdentity) -> "TrustedAgentCard":
        """
        Create a signed card from an identity.

        Args:
            identity: The identity to create a card for

        Returns:
            A signed TrustedAgentCard
        """
        card = cls(
            name=identity.name,
            description=identity.description or "",
            capabilities=identity.capabilities,
        )
        card.sign(identity)
        return card

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the card to a plain dictionary.

        Includes identity and signature fields only when they are
        populated.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        result = {
            "name": self.name,
            "description": self.description,
            "capabilities": self.capabilities,
            "trust_score": self.trust_score,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }
        if self.agent_did:
            result["agent_did"] = self.agent_did
        if self.public_key:
            result["public_key"] = self.public_key
        if self.card_signature:
            result["card_signature"] = self.card_signature
            result["signature_timestamp"] = self.signature_timestamp.isoformat() if self.signature_timestamp else None
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustedAgentCard":
        """Deserialize a card from a dictionary.

        Performs safe access on all keys so missing values fall back to
        sensible defaults.

        Args:
            data: Dictionary previously produced by :meth:`to_dict` or
                an equivalent external source.

        Returns:
            A ``TrustedAgentCard`` instance.
        """
        signature_ts = data.get("signature_timestamp")
        created_at = data.get("created_at")

        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            capabilities=data.get("capabilities", []),
            agent_did=data.get("agent_did"),
            public_key=data.get("public_key"),
            trust_score=data.get("trust_score", 1.0),
            card_signature=data.get("card_signature"),
            signature_timestamp=datetime.fromisoformat(signature_ts) if signature_ts else None,
            metadata=data.get("metadata", {}),
            created_at=datetime.fromisoformat(created_at) if created_at else datetime.now(timezone.utc),
        )


class CardRegistry:
    """
    Registry for trusted agent cards.

    Provides discovery and caching of verified cards.
    Optionally integrates with a ``RevocationList`` to reject cards
    whose agent DID has been revoked.
    """

    def __init__(
        self,
        cache_ttl_seconds: int = 900,
        revocation_list: Optional["RevocationList"] = None,
    ):
        """Initialise the card registry.

        Args:
            cache_ttl_seconds: Time-to-live in seconds for the
                verification cache. Defaults to 900 (15 minutes).
            revocation_list: Optional revocation list to check during
                verification. When set, revoked agent DIDs fail
                ``is_verified()`` even if their signatures are valid.
        """
        self._cards: Dict[str, TrustedAgentCard] = {}
        self._verified_cache: Dict[str, tuple[bool, datetime]] = {}
        self._cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self._revocation_list = revocation_list

    def register(self, card: TrustedAgentCard) -> bool:
        """
        Register a card after verifying its signature.

        Args:
            card: The card to register

        Returns:
            True if registered successfully, False if verification failed
        """
        if not card.verify_signature():
            return False

        if card.agent_did:
            self._cards[card.agent_did] = card
            self._verified_cache[card.agent_did] = (True, datetime.now(timezone.utc))

        return True

    def get(self, agent_did: str) -> Optional[TrustedAgentCard]:
        """Get a registered card by agent DID.

        Args:
            agent_did: The agent's decentralized identifier.

        Returns:
            The ``TrustedAgentCard``, or ``None`` if not registered.
        """
        return self._cards.get(agent_did)

    @property
    def revocation_list(self) -> Optional["RevocationList"]:
        """The attached revocation list, if any."""
        return self._revocation_list

    @revocation_list.setter
    def revocation_list(self, value: Optional["RevocationList"]) -> None:
        self._revocation_list = value
        self.clear_cache()

    def is_verified(self, agent_did: str) -> bool:
        """
        Check if a card is verified (with caching).

        Uses TTL-based caching to avoid repeated verification.
        Returns False if the agent DID is on the revocation list,
        even if the cryptographic signature is valid.
        """
        # Revocation check always runs (not cached — revocations are instant)
        if self._revocation_list and self._revocation_list.is_revoked(agent_did):
            self._verified_cache.pop(agent_did, None)
            return False

        if agent_did in self._verified_cache:
            verified, timestamp = self._verified_cache[agent_did]
            if datetime.now(timezone.utc) - timestamp < self._cache_ttl:
                return verified

        card = self._cards.get(agent_did)
        if not card:
            return False

        verified = card.verify_signature()
        self._verified_cache[agent_did] = (verified, datetime.now(timezone.utc))
        return verified

    def clear_cache(self) -> None:
        """Clear the verification cache.

        Subsequent calls to :meth:`is_verified` will re-verify
        signatures from scratch.
        """
        self._verified_cache.clear()

    def list_cards(self) -> List[TrustedAgentCard]:
        """List all registered agent cards.

        Returns:
            List of every ``TrustedAgentCard`` in the registry.
        """
        return list(self._cards.values())

    def find_by_capability(self, capability: str) -> List[TrustedAgentCard]:
        """Find registered cards that advertise a specific capability.

        Args:
            capability: Capability string to search for.

        Returns:
            List of ``TrustedAgentCard`` instances whose
            ``capabilities`` list contains the given string.
        """
        return [
            card for card in self._cards.values()
            if capability in card.capabilities
        ]
