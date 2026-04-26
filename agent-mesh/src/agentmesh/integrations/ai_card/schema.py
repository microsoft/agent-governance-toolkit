# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AI Card Schema Models

Data models aligned with the AI Card standard
(https://github.com/agent-card/ai-card).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AICardIdentity(BaseModel):
    """Identity metadata for an AI Card.

    Maps to AI Card spec's identity section, supporting DIDs and
    Ed25519 public keys from AgentMesh's CMVK infrastructure.
    """

    did: str = Field(..., description="Decentralized Identifier (e.g. did:mesh:abc123)")
    public_key: str = Field(..., description="Ed25519 public key (base64)")
    algorithm: str = Field(default="Ed25519", description="Signing algorithm")
    key_id: Optional[str] = Field(None, description="Key identifier for rotation")


class CapabilityAttestation(BaseModel):
    """Cryptographic attestation that an agent has a capability."""

    capability: str = Field(..., description="Capability being attested")
    proof: str = Field(..., description="Base64-encoded cryptographic proof")
    issuer_did: str = Field(..., description="DID of the attestation issuer")
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


class DelegationRecord(BaseModel):
    """Record of capability delegation between agents."""

    delegator_did: str = Field(..., description="DID of the delegating agent")
    delegatee_did: str = Field(..., description="DID of the receiving agent")
    capabilities: List[str] = Field(default_factory=list)
    signature: str = Field(..., description="Cryptographic signature over delegation")
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


class AICardVerifiable(BaseModel):
    """Verifiable metadata for an AI Card.

    Includes trust scores, capability attestations, and scope chains
    that can be cryptographically verified.
    """

    trust_score: float = Field(default=1.0, ge=0.0, le=1.0)
    capability_attestations: Dict[str, CapabilityAttestation] = Field(default_factory=dict)
    scope_chain: List[DelegationRecord] = Field(default_factory=list)


class AICardService(BaseModel):
    """Protocol-specific service entry in an AI Card.

    Each service describes a protocol the agent supports (A2A, MCP, etc.)
    along with its endpoint and protocol-specific metadata.
    """

    protocol: str = Field(..., description="Protocol identifier (e.g. 'a2a', 'mcp')")
    url: str = Field(..., description="Service endpoint URL")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Protocol-specific metadata (A2A skills, MCP tools, etc.)",
    )


class AICardSignature(BaseModel):
    """Cryptographic signature over the AI Card content."""

    algorithm: str = Field(default="Ed25519")
    public_key: str = Field(..., description="Signer's public key (base64)")
    signature: str = Field(..., description="Base64-encoded signature")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AICard(BaseModel):
    """AI Card — cross-protocol agent metadata standard.

    Implements the AI Card spec for agent discovery, identity verification,
    and trust establishment across protocols (A2A, MCP, etc.).

    The card is the canonical identity document for an agent, served at
    ``/.well-known/ai-card.json``.
    """

    # Common server metadata
    name: str = Field(..., description="Agent name")
    description: str = Field(default="", description="Agent description")
    version: str = Field(default="1.0.0", description="Agent version")
    homepage: Optional[str] = Field(None, description="Documentation URL")

    # Identity
    identity: Optional[AICardIdentity] = None

    # Verifiable metadata
    verifiable: AICardVerifiable = Field(default_factory=AICardVerifiable)

    # Protocol services
    services: List[AICardService] = Field(default_factory=list)

    # Card signature
    card_signature: Optional[AICardSignature] = None

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    # Custom extension data
    custom: Dict[str, Any] = Field(default_factory=dict)

    def _get_signable_content(self) -> str:
        """Get deterministic content for signing."""
        content = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
        }
        if self.identity:
            content["identity"] = {
                "did": self.identity.did,
                "public_key": self.identity.public_key,
            }
        if self.expires_at:
            content["expires_at"] = self.expires_at.isoformat()
        content["capabilities"] = sorted(
            a.capability for a in self.verifiable.capability_attestations.values()
        )
        return json.dumps(content, sort_keys=True, separators=(",", ":"))

    def sign(self, identity: Any) -> None:
        """Sign this AI Card with an AgentIdentity.

        Args:
            identity: An ``AgentIdentity`` instance with a private key.
        """
        from agentmesh.identity.agent_id import AgentIdentity

        if not isinstance(identity, AgentIdentity):
            raise TypeError(f"Expected AgentIdentity, got {type(identity).__name__}")

        # Set identity fields from the signer
        self.identity = AICardIdentity(
            did=str(identity.did),
            public_key=identity.public_key,
            key_id=identity.verification_key_id,
        )

        signable = self._get_signable_content()
        signature_b64 = identity.sign(signable.encode())

        self.card_signature = AICardSignature(
            public_key=identity.public_key,
            signature=signature_b64,
        )

    def verify_signature(self) -> bool:
        """Verify the card's signature is valid.

        Returns:
            True if the signature is valid and matches the identity.
        """
        if not self.identity or not self.card_signature:
            return False

        from cryptography.hazmat.primitives.asymmetric import ed25519
        import base64

        try:
            public_key_bytes = base64.b64decode(self.identity.public_key)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            signature_bytes = base64.b64decode(self.card_signature.signature)
            signable = self._get_signable_content()
            public_key.verify(signature_bytes, signable.encode())
            return True
        except Exception:
            return False

    @classmethod
    def from_identity(
        cls,
        identity: Any,
        description: str = "",
        services: Optional[List[AICardService]] = None,
    ) -> "AICard":
        """Create a signed AI Card from an AgentIdentity.

        Args:
            identity: An ``AgentIdentity`` with a private key.
            description: Agent description.
            services: Protocol service entries.

        Returns:
            A signed ``AICard``.
        """
        # Build capability attestations from identity capabilities
        attestations = {}
        for cap in getattr(identity, "capabilities", []):
            sig = identity.sign(f"capability:{cap}".encode())
            attestations[cap] = CapabilityAttestation(
                capability=cap,
                proof=sig,
                issuer_did=str(identity.did),
            )

        card = cls(
            name=identity.name,
            description=description or getattr(identity, "description", "") or "",
            services=services or [],
            verifiable=AICardVerifiable(
                trust_score=1.0,
                capability_attestations=attestations,
            ),
        )
        card.sign(identity)
        return card

    @classmethod
    def from_trusted_agent_card(cls, trusted_card: Any) -> "AICard":
        """Convert a TrustedAgentCard to an AI Card.

        Bridges the existing AgentMesh ``TrustedAgentCard`` format to
        the cross-protocol AI Card standard.

        Args:
            trusted_card: A ``TrustedAgentCard`` instance.

        Returns:
            An ``AICard`` (unsigned — call ``sign()`` to add signature).
        """
        identity = None
        if trusted_card.agent_did and trusted_card.public_key:
            identity = AICardIdentity(
                did=trusted_card.agent_did,
                public_key=trusted_card.public_key,
            )

        return cls(
            name=trusted_card.name,
            description=trusted_card.description,
            identity=identity,
            verifiable=AICardVerifiable(
                trust_score=trusted_card.trust_score,
            ),
            created_at=trusted_card.created_at,
            custom=trusted_card.metadata,
        )

    def to_json(self, indent: int = 2) -> str:
        """Serialize to AI Card JSON for ``/.well-known/ai-card.json``.

        Returns:
            JSON string conforming to the AI Card spec.
        """
        data: Dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
        }

        if self.homepage:
            data["homepage"] = self.homepage

        if self.identity:
            data["identity"] = {
                "did": self.identity.did,
                "public_key": self.identity.public_key,
                "algorithm": self.identity.algorithm,
            }
            if self.identity.key_id:
                data["identity"]["key_id"] = self.identity.key_id

        # Verifiable metadata
        verifiable: Dict[str, Any] = {
            "trust_score": self.verifiable.trust_score,
        }
        if self.verifiable.capability_attestations:
            verifiable["capability_attestations"] = {
                k: {
                    "capability": v.capability,
                    "proof": v.proof,
                    "issuer_did": v.issuer_did,
                    "issued_at": v.issued_at.isoformat(),
                    **({"expires_at": v.expires_at.isoformat()} if v.expires_at else {}),
                }
                for k, v in self.verifiable.capability_attestations.items()
            }
        if self.verifiable.scope_chain:
            verifiable["scope_chain"] = [
                {
                    "delegator_did": d.delegator_did,
                    "delegatee_did": d.delegatee_did,
                    "capabilities": d.capabilities,
                    "signature": d.signature,
                    "issued_at": d.issued_at.isoformat(),
                    **({"expires_at": d.expires_at.isoformat()} if d.expires_at else {}),
                }
                for d in self.verifiable.scope_chain
            ]
        data["verifiable"] = verifiable

        # Services
        if self.services:
            data["services"] = [
                {
                    "protocol": s.protocol,
                    "url": s.url,
                    **({"metadata": s.metadata} if s.metadata else {}),
                }
                for s in self.services
            ]

        if self.card_signature:
            data["card_signature"] = {
                "algorithm": self.card_signature.algorithm,
                "public_key": self.card_signature.public_key,
                "signature": self.card_signature.signature,
                "timestamp": self.card_signature.timestamp.isoformat(),
            }

        if self.expires_at:
            data["expires_at"] = self.expires_at.isoformat()

        if self.custom:
            data["custom"] = self.custom

        return json.dumps(data, indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> "AICard":
        """Deserialize an AI Card from JSON.

        Args:
            json_str: JSON string from ``/.well-known/ai-card.json``.

        Returns:
            Parsed ``AICard`` instance.
        """
        data = json.loads(json_str)

        identity = None
        if "identity" in data:
            identity = AICardIdentity(
                did=data["identity"]["did"],
                public_key=data["identity"]["public_key"],
                algorithm=data["identity"].get("algorithm", "Ed25519"),
                key_id=data["identity"].get("key_id"),
            )

        verifiable = AICardVerifiable()
        if "verifiable" in data:
            v = data["verifiable"]
            attestations = {}
            for k, att in v.get("capability_attestations", {}).items():
                attestations[k] = CapabilityAttestation(
                    capability=att["capability"],
                    proof=att["proof"],
                    issuer_did=att["issuer_did"],
                    issued_at=datetime.fromisoformat(att["issued_at"]),
                    expires_at=datetime.fromisoformat(att["expires_at"]) if att.get("expires_at") else None,
                )
            scope_chain = [
                DelegationRecord(
                    delegator_did=d["delegator_did"],
                    delegatee_did=d["delegatee_did"],
                    capabilities=d["capabilities"],
                    signature=d["signature"],
                    issued_at=datetime.fromisoformat(d["issued_at"]),
                    expires_at=datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None,
                )
                for d in v.get("scope_chain", [])
            ]
            verifiable = AICardVerifiable(
                trust_score=v.get("trust_score", 1.0),
                capability_attestations=attestations,
                scope_chain=scope_chain,
            )

        card_signature = None
        if "card_signature" in data:
            cs = data["card_signature"]
            card_signature = AICardSignature(
                algorithm=cs.get("algorithm", "Ed25519"),
                public_key=cs["public_key"],
                signature=cs["signature"],
                timestamp=datetime.fromisoformat(cs["timestamp"]),
            )

        services = [
            AICardService(
                protocol=s["protocol"],
                url=s["url"],
                metadata=s.get("metadata", {}),
            )
            for s in data.get("services", [])
        ]

        return cls(
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            homepage=data.get("homepage"),
            identity=identity,
            verifiable=verifiable,
            services=services,
            card_signature=card_signature,
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(timezone.utc),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            custom=data.get("custom", {}),
        )
