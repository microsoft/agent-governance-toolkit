# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Identity

Every agent gets a unique, cryptographically bound identity issued by AgentMesh CA.
Identity persists across restarts; revocation propagates in ≤5s.
"""

from datetime import datetime
from typing import ClassVar, Optional, Literal
from pydantic import BaseModel, Field, field_validator
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import hashlib
import logging
import uuid
import base64

from agentmesh.exceptions import IdentityError, HandshakeError

logger = logging.getLogger(__name__)


class AgentDID(BaseModel):
    """
    Decentralized Identifier for an agent.

    Format: did:mesh:<unique-id>
    """

    method: Literal["mesh"] = "mesh"
    unique_id: str = Field(..., description="Unique identifier within the mesh")

    @classmethod
    def generate(cls, name: str, org: Optional[str] = None) -> "AgentDID":
        """Generate a new DID for an agent."""
        # Create deterministic but unique ID
        seed = f"{name}:{org or 'default'}:{uuid.uuid4().hex[:8]}"
        unique_id = hashlib.sha256(seed.encode()).hexdigest()[:32]
        return cls(unique_id=unique_id)

    @classmethod
    def from_string(cls, did_string: str) -> "AgentDID":
        """Parse a DID string."""
        if not did_string.startswith("did:mesh:"):
            raise ValueError(f"Invalid AgentMesh DID: {did_string}")
        unique_id = did_string[9:]  # Remove "did:mesh:"
        return cls(unique_id=unique_id)

    def __str__(self) -> str:
        return f"did:{self.method}:{self.unique_id}"

    def __hash__(self) -> int:
        return hash(str(self))


class AgentIdentity(BaseModel):
    """
    First-class identity for an AI agent.

    Unlike service accounts, agent identities:
    - Are linked to a human sponsor
    - Have ephemeral credentials
    - Support scope chains
    - Are continuously risk-scored
    """

    did: AgentDID = Field(..., description="Decentralized identifier")
    name: str = Field(..., description="Human-readable agent name")
    description: Optional[str] = Field(None, description="Agent description")

    # Cryptographic identity
    public_key: str = Field(..., description="Ed25519 public key (base64)")
    verification_key_id: str = Field(..., description="Key ID for verification")

    # Human sponsor (accountability)
    sponsor_email: str = Field(..., description="Human sponsor email")
    sponsor_verified: bool = Field(default=False, description="Whether sponsor is verified")

    # Organization
    organization: Optional[str] = Field(None, description="Organization name")
    organization_id: Optional[str] = Field(None, description="Organization identifier")

    # Capabilities (what this agent is allowed to do)
    capabilities: list[str] = Field(default_factory=list)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = Field(None, description="Identity expiration")

    # Status
    status: Literal["active", "suspended", "revoked"] = Field(default="active")
    revocation_reason: Optional[str] = Field(None)

    # Delegation
    parent_did: Optional[str] = Field(None, description="Parent agent DID if delegated")
    delegation_depth: int = Field(default=0, ge=0, description="Depth in scope chain")
    max_initial_trust_score: Optional[int] = Field(
        None,
        description="Lineage-bound trust cap: child's initial trust score "
        "cannot exceed this value (Invariant 6 — Sybil resistance)",
    )

    # Private key stored separately (not serialized)
    _private_key: Optional[ed25519.Ed25519PrivateKey] = None

    model_config = {"arbitrary_types_allowed": True}

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise IdentityError("Agent name must not be empty")
        return v

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        if not v or not v.strip():
            raise IdentityError("Public key must not be empty")
        return v

    @field_validator("sponsor_email")
    @classmethod
    def validate_sponsor_email(cls, v: str) -> str:
        if not v or not v.strip():
            raise IdentityError("Sponsor email must not be empty")
        if "@" not in v:
            raise IdentityError(f"Invalid sponsor email format: {v}")
        return v

    @field_validator("parent_did")
    @classmethod
    def validate_parent_did(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.startswith("did:mesh:"):
            raise IdentityError(
                f"Parent DID must match 'did:mesh:' pattern, got: {v}"
            )
        return v

    @classmethod
    def create(
        cls,
        name: str,
        sponsor: str,
        capabilities: Optional[list[str]] = None,
        organization: Optional[str] = None,
        description: Optional[str] = None,
    ) -> "AgentIdentity":
        """
        Create a new agent identity.

        This is the primary factory method for creating governed agents.
        """
        if not name or not name.strip():
            raise IdentityError("Agent name must not be empty")
        if not sponsor or not sponsor.strip():
            raise IdentityError("Sponsor email must not be empty")
        if "@" not in sponsor:
            raise IdentityError(f"Invalid sponsor email format: {sponsor}")

        # Generate keypair
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Encode public key
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_key_b64 = base64.b64encode(public_key_bytes).decode()

        # Generate DID
        did = AgentDID.generate(name, organization)

        # Create key ID
        key_id = f"key-{hashlib.sha256(public_key_bytes).hexdigest()[:16]}"

        identity = cls(
            did=did,
            name=name,
            description=description,
            public_key=public_key_b64,
            verification_key_id=key_id,
            sponsor_email=sponsor,
            organization=organization,
            capabilities=capabilities or [],
        )

        # Store private key (not serialized)
        identity._private_key = private_key

        return identity

    def sign(self, data: bytes) -> str:
        """Sign data with this agent's private key."""
        if self._private_key is None:
            raise ValueError("Private key not available for signing")

        signature = self._private_key.sign(data)
        return base64.b64encode(signature).decode()

    def verify_signature(self, data: bytes, signature: str) -> bool:
        """Verify a signature against this agent's public key."""
        try:
            public_key_bytes = base64.b64decode(self.public_key)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            signature_bytes = base64.b64decode(signature)
            public_key.verify(signature_bytes, data)
            return True
        except (ValueError, TypeError) as exc:
            logger.debug("Malformed key or signature data: %s", exc)
            return False
        except Exception as exc:
            logger.warning("Signature verification failed: %s", exc)
            return False

    # Maximum delegation depth to prevent Sybil attacks via infinite chains.
    MAX_DELEGATION_DEPTH: ClassVar[int] = 10

    def delegate(
        self,
        name: str,
        capabilities: list[str],
        description: Optional[str] = None,
        max_initial_trust_score: Optional[int] = None,
    ) -> "AgentIdentity":
        """
        Delegate to a child agent with narrowed capabilities.

        The child agent's capabilities MUST be a subset of the parent's.
        This is enforced cryptographically - scope chains can only narrow.

        Lineage-bound trust (Invariant 6): if ``max_initial_trust_score``
        is provided, it is stored on the child identity so that authority
        resolvers can cap the child's initial trust at
        ``min(default_score, parent_score)``. This prevents trust washing
        through sub-agent spawning (Sybil resistance).

        Args:
            name: Name for the child agent.
            capabilities: Capabilities to delegate (must be subset of parent's).
            description: Optional description.
            max_initial_trust_score: Upper bound on the child's initial trust
                score. Typically set to the parent's current trust score.

        Raises:
            ValueError: If capabilities are not a subset, delegation depth
                exceeds MAX_DELEGATION_DEPTH, or wildcard is propagated.
        """
        # V01: Enforce maximum delegation depth
        if self.delegation_depth >= self.MAX_DELEGATION_DEPTH:
            raise ValueError(
                f"Maximum delegation depth ({self.MAX_DELEGATION_DEPTH}) exceeded. "
                f"Current depth: {self.delegation_depth}"
            )

        # V02: Block wildcard capability propagation
        if "*" in capabilities:
            raise ValueError(
                "Cannot delegate wildcard capability '*'. "
                "Explicitly list the capabilities to delegate."
            )

        # Validate capabilities are a subset
        for cap in capabilities:
            if cap not in self.capabilities:
                raise ValueError(
                    f"Cannot delegate capability '{cap}' - not in parent's capabilities"
                )

        # Create child identity
        child = AgentIdentity.create(
            name=name,
            sponsor=self.sponsor_email,
            capabilities=capabilities,
            organization=self.organization,
            description=description,
        )

        # Set delegation metadata
        child.parent_did = str(self.did)
        child.delegation_depth = self.delegation_depth + 1
        child.max_initial_trust_score = max_initial_trust_score

        return child

    def revoke(self, reason: str) -> None:
        """Revoke this identity."""
        self.status = "revoked"
        self.revocation_reason = reason
        self.updated_at = datetime.utcnow()

    def suspend(self, reason: str) -> None:
        """Temporarily suspend this identity."""
        self.status = "suspended"
        self.revocation_reason = reason
        self.updated_at = datetime.utcnow()

    def reactivate(self, *, override_reason: bool = False) -> None:
        """Reactivate a suspended identity.

        Args:
            override_reason: If True, bypass the security-suspension guard.
                Must be explicitly set when reactivating an identity that was
                suspended for security reasons.
        """
        if self.status == "revoked":
            raise ValueError("Cannot reactivate a revoked identity")
        if self.status != "suspended":
            raise ValueError(f"Cannot reactivate identity in '{self.status}' state")
        # Guard against blind reactivation of security suspensions
        if self.revocation_reason and "security" in self.revocation_reason.lower():
            if not override_reason:
                raise ValueError(
                    "Identity was suspended for security reasons — "
                    "pass override_reason=True to force reactivation"
                )
        self.status = "active"
        self.revocation_reason = None
        self.updated_at = datetime.utcnow()

    def is_active(self) -> bool:
        """Check if identity is active and not expired."""
        if self.status != "active":
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    def has_capability(self, capability: str) -> bool:
        """Check if this agent has a specific capability."""
        for cap in self.capabilities:
            if cap == "*":
                return True
            if cap == capability:
                return True
            # Prefix matching: "read:*" matches "read:data" but ":*" is rejected
            if cap.endswith(":*") and len(cap) > 2:
                prefix = cap[:-2]
                if capability.startswith(prefix + ":"):
                    return True
        return False

    def to_jwk(self, include_private: bool = False) -> dict:
        """Export this identity as a JWK (JSON Web Key).

        Args:
            include_private: If True, include the private key. Defaults to False.

        Returns:
            A dict representing the JWK per RFC 7517.
        """
        from agentmesh.identity.jwk import to_jwk

        return to_jwk(self, include_private=include_private)

    @classmethod
    def from_jwk(cls, jwk: dict) -> "AgentIdentity":
        """Create an AgentIdentity from a JWK.

        Args:
            jwk: A dict representing a JWK with Ed25519 key material.

        Returns:
            A new AgentIdentity.
        """
        from agentmesh.identity.jwk import from_jwk

        return from_jwk(jwk)

    def to_jwks(self, include_private: bool = False) -> dict:
        """Export this identity as a JWK Set.

        Args:
            include_private: If True, include private keys. Defaults to False.

        Returns:
            A dict with a "keys" array containing the JWK.
        """
        from agentmesh.identity.jwk import to_jwks

        return to_jwks(self, include_private=include_private)

    @classmethod
    def from_jwks(cls, jwks: dict, kid: str | None = None) -> "AgentIdentity":
        """Import an AgentIdentity from a JWK Set.

        Args:
            jwks: A dict representing a JWK Set.
            kid: Optional key ID to filter by.

        Returns:
            An AgentIdentity from the matching key.
        """
        from agentmesh.identity.jwk import from_jwks

        return from_jwks(jwks, kid=kid)

    # ------------------------------------------------------------------
    # Delegation chain verification (Issue #607)
    # ------------------------------------------------------------------

    @staticmethod
    def verify_delegation_chain(
        identity: "AgentIdentity",
        registry: "IdentityRegistry | None" = None,
        _visited: set[str] | None = None,
    ) -> bool:
        """Verify the entire delegation chain from *identity* to the root.

        Walks ``parent_did`` links, checking at each level that:
        1. The parent exists in *registry* (if supplied) or has no parent.
        2. The child's capabilities are a subset of the parent's.
        3. The delegation depth is consistent.
        4. No circular references exist.

        When *registry* is ``None`` only the leaf identity is validated
        (parent lookup is not possible without a registry).

        Returns ``True`` when the chain is valid, ``False`` otherwise.
        """
        if _visited is None:
            _visited = set()

        did_str = str(identity.did)
        if did_str in _visited:
            # Circular reference detected
            return False
        _visited.add(did_str)

        # Leaf-only validation (no parent → root)
        if identity.parent_did is None:
            return identity.delegation_depth == 0

        # Depth must be > 0 for delegated identities
        if identity.delegation_depth <= 0:
            return False

        if registry is None:
            # Without a registry we can only validate structural consistency
            return identity.delegation_depth > 0

        parent = registry.get(identity.parent_did)
        if parent is None:
            return False

        # Parent must be active
        if not parent.is_active():
            return False

        # Child capabilities must be subset of parent's
        for cap in identity.capabilities:
            if not parent.has_capability(cap):
                return False

        # Depth must be exactly parent + 1
        if identity.delegation_depth != parent.delegation_depth + 1:
            return False

        # Recurse up the chain
        return AgentIdentity.verify_delegation_chain(
            parent, registry, _visited
        )

    def get_effective_capabilities(
        self,
        registry: "IdentityRegistry | None" = None,
    ) -> list[str]:
        """Return the intersection of capabilities across the full chain.

        Walks the delegation chain from this identity to the root,
        returning only capabilities present at *every* level.  If the
        registry is ``None`` or a parent cannot be found, returns this
        identity's own capabilities (the narrowest known set).
        """
        current_caps = set(self.capabilities)

        if self.parent_did is None or registry is None:
            return sorted(current_caps)

        visited: set[str] = {str(self.did)}
        identity: AgentIdentity | None = self

        while identity is not None and identity.parent_did is not None:
            if identity.parent_did in visited:
                break  # circular guard
            visited.add(identity.parent_did)

            parent = registry.get(identity.parent_did)
            if parent is None:
                break
            current_caps &= set(parent.capabilities)
            identity = parent

        return sorted(current_caps)

    def to_did_document(self) -> dict:
        """Export as a DID Document (W3C format)."""
        return {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": str(self.did),
            "verificationMethod": [
                {
                    "id": f"{self.did}#{self.verification_key_id}",
                    "type": "Ed25519VerificationKey2020",
                    "controller": str(self.did),
                    "publicKeyBase64": self.public_key,
                }
            ],
            "authentication": [f"{self.did}#{self.verification_key_id}"],
            "service": [
                {
                    "id": f"{self.did}#agentmesh",
                    "type": "AgentMeshIdentity",
                    "serviceEndpoint": "https://mesh.agentmesh.dev/v1",
                }
            ],
        }


class IdentityRegistry:
    """
    Registry for agent identities.

    In production, this would be backed by a database and the AgentMesh CA.
    """

    def __init__(self, require_attestation: bool = False):
        self._identities: dict[str, AgentIdentity] = {}
        self._by_sponsor: dict[str, list[str]] = {}  # sponsor -> list of DIDs
        self._require_attestation = require_attestation

    def register(self, identity: AgentIdentity) -> None:
        """Register an identity."""
        if self._require_attestation:
            attestation = getattr(identity, 'attestation', None)
            if not attestation or not getattr(attestation, 'verified', False):
                raise HandshakeError(
                    f"Identity {identity.did} rejected: attestation required but not verified"
                )

        did_str = str(identity.did)

        if did_str in self._identities:
            raise ValueError(f"Identity already registered: {did_str}")

        self._identities[did_str] = identity

        # Index by sponsor
        if identity.sponsor_email not in self._by_sponsor:
            self._by_sponsor[identity.sponsor_email] = []
        self._by_sponsor[identity.sponsor_email].append(did_str)

    def get(self, did: str | AgentDID) -> Optional[AgentIdentity]:
        """Get an identity by DID."""
        did_str = str(did) if isinstance(did, AgentDID) else did
        return self._identities.get(did_str)

    def is_trusted(self, agent_did: str) -> bool:
        """Check if an agent DID is trusted in the registry."""
        identity = self._identities.get(agent_did)
        if identity is None:
            return False
        if self._require_attestation:
            attestation = getattr(identity, 'attestation', None)
            return bool(attestation and getattr(attestation, 'verified', False))
        return True

    def revoke(self, did: str | AgentDID, reason: str) -> bool:
        """Revoke an identity and all its delegates."""
        identity = self.get(did)
        if not identity:
            return False

        identity.revoke(reason)

        # Revoke all children
        for child_did, child in self._identities.items():
            if child.parent_did == str(did):
                self.revoke(child_did, f"Parent revoked: {reason}")

        return True

    def get_by_sponsor(self, sponsor_email: str) -> list[AgentIdentity]:
        """Get all identities for a sponsor."""
        dids = self._by_sponsor.get(sponsor_email, [])
        return [self._identities[did] for did in dids if did in self._identities]

    def list_active(self) -> list[AgentIdentity]:
        """List all active identities."""
        return [i for i in self._identities.values() if i.is_active()]
