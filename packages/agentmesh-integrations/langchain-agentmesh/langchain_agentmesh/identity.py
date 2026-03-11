"""Cryptographic identity management for AgentMesh.

This module provides verification (Cryptographic Multi-Vector Keys) based identity
for LangChain agents, using Ed25519 for cryptographic operations.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# Try to import cryptography for real Ed25519 operations
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


@dataclass
class VerificationSignature:
    """A cryptographic signature from a verification identity."""

    algorithm: str = "verification-Ed25519"
    public_key: str = ""
    signature: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize signature to dictionary."""
        return {
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "signature": self.signature,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationSignature":
        """Deserialize signature from dictionary."""
        timestamp_str = data.get("timestamp")
        return cls(
            algorithm=data.get("algorithm", "verification-Ed25519"),
            public_key=data.get("public_key", ""),
            signature=data.get("signature", ""),
            timestamp=(
                datetime.fromisoformat(timestamp_str)
                if timestamp_str
                else datetime.now(timezone.utc)
            ),
        )


@dataclass
class VerificationIdentity:
    """Cryptographic identity for an agent using verification scheme.

    Uses Ed25519 for real cryptographic signing and verification when the
    `cryptography` library is available, otherwise falls back to simulation
    for demonstration purposes.
    """

    did: str  # Decentralized Identifier
    agent_name: str
    public_key: str  # base64 encoded public key
    private_key: Optional[str] = None  # base64 encoded private key
    capabilities: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None  # Identity expiration for TTL enforcement

    def is_expired(self) -> bool:
        """Check if this identity has expired.

        Returns:
            True if expired, False if still valid or no TTL set
        """
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @classmethod
    def generate(
        cls, agent_name: str, capabilities: Optional[List[str]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> "VerificationIdentity":
        """Generate a new verification identity with Ed25519 key pair.

        Args:
            agent_name: Human-readable name for the agent
            capabilities: List of capabilities this agent has
            ttl_seconds: Optional TTL in seconds (None = no expiry)

        Returns:
            A new VerificationIdentity with generated keys
        """
        # Generate unique DID from agent name and timestamp
        seed = f"{agent_name}:{time.time_ns()}"
        did_hash = hashlib.sha256(seed.encode()).hexdigest()[:32]
        did = f"did:verification:{did_hash}"

        if CRYPTO_AVAILABLE:
            # Generate real Ed25519 key pair
            private_key_obj = ed25519.Ed25519PrivateKey.generate()
            public_key_obj = private_key_obj.public_key()

            private_key_b64 = base64.b64encode(
                private_key_obj.private_bytes_raw()
            ).decode("ascii")
            public_key_b64 = base64.b64encode(
                public_key_obj.public_bytes_raw()
            ).decode("ascii")
        else:
            # Fallback for environments without cryptography
            key_seed = hashlib.sha256(f"{did}:key".encode()).hexdigest()
            private_key_b64 = base64.b64encode(key_seed[:32].encode()).decode("ascii")
            public_key_b64 = base64.b64encode(key_seed[32:].encode()).decode("ascii")

        return cls(
            did=did,
            agent_name=agent_name,
            public_key=public_key_b64,
            private_key=private_key_b64,
            capabilities=capabilities or [],
            expires_at=(
                datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
                if ttl_seconds is not None
                else None
            ),
        )

    def sign(self, data: str) -> VerificationSignature:
        """Sign data with this identity's private key.

        Args:
            data: String data to sign

        Returns:
            VerificationSignature containing the signature

        Raises:
            ValueError: If private key is not available
        """
        if not self.private_key:
            raise ValueError("Cannot sign without private key")

        if CRYPTO_AVAILABLE:
            private_key_bytes = base64.b64decode(self.private_key)
            private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(
                private_key_bytes
            )
            signature_bytes = private_key_obj.sign(data.encode("utf-8"))
            signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
        else:
            # Fallback simulation
            sig_input = f"{data}:{self.private_key}"
            signature_b64 = base64.b64encode(
                hashlib.sha256(sig_input.encode()).digest()
            ).decode("ascii")

        return VerificationSignature(
            public_key=self.public_key,
            signature=signature_b64,
        )

    def verify_signature(self, data: str, signature: VerificationSignature) -> bool:
        """Verify a signature against this identity's public key.

        Args:
            data: The original data that was signed
            signature: The signature to verify

        Returns:
            True if signature is valid, False otherwise
        """
        if signature.public_key != self.public_key:
            return False

        if CRYPTO_AVAILABLE:
            try:
                public_key_bytes = base64.b64decode(self.public_key)
                public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(
                    public_key_bytes
                )
                signature_bytes = base64.b64decode(signature.signature)
                public_key_obj.verify(signature_bytes, data.encode("utf-8"))
                return True
            except (InvalidSignature, ValueError):
                return False
        else:
            # Fallback verification (less secure, for demo only)
            return len(signature.signature) > 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize identity to dictionary (excludes private key)."""
        result = {
            "did": self.did,
            "agent_name": self.agent_name,
            "public_key": self.public_key,
            "capabilities": self.capabilities,
            "created_at": self.created_at.isoformat(),
        }
        if self.expires_at is not None:
            result["expires_at"] = self.expires_at.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationIdentity":
        """Deserialize identity from dictionary."""
        created_str = data.get("created_at")
        expires_str = data.get("expires_at")
        return cls(
            did=data["did"],
            agent_name=data["agent_name"],
            public_key=data["public_key"],
            capabilities=data.get("capabilities", []),
            created_at=(
                datetime.fromisoformat(created_str)
                if created_str
                else datetime.now(timezone.utc)
            ),
            expires_at=(
                datetime.fromisoformat(expires_str)
                if expires_str
                else None
            ),
        )

    def public_identity(self) -> "VerificationIdentity":
        """Return a copy of this identity without the private key."""
        return VerificationIdentity(
            did=self.did,
            agent_name=self.agent_name,
            public_key=self.public_key,
            private_key=None,
            capabilities=self.capabilities.copy(),
            created_at=self.created_at,
            expires_at=self.expires_at,
        )


@dataclass
class UserContext:
    """User context for On-Behalf-Of (OBO) flows.

    When an agent acts on behalf of an end user, this context propagates
    through the trust layer so downstream agents can enforce user-level
    access control.
    """

    user_id: str
    user_email: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        """Check if the user context is still valid."""
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    def has_permission(self, permission: str) -> bool:
        """Check if the user has a specific permission."""
        if "*" in self.permissions:
            return True
        return permission in self.permissions

    def has_role(self, role: str) -> bool:
        """Check if the user has a specific role."""
        return role in self.roles

    @classmethod
    def create(
        cls,
        user_id: str,
        user_email: Optional[str] = None,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        ttl_seconds: int = 3600,
    ) -> "UserContext":
        """Create a new user context with TTL."""
        now = datetime.now(timezone.utc)
        return cls(
            user_id=user_id,
            user_email=user_email,
            roles=roles or [],
            permissions=permissions or [],
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        result: Dict[str, Any] = {
            "user_id": self.user_id,
            "roles": self.roles,
            "permissions": self.permissions,
            "issued_at": self.issued_at.isoformat(),
            "metadata": self.metadata,
        }
        if self.user_email:
            result["user_email"] = self.user_email
        if self.expires_at:
            result["expires_at"] = self.expires_at.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserContext":
        """Deserialize from dictionary."""
        issued_str = data.get("issued_at")
        expires_str = data.get("expires_at")
        return cls(
            user_id=data["user_id"],
            user_email=data.get("user_email"),
            roles=data.get("roles", []),
            permissions=data.get("permissions", []),
            issued_at=(
                datetime.fromisoformat(issued_str)
                if issued_str
                else datetime.now(timezone.utc)
            ),
            expires_at=(
                datetime.fromisoformat(expires_str)
                if expires_str
                else None
            ),
            metadata=data.get("metadata", {}),
        )
