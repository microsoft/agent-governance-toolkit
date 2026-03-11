"""Lightweight Ed25519 identity manager (zero external dependencies beyond cryptography)."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


@dataclass
class AgentID:
    """Cryptographic identity for a graph agent."""

    did: str
    public_key_bytes: bytes
    capabilities: list[str] = field(default_factory=list)
    _private_key: Ed25519PrivateKey | None = field(default=None, repr=False)

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def sign(self, data: bytes) -> bytes:
        """Sign data with this agent's private key."""
        if self._private_key is None:
            raise ValueError("Cannot sign: no private key (peer identity)")
        return self._private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify a signature against this agent's public key."""
        pub = Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
        try:
            pub.verify(signature, data)
            return True
        except Exception:
            return False

    def has_capability(self, cap: str) -> bool:
        if "*" in self.capabilities:
            return True
        return cap in self.capabilities


class AgentIdentityManager:
    """Create and manage Ed25519-based agent identities. Thread-safe."""

    def __init__(self) -> None:
        self._identities: dict[str, AgentID] = {}
        self._lock = threading.Lock()

    def create_identity(
        self,
        name: str,
        capabilities: list[str] | None = None,
    ) -> AgentID:
        """Generate a new Ed25519 identity for a named agent."""
        private_key = Ed25519PrivateKey.generate()
        pub_bytes = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        did = "did:langgraph:%s" % hashlib.sha256(pub_bytes).hexdigest()[:16]
        identity = AgentID(
            did=did,
            public_key_bytes=pub_bytes,
            capabilities=capabilities or [],
            _private_key=private_key,
        )
        with self._lock:
            self._identities[name] = identity
        return identity

    def get_identity(self, name: str) -> AgentID | None:
        with self._lock:
            return self._identities.get(name)

    def get_or_create(
        self, name: str, capabilities: list[str] | None = None
    ) -> AgentID:
        existing = self.get_identity(name)
        if existing is not None:
            return existing
        return self.create_identity(name, capabilities)

    def register_peer(
        self,
        name: str,
        did: str,
        public_key_bytes: bytes,
        capabilities: list[str] | None = None,
    ) -> AgentID:
        """Register an external peer's identity (no private key)."""
        identity = AgentID(
            did=did,
            public_key_bytes=public_key_bytes,
            capabilities=capabilities or [],
        )
        with self._lock:
            self._identities[name] = identity
        return identity

    @property
    def all_identities(self) -> dict[str, AgentID]:
        with self._lock:
            return dict(self._identities)
