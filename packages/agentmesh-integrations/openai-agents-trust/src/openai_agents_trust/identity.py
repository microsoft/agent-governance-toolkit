"""Lightweight agent identity using Ed25519 signatures."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class AgentIdentity:
    """Represents a verifiable agent identity.

    Uses a simple HMAC-based scheme for identity verification without
    requiring heavy cryptographic dependencies. For production Ed25519,
    use the full agentmesh package.
    """

    agent_id: str
    name: str
    secret_key: str = field(repr=False)
    created_at: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)

    @property
    def did(self) -> str:
        """Generate a DID-like identifier from the agent_id."""
        digest = hashlib.sha256(self.agent_id.encode()).hexdigest()[:16]
        return f"did:agentmesh:{digest}"

    def sign(self, message: str) -> str:
        """Sign a message with this identity's secret key."""
        return hmac.new(
            self.secret_key.encode(), message.encode(), hashlib.sha256
        ).hexdigest()

    def verify(self, message: str, signature: str) -> bool:
        """Verify a signature against this identity."""
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "did": self.did,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }
