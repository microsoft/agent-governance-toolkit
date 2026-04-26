# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Key Rotation for Long-Lived Agents

Automatic Ed25519 key rotation with cryptographic rotation proofs,
key history tracking, and TTL-based auto-rotation while preserving
the agent's DID identity.
"""

import base64
import hashlib
import time
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from agentmesh.exceptions import IdentityError
from agentmesh.identity.agent_id import AgentIdentity


class KeyRotationManager:
    """Manages automatic key rotation for long-lived agents.

    Rotates Ed25519 keypairs while preserving the agent's DID. Old keys are
    kept in history so that signatures made with previous keys can still be
    verified.

    Args:
        identity: The agent identity whose keys will be rotated.
        rotation_ttl_seconds: Seconds between automatic rotations (default 24h).
        max_history: Maximum number of previous keys to retain.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        rotation_ttl_seconds: int = 86400,
        max_history: int = 5,
    ) -> None:
        if identity._private_key is None:
            raise IdentityError("Cannot manage rotation without a private key")

        self._identity = identity
        self._rotation_ttl_seconds = rotation_ttl_seconds
        self._max_history = max_history
        self._last_rotation_time: float = time.monotonic()
        self._key_history: list[dict] = []

    @property
    def identity(self) -> AgentIdentity:
        return self._identity

    # ------------------------------------------------------------------
    # Core rotation
    # ------------------------------------------------------------------

    def rotate(self) -> AgentIdentity:
        """Generate a new keypair, create a rotation proof, and update the identity.

        The old public key and rotation proof are stored in key history.
        The agent's DID remains unchanged.

        Returns:
            The updated AgentIdentity with the new keypair.
        """
        old_private_key = self._identity._private_key
        old_public_key_b64 = self._identity.public_key

        # Generate new keypair
        new_private_key = ed25519.Ed25519PrivateKey.generate()
        new_public_key = new_private_key.public_key()
        new_public_key_bytes = new_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        new_public_key_b64 = base64.b64encode(new_public_key_bytes).decode()

        # Build and store rotation proof
        proof = self._create_rotation_proof(
            old_private_key, old_public_key_b64, new_public_key_b64
        )

        # Record old key in history
        self._key_history.append(
            {
                "public_key": old_public_key_b64,
                "verification_key_id": self._identity.verification_key_id,
                "rotated_at": datetime.utcnow().isoformat(),
                "rotation_proof": proof,
            }
        )

        # Trim history to max_history
        if len(self._key_history) > self._max_history:
            self._key_history = self._key_history[-self._max_history :]

        # Update identity in-place (DID stays the same)
        new_key_id = f"key-{hashlib.sha256(new_public_key_bytes).hexdigest()[:16]}"
        self._identity.public_key = new_public_key_b64
        self._identity.verification_key_id = new_key_id
        self._identity._private_key = new_private_key
        self._identity.updated_at = datetime.utcnow()

        self._last_rotation_time = time.monotonic()

        return self._identity

    def needs_rotation(self) -> bool:
        """Return True if the TTL has elapsed since the last rotation.

        Returns:
            True if the elapsed time exceeds ``rotation_ttl_seconds``.
        """
        elapsed = time.monotonic() - self._last_rotation_time
        return elapsed >= self._rotation_ttl_seconds

    # ------------------------------------------------------------------
    # Rotation proofs
    # ------------------------------------------------------------------

    def get_rotation_proof(self) -> dict:
        """Return the most recent rotation proof.

        Raises:
            IdentityError: If no rotation has occurred yet.
        """
        if not self._key_history:
            raise IdentityError("No rotation has occurred yet")
        return self._key_history[-1]["rotation_proof"]

    @staticmethod
    def verify_rotation(
        old_public_key: str,
        new_public_key: str,
        proof: dict,
    ) -> bool:
        """Verify that a rotation proof correctly links old and new keys.

        Args:
            old_public_key: Base64-encoded old public key.
            new_public_key: Base64-encoded new public key.
            proof: The rotation proof dict produced during rotation.

        Returns:
            True if the proof is valid.
        """
        try:
            if proof.get("old_public_key") != old_public_key:
                return False
            if proof.get("new_public_key") != new_public_key:
                return False

            old_key_bytes = base64.b64decode(old_public_key)
            old_key = ed25519.Ed25519PublicKey.from_public_bytes(old_key_bytes)

            message = proof.get("message", "")
            signature_bytes = base64.b64decode(proof.get("signature", ""))
            old_key.verify(signature_bytes, message.encode())
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Key history
    # ------------------------------------------------------------------

    def get_key_history(self) -> list[dict]:
        """Return the list of previous public keys with rotation timestamps.

        Returns:
            List of dicts with keys ``public_key``, ``verification_key_id``,
            ``rotated_at``, and ``rotation_proof``.
        """
        return list(self._key_history)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _create_rotation_proof(
        old_private_key: ed25519.Ed25519PrivateKey,
        old_public_key_b64: str,
        new_public_key_b64: str,
    ) -> dict:
        """Create a rotation proof: the old key signs the new public key."""
        message = f"rotate:{old_public_key_b64}:{new_public_key_b64}"
        signature = old_private_key.sign(message.encode())
        return {
            "old_public_key": old_public_key_b64,
            "new_public_key": new_public_key_b64,
            "message": message,
            "signature": base64.b64encode(signature).decode(),
            "timestamp": datetime.utcnow().isoformat(),
        }
