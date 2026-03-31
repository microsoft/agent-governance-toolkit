# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Artifact signing and verification using Ed25519.

Provides :class:`ArtifactSigner` for signing agent build artifacts and
SBOMs, and :class:`SignatureBundle` as the portable verification envelope.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
    )

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

from agent_sre.sbom import AgentSBOM


@dataclass
class SignatureBundle:
    """Portable envelope returned after signing an artifact."""

    signature: bytes
    public_key: bytes
    artifact_hash: str  # SHA-256 hex digest
    timestamp: str  # ISO-8601
    signer_did: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dictionary."""
        return {
            "signature": self.signature.hex(),
            "public_key": self.public_key.hex(),
            "artifact_hash": self.artifact_hash,
            "timestamp": self.timestamp,
            "signer_did": self.signer_did,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignatureBundle:
        """Deserialise from a dictionary."""
        return cls(
            signature=bytes.fromhex(data["signature"]),
            public_key=bytes.fromhex(data["public_key"]),
            artifact_hash=data["artifact_hash"],
            timestamp=data["timestamp"],
            signer_did=data.get("signer_did"),
        )


class ArtifactSigner:
    """Sign and verify agent artifacts using Ed25519.

    If *private_key_path* points to a PEM file the key is loaded from disk;
    otherwise a fresh ephemeral key-pair is generated (useful for tests and
    CI pipelines that generate throw-away signatures).
    """

    def __init__(self, private_key_path: str | None = None) -> None:
        if not _HAS_CRYPTO:
            raise ImportError(
                "cryptography is required for artifact signing. "
                "Install it with: pip install cryptography"
            )
        if private_key_path is not None:
            pem_bytes = Path(private_key_path).read_bytes()
            key = load_pem_private_key(pem_bytes, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise TypeError("Only Ed25519 private keys are supported")
            self._private_key: Ed25519PrivateKey = key
        else:
            self._private_key = Ed25519PrivateKey.generate()

        self._public_key: Ed25519PublicKey = self._private_key.public_key()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte public key."""
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def export_private_key_pem(self) -> bytes:
        """Return the private key as PEM bytes (for persistence)."""
        return self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign_artifact(self, artifact_path: str) -> SignatureBundle:
        """Sign an artifact file and return a :class:`SignatureBundle`."""
        artifact_hash = AgentSBOM.hash_file(artifact_path)
        data = Path(artifact_path).read_bytes()
        signature = self._private_key.sign(data)

        return SignatureBundle(
            signature=signature,
            public_key=self.public_key_bytes,
            artifact_hash=artifact_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def verify_artifact(
        self, artifact_path: str, signature: bytes, public_key: bytes
    ) -> bool:
        """Verify an artifact's signature.

        Args:
            artifact_path: Path to the artifact file.
            signature: The Ed25519 signature bytes.
            public_key: The raw 32-byte Ed25519 public key.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey as PubKey,
        )

        pub = PubKey.from_public_bytes(public_key)
        data = Path(artifact_path).read_bytes()
        try:
            pub.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def sign_sbom(self, sbom: AgentSBOM) -> dict[str, Any]:
        """Sign an SBOM and return an envelope with the signature.

        The envelope wraps the SPDX payload together with a
        :class:`SignatureBundle` so that consumers can verify
        provenance without needing access to the signing key.
        """
        payload = json.dumps(sbom.to_spdx(), sort_keys=True).encode("utf-8")
        signature = self._private_key.sign(payload)
        payload_hash = hashlib.sha256(payload).hexdigest()

        bundle = SignatureBundle(
            signature=signature,
            public_key=self.public_key_bytes,
            artifact_hash=payload_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        return {
            "payload": sbom.to_spdx(),
            "signature": bundle.to_dict(),
        }
