# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ed25519 cryptographic helpers for Nexus signature generation and verification.
"""

import base64
import hashlib
import json
import logging
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

if TYPE_CHECKING:
    from .schemas.manifest import AgentManifest

_log = logging.getLogger(__name__)


def generate_keypair() -> tuple[bytes, str]:
    """
    Generate an Ed25519 keypair.

    Returns:
        (private_key_bytes, verification_key_str) where verification_key_str
        has the format "ed25519:<base64_public_key>".
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_bytes, f"ed25519:{base64.b64encode(public_bytes).decode()}"


def sign(private_key_bytes: bytes, message: bytes) -> str:
    """
    Sign a message with an Ed25519 private key.

    Args:
        private_key_bytes: Raw 32-byte Ed25519 private key.
        message: Bytes to sign.

    Returns:
        Base64-encoded signature string.
    """
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return base64.b64encode(private_key.sign(message)).decode()


def verify(verification_key: str, message: bytes, signature: str) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        verification_key: Public key in "ed25519:<base64>" format.
        message: Original message bytes.
        signature: Base64-encoded signature to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if not verification_key.startswith("ed25519:"):
        _log.warning(
            "verify: verification_key does not start with the expected 'ed25519:' prefix: %r",
            verification_key,
        )
        return False

    try:
        key_bytes = base64.b64decode(verification_key[len("ed25519:"):])
        sig_bytes = base64.b64decode(signature)
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(sig_bytes, message)
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        _log.warning("verify: unexpected exception – possible malformed key or signature: %s", exc)
        return False


def manifest_hash_for_signing(manifest: "AgentManifest") -> str:
    """
    Compute the deterministic manifest hash used as the signature message.

    Timestamps and mutable scoring fields are excluded so the hash is stable
    across registration calls and matches what AgentRegistry._compute_manifest_hash
    produces internally.
    """
    data = manifest.model_dump(exclude={
        "registered_at",  # set by registry after verification; unset at signing time
        "last_seen",      # activity timestamp, always None at signing time; changes post-registration
        "trust_score",    # computed by reputation engine after registration; not signed by agent
    })
    canonical = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def escrow_message(requester_did: str, provider_did: str, task_hash: str, credits: int) -> bytes:
    """
    Canonical byte string that the requester signs to authorize an escrow.

    Both ProofOfOutcome.create_escrow() and callers must use this function
    to ensure the signed message and the verified message are identical.
    """
    return f"{requester_did}:{provider_did}:{task_hash}:{credits}".encode()
