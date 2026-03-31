# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Nexus Cryptography Utilities

Provides Ed25519 signature verification and canonical payload generation.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel


class SignatureError(Exception):
    """Base for all signature-related errors."""


class SignatureDecodeError(SignatureError):
    """Raised when a signature string cannot be decoded."""


class SignatureVerificationError(SignatureError):
    """Raised when a signature does not match the payload."""


def canonical_payload(data: Any) -> bytes:
    """
    Produce a stable, deterministic byte string from a dict or Pydantic model.
    
    Rules:
    - Sort keys to ensure stable output.
    - Remove optional whitespace.
    - Handle Pydantic models by converting to dict.
    - Exclude 'signature' fields if present.
    """
    if isinstance(data, BaseModel):
        # Convert Pydantic model to dict, excluding fields that shouldn't be signed
        # These fields are usually added AFTER signing or are metadata
        raw_data = data.model_dump(exclude={"nexus_signature", "last_seen", "trust_score", "registered_at"})
    elif isinstance(data, dict):
        raw_data = data.copy()
    else:
        raise TypeError(f"Expected dict or BaseModel, got {type(data).__name__}")

    # Ensure the 'signature' field itself is NEVER part of the signable payload
    if "signature" in raw_data:
        del raw_data["signature"]
    if "requester_signature" in raw_data:
        del raw_data["requester_signature"]

    # Generate stable JSON
    return json.dumps(
        raw_data, 
        sort_keys=True, 
        separators=(",", ":"),
        default=str  # Handle datetimes and other non-serializable types
    ).encode("utf-8")


def parse_public_key(key_str: str) -> ed25519.Ed25519PublicKey:
    """
    Parse an Ed25519 public key from a string.
    Expected format: 'ed25519:<base64_encoded_key>'
    """
    if not key_str.startswith("ed25519:"):
        raise ValueError(f"Invalid key format: {key_str}. Expected 'ed25519:<base64>'")
    
    try:
        raw_key = base64.b64decode(key_str.replace("ed25519:", ""))
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
    except Exception as exc:
        raise ValueError(f"Failed to parse public key: {exc}") from exc


def verify_signature(
    public_key_str: str,
    signature_hex: str,
    data: Union[dict, BaseModel]
) -> None:
    """
    Verify a hex-encoded Ed25519 signature against data.
    
    Raises:
        SignatureDecodeError: If the hex string is malformed.
        SignatureVerificationError: If verification fails.
    """
    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise SignatureDecodeError(f"Invalid hex signature: {signature_hex}") from exc

    public_key = parse_public_key(public_key_str)
    payload = canonical_payload(data)

    try:
        public_key.verify(signature_bytes, payload)
    except InvalidSignature as exc:
        raise SignatureVerificationError("Signature verification failed") from exc


def sign_data(private_key: ed25519.Ed25519PrivateKey, data: Union[dict, BaseModel]) -> str:
    """
    Sign data and return a hex-encoded Ed25519 signature.
    """
    payload = canonical_payload(data)
    signature_bytes = private_key.sign(payload)
    return signature_bytes.hex()


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, str]:
    """
    Generate a fresh Ed25519 keypair for testing.
    Returns (private_key_object, public_key_string).
    """
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_str = f"ed25519:{base64.b64encode(pub_bytes).decode('utf-8')}"
    return priv, pub_str
