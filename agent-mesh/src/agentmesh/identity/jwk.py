# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
JWK (JSON Web Key) export/import for AgentIdentity.

Provides RFC 7517-compliant JWK serialization for Ed25519 agent keys,
enabling OAuth/OIDC interoperability and standard key exchange.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from agentmesh.exceptions import IdentityError

if TYPE_CHECKING:
    from agentmesh.identity.agent_id import AgentIdentity


def _base64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding per RFC 7515."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s: str) -> bytes:
    """Decode base64url string without padding per RFC 7515."""
    # Add padding back
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def to_jwk(identity: AgentIdentity, include_private: bool = False) -> dict:
    """Export an AgentIdentity as a JWK (JSON Web Key).

    Args:
        identity: The agent identity to export.
        include_private: If True, include the private key ("d" parameter).
            Defaults to False for security.

    Returns:
        A dict representing the JWK.

    Raises:
        IdentityError: If include_private is True but no private key is available.
    """
    public_key_bytes = base64.b64decode(identity.public_key)
    jwk: dict = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _base64url_encode(public_key_bytes),
        "kid": str(identity.did),
        "use": "sig",
    }

    if include_private:
        if identity._private_key is None:
            raise IdentityError("Private key not available for export")
        private_bytes = identity._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        jwk["d"] = _base64url_encode(private_bytes)

    return jwk


def from_jwk(jwk: dict) -> AgentIdentity:
    """Create an AgentIdentity from a JWK.

    Args:
        jwk: A dict representing a JWK with Ed25519 key material.

    Returns:
        A new AgentIdentity with the key material from the JWK.

    Raises:
        IdentityError: If the JWK is invalid or has wrong key type/curve.
    """
    from agentmesh.identity.agent_id import AgentIdentity, AgentDID

    if not isinstance(jwk, dict):
        raise IdentityError("JWK must be a dict")
    if jwk.get("kty") != "OKP":
        raise IdentityError(f"Unsupported key type: {jwk.get('kty')}, expected 'OKP'")
    if jwk.get("crv") != "Ed25519":
        raise IdentityError(f"Unsupported curve: {jwk.get('crv')}, expected 'Ed25519'")
    if "x" not in jwk:
        raise IdentityError("JWK missing required 'x' parameter")

    try:
        public_key_bytes = _base64url_decode(jwk["x"])
    except Exception as e:
        raise IdentityError(f"Invalid base64url in 'x' parameter: {e}") from e

    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except Exception as e:
        raise IdentityError(f"Invalid Ed25519 public key in JWK: {e}") from e
    public_key_b64 = base64.b64encode(public_key_bytes).decode()

    # Recover DID from kid if present
    kid = jwk.get("kid", "")
    if kid.startswith("did:mesh:"):
        did = AgentDID.from_string(kid)
    else:
        did = AgentDID.generate("imported-agent")

    import hashlib

    key_id = f"key-{hashlib.sha256(public_key_bytes).hexdigest()[:16]}"

    identity = AgentIdentity(
        did=did,
        name="imported-agent",
        public_key=public_key_b64,
        verification_key_id=key_id,
        sponsor_email="imported@agentmesh.dev",
    )

    # Restore private key if present
    if "d" in jwk:
        try:
            private_bytes = _base64url_decode(jwk["d"])
            identity._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        except Exception as e:
            raise IdentityError(f"Invalid private key in JWK: {e}") from e

    return identity


def to_jwks(identity: AgentIdentity, include_private: bool = False) -> dict:
    """Export an AgentIdentity as a JWK Set.

    Args:
        identity: The agent identity to export.
        include_private: If True, include private keys. Defaults to False.

    Returns:
        A dict representing the JWK Set ({"keys": [jwk]}).
    """
    return {"keys": [to_jwk(identity, include_private=include_private)]}


def from_jwks(jwks: dict, kid: str | None = None) -> AgentIdentity:
    """Import an AgentIdentity from a JWK Set.

    Args:
        jwks: A dict representing a JWK Set.
        kid: Optional key ID to filter by. If None, uses the first key.

    Returns:
        An AgentIdentity created from the matching JWK.

    Raises:
        IdentityError: If the JWK Set is invalid or no matching key is found.
    """
    if not isinstance(jwks, dict) or "keys" not in jwks:
        raise IdentityError("Invalid JWK Set: missing 'keys' array")

    keys = jwks["keys"]
    if not isinstance(keys, list) or len(keys) == 0:
        raise IdentityError("JWK Set contains no keys")

    if kid is not None:
        matching = [k for k in keys if k.get("kid") == kid]
        if not matching:
            raise IdentityError(f"No key found with kid: {kid}")
        return from_jwk(matching[0])

    return from_jwk(keys[0])
