# Copyright (c) 2026 Tom Farley (ScopeBlind).
# Licensed under the MIT License.
"""Ed25519 signing + JCS canonical JSON for sb-runtime decision receipts.

Produces receipts in the format specified by
draft-farley-acta-signed-receipts (Veritas Acta). The output is
bit-compatible with receipts emitted by the sb-runtime Rust binary and
verifies with the @veritasacta/verify reference CLI.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _canonicalize(obj: Any) -> bytes:
    """Produce a JCS-conformant canonical byte string.

    Conforms to RFC 8785 for the payload shapes used by Veritas Acta
    receipts (string keys, string/int/float/bool/null values, nested
    objects and arrays). ASCII-only key enforcement per AIP-0001 is
    applied at the object level.
    """
    _assert_ascii_keys(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _assert_ascii_keys(obj: Any, path: str = "$") -> None:
    if isinstance(obj, Mapping):
        for key in obj.keys():
            if not isinstance(key, str):
                raise ValueError(f"Non-string key at {path}: {key!r}")
            try:
                key.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    f"Non-ASCII key at {path}.{key!r} violates AIP-0001"
                ) from exc
            _assert_ascii_keys(obj[key], f"{path}.{key}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _assert_ascii_keys(item, f"{path}[{i}]")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s = s + ("=" * pad)
    return base64.urlsafe_b64decode(s)


def _jwk_thumbprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": _b64url(raw)}
    digest = hashlib.sha256(_canonicalize(jwk)).digest()
    return _b64url(digest)


@dataclass
class Signer:
    """Thin wrapper around an Ed25519 private key.

    Use ``Signer.generate()`` for ephemeral keys in tests or
    ``Signer.from_pem(pem_bytes)`` to load an operator key.
    """

    private_key: Ed25519PrivateKey
    kid: str

    @classmethod
    def generate(cls, kid: Optional[str] = None) -> "Signer":
        pk = Ed25519PrivateKey.generate()
        resolved_kid = kid or _jwk_thumbprint(pk.public_key())
        return cls(private_key=pk, kid=resolved_kid)

    @classmethod
    def from_pem(cls, pem: bytes, kid: Optional[str] = None) -> "Signer":
        pk = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(pk, Ed25519PrivateKey):
            raise ValueError("PEM must contain an Ed25519 private key")
        resolved_kid = kid or _jwk_thumbprint(pk.public_key())
        return cls(private_key=pk, kid=resolved_kid)

    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


def sign_receipt(
    payload: Mapping[str, Any],
    signer: Signer,
    previous_receipt_hash: Optional[str] = None,
) -> dict:
    """Sign a receipt payload and return the full signed envelope.

    The envelope matches draft-farley-acta-signed-receipts section 2:
    ``{payload: {...}, signature: {alg, kid, sig}}``. If
    ``previous_receipt_hash`` is provided it is inserted into the
    payload before signing, establishing chain linkage.
    """
    final_payload = dict(payload)
    final_payload.setdefault(
        "issued_at", datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    if previous_receipt_hash is not None:
        final_payload["previousReceiptHash"] = previous_receipt_hash

    canonical = _canonicalize(final_payload)
    signature = signer.private_key.sign(canonical)

    return {
        "payload": final_payload,
        "signature": {
            "alg": "EdDSA",
            "kid": signer.kid,
            "sig": _b64url(signature),
        },
    }


def verify_receipt(envelope: Mapping[str, Any], public_key: Ed25519PublicKey) -> bool:
    """Verify a signed receipt envelope against the provided public key.

    Returns True on success; False on any signature or structural
    failure. Raises ValueError for malformed envelopes (missing fields).
    """
    if not isinstance(envelope, Mapping):
        raise ValueError("Envelope must be a mapping")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if payload is None or signature is None:
        raise ValueError("Envelope must contain payload and signature")
    alg = signature.get("alg")
    if alg != "EdDSA":
        return False
    sig_b64 = signature.get("sig")
    if not isinstance(sig_b64, str):
        return False

    canonical = _canonicalize(payload)
    try:
        public_key.verify(_b64url_decode(sig_b64), canonical)
    except InvalidSignature:
        return False
    return True


def receipt_hash(envelope: Mapping[str, Any]) -> str:
    """Compute the chain-linkage hash of a signed receipt.

    Matches the definition used by @veritasacta/verify: SHA-256 of the
    canonical form of the full envelope, base64url-encoded.
    """
    digest = hashlib.sha256(_canonicalize(envelope)).digest()
    return _b64url(digest)
