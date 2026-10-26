"""Check a signed Parmana record before acting on it."""

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from parmana_verifier.canonical import canonical_bytes
from parmana_verifier.verify import canonical_trust_record

from parmana_trust_verify import verify_record


def make_record(private_key: Ed25519PrivateKey) -> dict:
    record = {
        "trustRecordId": "tr-1",
        "businessTransactionId": "btx-1",
        "transaction": {"amount": 100, "currency": "INR"},
        "authorization": {"approvedBy": "ana"},
        "overrides": None,
        "executions": [{"n": 1}],
        "createdAt": "2026-06-01T12:00:00.000Z",
    }
    message = canonical_bytes(canonical_trust_record(record))
    record["trustRecordHash"] = hashlib.sha256(message).hexdigest()
    record["signature"] = {
        "algorithm": "ed25519",
        "keyId": "ana-key-1",
        "signature": base64.b64encode(private_key.sign(message)).decode(),
    }
    return record


def make_trust_document(private_key: Ed25519PrivateKey) -> dict:
    public = private_key.public_key()
    der = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem = public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return {
        "keys": [
            {
                "keyId": "ana-key-1",
                "algorithm": "ed25519",
                "publicKeyPem": pem,
                "fingerprint": "sha256:" + hashlib.sha256(der).hexdigest(),
                "validFrom": "2026-01-01T00:00:00.000Z",
                "validUntil": None,
                "compromised": False,
            }
        ]
    }


key = Ed25519PrivateKey.generate()
record = make_record(key)
trust = make_trust_document(key)
print("allowed:", verify_record(record, trust).allowed)

record["transaction"]["amount"] = 999
verdict = verify_record(record, trust)
print("after tampering, allowed:", verdict.allowed, "| first error:", verdict.errors[0])
