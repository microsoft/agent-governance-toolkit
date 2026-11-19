import base64
import copy
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from parmana_verifier.canonical import canonical_bytes
from parmana_verifier.verify import canonical_trust_record

from parmana_trust_verify import verify_record

KEY_ID = "ana-key-1"


def trust_document(private_key, key_id=KEY_ID):
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
                "keyId": key_id,
                "algorithm": "ed25519",
                "publicKeyPem": pem,
                "fingerprint": "sha256:" + hashlib.sha256(der).hexdigest(),
                "validFrom": "2026-01-01T00:00:00.000Z",
                "validUntil": None,
                "compromised": False,
            }
        ]
    }


def signed_record(private_key, key_id=KEY_ID):
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
        "keyId": key_id,
        "signature": base64.b64encode(private_key.sign(message)).decode(),
    }
    return record


def test_valid_record_under_a_pinned_key_is_allowed():
    key = Ed25519PrivateKey.generate()
    verdict = verify_record(signed_record(key), trust_document(key))
    assert verdict.allowed is True
    assert verdict.errors == ()


def test_tampered_transaction_is_denied():
    key = Ed25519PrivateKey.generate()
    record = signed_record(key)
    record["transaction"]["amount"] = 999
    verdict = verify_record(record, trust_document(key))
    assert verdict.allowed is False
    assert verdict.errors


def test_record_signed_by_an_unpinned_key_is_denied():
    signer = Ed25519PrivateKey.generate()
    pinned = Ed25519PrivateKey.generate()
    verdict = verify_record(signed_record(signer), trust_document(pinned))
    assert verdict.allowed is False


def test_record_without_a_signature_is_denied():
    key = Ed25519PrivateKey.generate()
    record = signed_record(key)
    del record["signature"]
    assert verify_record(record, trust_document(key)).allowed is False


def test_malformed_trust_document_is_denied_with_a_reason():
    key = Ed25519PrivateKey.generate()
    verdict = verify_record(signed_record(key), {"keys": "not-a-list"})
    assert verdict.allowed is False
    assert verdict.errors[0].startswith("trust set rejected")


def test_non_object_record_is_denied_without_raising():
    key = Ed25519PrivateKey.generate()
    assert verify_record(["not", "a", "record"], trust_document(key)).allowed is False


def test_original_record_is_not_mutated():
    key = Ed25519PrivateKey.generate()
    record = signed_record(key)
    snapshot = copy.deepcopy(record)
    verify_record(record, trust_document(key))
    assert record == snapshot
