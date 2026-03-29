# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
from pydantic import BaseModel
from datetime import datetime, timezone
from .. import crypto

class MockModel(BaseModel):
    name: str
    value: int
    timestamp: datetime
    signature: str = ""

def test_canonical_payload_stability():
    """Ensure dict and pydantic models produce same canonical output."""
    ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
    data_dict = {"name": "test", "value": 42, "timestamp": ts, "signature": "ignore-me"}
    data_model = MockModel(name="test", value=42, timestamp=ts, signature="ignore-me")
    
    payload1 = crypto.canonical_payload(data_dict)
    payload2 = crypto.canonical_payload(data_model)
    
    assert payload1 == payload2
    # Check that signature field is excluded
    assert b"ignore-me" not in payload1
    # Check that keys are sorted (name before value)
    assert payload1.find(b"name") < payload1.find(b"value")

def test_sign_and_verify_roundtrip():
    """Test full sign/verify cycle."""
    priv, pub_str = crypto.generate_keypair()
    data = {"agent_did": "did:nexus:test", "action": "register"}
    
    sig_hex = crypto.sign_data(priv, data)
    assert len(sig_hex) == 128  # 64 bytes hex encoded
    
    # Should not raise
    crypto.verify_signature(pub_str, sig_hex, data)

def test_verify_fails_on_tamper():
    """Test that tampered data fails verification."""
    priv, pub_str = crypto.generate_keypair()
    data = {"agent_did": "did:nexus:test", "action": "register"}
    sig_hex = crypto.sign_data(priv, data)
    
    tampered_data = {"agent_did": "did:nexus:EVIL", "action": "register"}
    
    with pytest.raises(crypto.SignatureVerificationError):
        crypto.verify_signature(pub_str, sig_hex, tampered_data)

def test_verify_fails_on_wrong_key():
    """Test that verification fails with a different key."""
    priv1, pub_str1 = crypto.generate_keypair()
    priv2, pub_str2 = crypto.generate_keypair()
    
    data = {"agent_did": "did:nexus:test"}
    sig_hex = crypto.sign_data(priv1, data)
    
    with pytest.raises(crypto.SignatureVerificationError):
        crypto.verify_signature(pub_str2, sig_hex, data)

def test_decode_error():
    """Test behavior with malformed hex."""
    _, pub_str = crypto.generate_keypair()
    with pytest.raises(crypto.SignatureDecodeError):
        crypto.verify_signature(pub_str, "not-a-hex-string", {"data": 1})
