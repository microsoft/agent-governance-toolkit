# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Ed25519 cryptographic attestation in IATP."""

import pytest
from iatp.attestation import (
    AttestationValidator,
    generate_ed25519_keypair,
)


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 key pair."""
    return generate_ed25519_keypair()


@pytest.fixture
def validator_with_key(keypair):
    """Create an AttestationValidator with a registered public key."""
    _, public_b64 = keypair
    v = AttestationValidator()
    v.add_trusted_key("test-key", public_b64)
    return v


class TestGenerateKeypair:
    def test_returns_two_strings(self):
        priv, pub = generate_ed25519_keypair()
        assert isinstance(priv, str)
        assert isinstance(pub, str)

    def test_keys_are_base64(self):
        import base64
        priv, pub = generate_ed25519_keypair()
        priv_bytes = base64.b64decode(priv)
        pub_bytes = base64.b64decode(pub)
        assert len(priv_bytes) == 32  # Ed25519 private key is 32 bytes
        assert len(pub_bytes) == 32   # Ed25519 public key is 32 bytes

    def test_unique_each_call(self):
        _, pub1 = generate_ed25519_keypair()
        _, pub2 = generate_ed25519_keypair()
        assert pub1 != pub2


class TestRealCryptoSignAndVerify:
    def test_sign_and_verify_roundtrip(self, keypair, validator_with_key):
        """Create an attestation with real key, verify with real crypto."""
        priv_b64, _ = keypair
        v = validator_with_key

        attestation = v.create_attestation(
            agent_id="agent-001",
            codebase_hash="aabbccdd",
            config_hash="11223344",
            signing_key_id="test-key",
            private_key=priv_b64,
        )

        is_valid, error = v.validate_attestation(attestation, verify_signature=True)
        assert is_valid, f"Verification failed: {error}"
        assert error is None

    def test_tampered_signature_rejected(self, keypair, validator_with_key):
        """Tampered signature must be rejected."""
        import base64
        priv_b64, _ = keypair
        v = validator_with_key

        attestation = v.create_attestation(
            agent_id="agent-001",
            codebase_hash="aabbccdd",
            config_hash="11223344",
            signing_key_id="test-key",
            private_key=priv_b64,
        )

        # Tamper with the signature (flip a byte)
        sig_bytes = bytearray(base64.b64decode(attestation.signature))
        sig_bytes[0] ^= 0xFF
        attestation.signature = base64.b64encode(bytes(sig_bytes)).decode()

        is_valid, error = v.validate_attestation(attestation, verify_signature=True)
        assert not is_valid
        assert "invalid signature" in error.lower()

    def test_tampered_agent_id_rejected(self, keypair, validator_with_key):
        """Changing the agent_id after signing must be rejected."""
        priv_b64, _ = keypair
        v = validator_with_key

        attestation = v.create_attestation(
            agent_id="agent-001",
            codebase_hash="aabbccdd",
            config_hash="11223344",
            signing_key_id="test-key",
            private_key=priv_b64,
        )

        # Tamper with agent_id (message changes, signature invalid)
        attestation.agent_id = "evil-agent"

        is_valid, error = v.validate_attestation(attestation, verify_signature=True)
        assert not is_valid
        assert "invalid signature" in error.lower()

    def test_tampered_codebase_hash_rejected(self, keypair, validator_with_key):
        """Changing the codebase_hash after signing must be rejected."""
        priv_b64, _ = keypair
        v = validator_with_key

        attestation = v.create_attestation(
            agent_id="agent-001",
            codebase_hash="aabbccdd",
            config_hash="11223344",
            signing_key_id="test-key",
            private_key=priv_b64,
        )

        attestation.codebase_hash = "deadbeef"

        is_valid, error = v.validate_attestation(attestation, verify_signature=True)
        assert not is_valid

    def test_wrong_key_rejected(self, keypair):
        """Signature made with one key must fail with a different public key."""
        priv_b64, _ = keypair
        _, other_pub = generate_ed25519_keypair()

        v = AttestationValidator()
        v.add_trusted_key("other-key", other_pub)

        # Sign with original key, register different public key
        attestation = v.create_attestation(
            agent_id="agent-001",
            codebase_hash="aabb",
            config_hash="ccdd",
            signing_key_id="other-key",
            private_key=priv_b64,
        )

        is_valid, error = v.validate_attestation(attestation, verify_signature=True)
        assert not is_valid
        assert "invalid signature" in error.lower()

    def test_unsigned_attestation_accepted_without_verify_flag(self, validator_with_key):
        """When verify_signature=False, unsigned attestations pass."""
        v = validator_with_key
        attestation = v.create_attestation(
            agent_id="agent-001",
            codebase_hash="aabb",
            config_hash="ccdd",
            signing_key_id="test-key",
            private_key=None,  # No signing
        )

        is_valid, error = v.validate_attestation(attestation, verify_signature=False)
        assert is_valid

    def test_unsigned_attestation_rejected_with_verify_flag(self, validator_with_key):
        """Unsigned attestation fails when verify_signature=True."""
        v = validator_with_key
        attestation = v.create_attestation(
            agent_id="agent-001",
            codebase_hash="aabb",
            config_hash="ccdd",
            signing_key_id="test-key",
            private_key=None,  # No real signing — base64 of message, not Ed25519
        )

        is_valid, error = v.validate_attestation(attestation, verify_signature=True)
        assert not is_valid

    def test_multiple_agents_different_keys(self):
        """Each agent can have its own key pair."""
        v = AttestationValidator()

        priv1, pub1 = generate_ed25519_keypair()
        priv2, pub2 = generate_ed25519_keypair()
        v.add_trusted_key("key-agent1", pub1)
        v.add_trusted_key("key-agent2", pub2)

        att1 = v.create_attestation("agent-1", "h1", "c1", "key-agent1", priv1)
        att2 = v.create_attestation("agent-2", "h2", "c2", "key-agent2", priv2)

        assert v.validate_attestation(att1, verify_signature=True) == (True, None)
        assert v.validate_attestation(att2, verify_signature=True) == (True, None)

        # Cross-verify should fail (agent-1's attestation with agent-2's key)
        att1.signing_key_id = "key-agent2"
        is_valid, _ = v.validate_attestation(att1, verify_signature=True)
        assert not is_valid

    def test_expired_attestation_rejected_even_with_valid_sig(self, keypair, validator_with_key):
        """Valid signature doesn't help if attestation is expired."""
        priv_b64, _ = keypair
        v = validator_with_key

        attestation = v.create_attestation(
            agent_id="agent-001",
            codebase_hash="aabb",
            config_hash="ccdd",
            signing_key_id="test-key",
            private_key=priv_b64,
            expires_in_hours=-1,  # Already expired
        )

        is_valid, error = v.validate_attestation(attestation, verify_signature=True)
        assert not is_valid
        assert "expired" in error.lower()
