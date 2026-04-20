# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for X3DH key agreement."""

import pytest
from nacl.signing import SigningKey

from agentmesh.encryption.x3dh import (
    InMemoryPreKeyStore,
    PreKeyBundle,
    X25519KeyPair,
    X3DHKeyManager,
    X3DHResult,
)


def _make_manager() -> X3DHKeyManager:
    """Create an X3DH key manager with a fresh Ed25519 identity."""
    sk = SigningKey.generate()
    return X3DHKeyManager.from_ed25519_keys(
        private_key=bytes(sk) + bytes(sk.verify_key),
        public_key=bytes(sk.verify_key),
    )


class TestX25519KeyPair:
    def test_generate_produces_32_byte_keys(self):
        kp = X25519KeyPair.generate()
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32

    def test_generate_unique(self):
        kp1 = X25519KeyPair.generate()
        kp2 = X25519KeyPair.generate()
        assert kp1.private_key != kp2.private_key

    def test_from_ed25519_roundtrip(self):
        sk = SigningKey.generate()
        private = bytes(sk) + bytes(sk.verify_key)
        public = bytes(sk.verify_key)
        kp = X25519KeyPair.from_ed25519(private, public)
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32

    def test_from_ed25519_invalid_public_key_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            X25519KeyPair.from_ed25519(b"\x00" * 64, b"\x00" * 16)

    def test_from_ed25519_invalid_private_key_length(self):
        with pytest.raises(ValueError, match="64 bytes"):
            X25519KeyPair.from_ed25519(b"\x00" * 32, b"\x00" * 32)


class TestX3DHKeyManager:
    def test_generate_signed_pre_key(self):
        mgr = _make_manager()
        spk = mgr.generate_signed_pre_key()
        assert len(spk.key_pair.public_key) == 32
        assert len(spk.signature) == 64
        assert spk.key_id == 0

    def test_generate_one_time_pre_keys(self):
        mgr = _make_manager()
        otks = mgr.generate_one_time_pre_keys(5)
        assert len(otks) == 5
        assert all(len(otk.key_pair.public_key) == 32 for otk in otks)
        assert len(set(otk.key_id for otk in otks)) == 5

    def test_get_public_bundle_requires_spk(self):
        mgr = _make_manager()
        with pytest.raises(RuntimeError, match="No signed pre-key"):
            mgr.get_public_bundle()

    def test_get_public_bundle_without_otk(self):
        mgr = _make_manager()
        mgr.generate_signed_pre_key()
        bundle = mgr.get_public_bundle()
        assert len(bundle.identity_key) == 32
        assert len(bundle.signed_pre_key) == 32
        assert bundle.one_time_pre_key is None

    def test_get_public_bundle_with_otk(self):
        mgr = _make_manager()
        mgr.generate_signed_pre_key()
        otks = mgr.generate_one_time_pre_keys(3)
        bundle = mgr.get_public_bundle(otk_id=otks[1].key_id)
        assert bundle.one_time_pre_key is not None
        assert bundle.one_time_pre_key_id == otks[1].key_id


class TestX3DHExchange:
    def test_full_exchange_with_otk(self):
        """Full 4-DH exchange with a one-time pre-key."""
        alice = _make_manager()
        bob = _make_manager()

        bob.generate_signed_pre_key()
        bob_otks = bob.generate_one_time_pre_keys(5)
        bob_bundle = bob.get_public_bundle(otk_id=bob_otks[0].key_id)

        alice_result = alice.initiate(bob_bundle)
        bob_result = bob.respond(
            peer_identity_key=alice.identity_key.public_key,
            ephemeral_public_key=alice_result.ephemeral_public_key,
            used_one_time_key_id=alice_result.used_one_time_key_id,
        )

        assert alice_result.shared_secret == bob_result.shared_secret
        assert len(alice_result.shared_secret) == 32
        assert alice_result.used_one_time_key_id == bob_otks[0].key_id

    def test_exchange_without_otk(self):
        """3-DH exchange when no one-time pre-key is available."""
        alice = _make_manager()
        bob = _make_manager()

        bob.generate_signed_pre_key()
        bob_bundle = bob.get_public_bundle()  # No OTK

        alice_result = alice.initiate(bob_bundle)
        bob_result = bob.respond(
            peer_identity_key=alice.identity_key.public_key,
            ephemeral_public_key=alice_result.ephemeral_public_key,
            used_one_time_key_id=None,
        )

        assert alice_result.shared_secret == bob_result.shared_secret
        assert alice_result.used_one_time_key_id is None

    def test_otk_consumed_after_use(self):
        """One-time pre-key is removed after being used."""
        bob = _make_manager()
        bob.generate_signed_pre_key()
        otks = bob.generate_one_time_pre_keys(1)
        otk_id = otks[0].key_id

        alice = _make_manager()
        bob_bundle = bob.get_public_bundle(otk_id=otk_id)
        alice_result = alice.initiate(bob_bundle)

        bob.respond(
            peer_identity_key=alice.identity_key.public_key,
            ephemeral_public_key=alice_result.ephemeral_public_key,
            used_one_time_key_id=otk_id,
        )

        # OTK should be consumed
        assert otk_id not in bob.one_time_pre_keys

    def test_reused_otk_raises(self):
        """Using an already-consumed OTK raises ValueError."""
        bob = _make_manager()
        bob.generate_signed_pre_key()
        otks = bob.generate_one_time_pre_keys(1)
        otk_id = otks[0].key_id

        alice = _make_manager()
        bob_bundle = bob.get_public_bundle(otk_id=otk_id)
        alice_result = alice.initiate(bob_bundle)

        bob.respond(
            peer_identity_key=alice.identity_key.public_key,
            ephemeral_public_key=alice_result.ephemeral_public_key,
            used_one_time_key_id=otk_id,
        )

        # Second use should fail
        with pytest.raises(ValueError, match="not found or already consumed"):
            bob.respond(
                peer_identity_key=alice.identity_key.public_key,
                ephemeral_public_key=alice_result.ephemeral_public_key,
                used_one_time_key_id=otk_id,
            )

    def test_different_initiators_get_different_secrets(self):
        """Two different initiators contacting the same responder get different secrets."""
        bob = _make_manager()
        bob.generate_signed_pre_key()
        bob.generate_one_time_pre_keys(2)

        alice1 = _make_manager()
        alice2 = _make_manager()

        bundle1 = bob.get_public_bundle(otk_id=0)
        bundle2 = bob.get_public_bundle(otk_id=1)

        result1 = alice1.initiate(bundle1)
        result2 = alice2.initiate(bundle2)

        assert result1.shared_secret != result2.shared_secret

    def test_associated_data_correct(self):
        """Associated data is initiator IK || responder IK."""
        alice = _make_manager()
        bob = _make_manager()
        bob.generate_signed_pre_key()
        bob_bundle = bob.get_public_bundle()

        alice_result = alice.initiate(bob_bundle)
        bob_result = bob.respond(
            peer_identity_key=alice.identity_key.public_key,
            ephemeral_public_key=alice_result.ephemeral_public_key,
        )

        assert alice_result.associated_data == alice.identity_key.public_key + bob.identity_key.public_key
        assert bob_result.associated_data == alice.identity_key.public_key + bob.identity_key.public_key

    def test_invalid_spk_signature_length_rejected(self):
        """A bundle with an invalid SPK signature length is rejected."""
        alice = _make_manager()
        bad_bundle = PreKeyBundle(
            identity_key=b"\x00" * 32,
            signed_pre_key=b"\x00" * 32,
            signed_pre_key_signature=b"\x00" * 32,  # Should be 64
            signed_pre_key_id=0,
        )
        with pytest.raises(ValueError, match="signature length"):
            alice.initiate(bad_bundle)


class TestInMemoryPreKeyStore:
    def test_store_and_retrieve(self):
        store = InMemoryPreKeyStore()
        bundle = PreKeyBundle(
            identity_key=b"\x01" * 32,
            signed_pre_key=b"\x02" * 32,
            signed_pre_key_signature=b"\x03" * 64,
            signed_pre_key_id=0,
        )
        store.store_bundle("did:mesh:agent-1", bundle)
        result = store.get_bundle("did:mesh:agent-1")
        assert result is not None
        assert result.identity_key == bundle.identity_key

    def test_get_missing_returns_none(self):
        store = InMemoryPreKeyStore()
        assert store.get_bundle("did:mesh:unknown") is None

    def test_consume_otk(self):
        store = InMemoryPreKeyStore()
        bundle = PreKeyBundle(
            identity_key=b"\x01" * 32,
            signed_pre_key=b"\x02" * 32,
            signed_pre_key_signature=b"\x03" * 64,
            signed_pre_key_id=0,
            one_time_pre_key=b"\x04" * 32,
            one_time_pre_key_id=7,
        )
        store.store_bundle("did:mesh:agent-1", bundle)
        assert store.consume_one_time_key("did:mesh:agent-1", 7) is True
        # Second consumption should fail
        assert store.consume_one_time_key("did:mesh:agent-1", 7) is False
        # Bundle should have OTK removed
        updated = store.get_bundle("did:mesh:agent-1")
        assert updated is not None
        assert updated.one_time_pre_key is None
