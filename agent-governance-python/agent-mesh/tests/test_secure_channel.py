# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for SecureChannel E2E encrypted messaging."""

import pytest
from nacl.signing import SigningKey

from agentmesh.encryption.channel import ChannelEstablishment, SecureChannel
from agentmesh.encryption.x3dh import X3DHKeyManager


def _make_manager() -> X3DHKeyManager:
    sk = SigningKey.generate()
    return X3DHKeyManager.from_ed25519_keys(
        bytes(sk) + bytes(sk.verify_key), bytes(sk.verify_key)
    )


def _setup_channel(
    ad: bytes = b"",
) -> tuple[SecureChannel, SecureChannel]:
    """Create a connected Alice ↔ Bob secure channel pair."""
    alice_mgr = _make_manager()
    bob_mgr = _make_manager()

    bob_mgr.generate_signed_pre_key()
    bob_mgr.generate_one_time_pre_keys(1)
    bob_bundle = bob_mgr.get_public_bundle(otk_id=0)

    alice_ch, establishment = SecureChannel.create_sender(alice_mgr, bob_bundle, ad)
    bob_ch = SecureChannel.create_receiver(bob_mgr, establishment, ad)

    return alice_ch, bob_ch


class TestSecureChannel:
    def test_single_message(self):
        alice, bob = _setup_channel()
        enc = alice.send(b"hello bob")
        assert bob.receive(enc) == b"hello bob"

    def test_bidirectional(self):
        alice, bob = _setup_channel()

        enc1 = alice.send(b"hello bob")
        assert bob.receive(enc1) == b"hello bob"

        enc2 = bob.send(b"hello alice")
        assert alice.receive(enc2) == b"hello alice"

        enc3 = alice.send(b"how are you?")
        assert bob.receive(enc3) == b"how are you?"

    def test_multiple_messages_same_direction(self):
        alice, bob = _setup_channel()
        for i in range(10):
            msg = f"msg-{i}".encode()
            enc = alice.send(msg)
            assert bob.receive(enc) == msg

    def test_associated_data_bound(self):
        ad = b"did:mesh:alice|did:mesh:bob"
        alice, bob = _setup_channel(ad=ad)
        enc = alice.send(b"governed message")
        assert bob.receive(enc) == b"governed message"

    def test_message_count(self):
        alice, bob = _setup_channel()
        assert alice.message_count == 0
        assert bob.message_count == 0

        enc = alice.send(b"msg1")
        assert alice.message_count == 1
        bob.receive(enc)
        assert bob.message_count == 1

    def test_close_prevents_send(self):
        alice, bob = _setup_channel()
        alice.close()
        assert alice.is_closed is True
        with pytest.raises(RuntimeError, match="closed"):
            alice.send(b"nope")

    def test_close_prevents_receive(self):
        alice, bob = _setup_channel()
        enc = alice.send(b"last message")
        bob.close()
        with pytest.raises(RuntimeError, match="closed"):
            bob.receive(enc)

    def test_close_clears_key_material(self):
        alice, bob = _setup_channel()
        alice.send(b"test")
        alice.close()
        state = alice._ratchet.state
        assert state.root_key == b"\x00" * 32
        assert len(state.skipped_keys) == 0

    def test_identity_keys_accessible(self):
        alice_mgr = _make_manager()
        bob_mgr = _make_manager()
        bob_mgr.generate_signed_pre_key()
        bob_bundle = bob_mgr.get_public_bundle()

        alice_ch, est = SecureChannel.create_sender(alice_mgr, bob_bundle)
        bob_ch = SecureChannel.create_receiver(bob_mgr, est)

        assert alice_ch.local_identity_key == alice_mgr.identity_key.public_key
        assert alice_ch.remote_identity_key == bob_mgr.identity_key.public_key
        assert bob_ch.local_identity_key == bob_mgr.identity_key.public_key
        assert bob_ch.remote_identity_key == alice_mgr.identity_key.public_key

    def test_out_of_order_messages(self):
        alice, bob = _setup_channel()
        enc0 = alice.send(b"msg0")
        enc1 = alice.send(b"msg1")
        enc2 = alice.send(b"msg2")

        assert bob.receive(enc2) == b"msg2"
        assert bob.receive(enc0) == b"msg0"
        assert bob.receive(enc1) == b"msg1"

    def test_long_conversation(self):
        """20-message bidirectional conversation."""
        alice, bob = _setup_channel()
        for i in range(20):
            if i % 2 == 0:
                enc = alice.send(f"alice-{i}".encode())
                assert bob.receive(enc) == f"alice-{i}".encode()
            else:
                enc = bob.send(f"bob-{i}".encode())
                assert alice.receive(enc) == f"bob-{i}".encode()
        assert alice.message_count == 20
        assert bob.message_count == 20

    def test_receiver_needs_signed_pre_key(self):
        bob_mgr = _make_manager()
        est = ChannelEstablishment(
            initiator_identity_key=b"\x00" * 32,
            ephemeral_public_key=b"\x00" * 32,
            used_one_time_key_id=None,
        )
        with pytest.raises(RuntimeError, match="signed pre-key"):
            SecureChannel.create_receiver(bob_mgr, est)

    def test_without_one_time_pre_key(self):
        """Channel works without OTK (3-DH fallback)."""
        alice_mgr = _make_manager()
        bob_mgr = _make_manager()
        bob_mgr.generate_signed_pre_key()
        bob_bundle = bob_mgr.get_public_bundle()  # No OTK

        alice_ch, est = SecureChannel.create_sender(alice_mgr, bob_bundle)
        bob_ch = SecureChannel.create_receiver(bob_mgr, est)

        enc = alice_ch.send(b"no otk")
        assert bob_ch.receive(enc) == b"no otk"
