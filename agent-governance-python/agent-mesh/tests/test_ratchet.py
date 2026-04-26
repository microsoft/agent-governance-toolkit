# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Double Ratchet algorithm."""

import pytest
from nacl.signing import SigningKey

from agentmesh.encryption.x3dh import X3DHKeyManager
from agentmesh.encryption.ratchet import (
    DoubleRatchet,
    EncryptedMessage,
    MessageHeader,
    RatchetState,
)


def _setup_pair() -> tuple[DoubleRatchet, DoubleRatchet]:
    """Create an Alice (sender) / Bob (receiver) ratchet pair via X3DH."""
    alice_sk = SigningKey.generate()
    bob_sk = SigningKey.generate()

    alice_mgr = X3DHKeyManager.from_ed25519_keys(
        bytes(alice_sk) + bytes(alice_sk.verify_key), bytes(alice_sk.verify_key)
    )
    bob_mgr = X3DHKeyManager.from_ed25519_keys(
        bytes(bob_sk) + bytes(bob_sk.verify_key), bytes(bob_sk.verify_key)
    )

    bob_mgr.generate_signed_pre_key()
    bob_mgr.generate_one_time_pre_keys(1)
    bob_bundle = bob_mgr.get_public_bundle(otk_id=0)

    alice_x3dh = alice_mgr.initiate(bob_bundle)
    bob_x3dh = bob_mgr.respond(
        peer_identity_key=alice_mgr.identity_key.public_key,
        ephemeral_public_key=alice_x3dh.ephemeral_public_key,
        used_one_time_key_id=alice_x3dh.used_one_time_key_id,
    )

    alice_ratchet = DoubleRatchet.init_sender(
        shared_secret=alice_x3dh.shared_secret,
        remote_dh_public=bob_bundle.signed_pre_key,
    )
    bob_ratchet = DoubleRatchet.init_receiver(
        shared_secret=bob_x3dh.shared_secret,
        dh_key_pair=(
            bob_mgr.signed_pre_key.key_pair.private_key,
            bob_mgr.signed_pre_key.key_pair.public_key,
        ),
    )
    return alice_ratchet, bob_ratchet


class TestMessageHeader:
    def test_serialize_roundtrip(self):
        header = MessageHeader(dh_public_key=b"\xaa" * 32, previous_chain_length=5, message_number=42)
        data = header.serialize()
        assert len(data) == 40
        restored = MessageHeader.deserialize(data)
        assert restored.dh_public_key == header.dh_public_key
        assert restored.previous_chain_length == 5
        assert restored.message_number == 42

    def test_deserialize_invalid_length(self):
        with pytest.raises(ValueError, match="Invalid header length"):
            MessageHeader.deserialize(b"\x00" * 20)


class TestEncryptedMessage:
    def test_serialize_roundtrip(self):
        header = MessageHeader(dh_public_key=b"\xbb" * 32, previous_chain_length=0, message_number=0)
        msg = EncryptedMessage(header=header, ciphertext=b"hello encrypted")
        data = msg.serialize()
        restored = EncryptedMessage.deserialize(data)
        assert restored.header.dh_public_key == header.dh_public_key
        assert restored.ciphertext == b"hello encrypted"


class TestDoubleRatchet:
    def test_single_message_alice_to_bob(self):
        alice, bob = _setup_pair()
        enc = alice.encrypt(b"hello bob")
        plaintext = bob.decrypt(enc)
        assert plaintext == b"hello bob"

    def test_multiple_messages_one_direction(self):
        alice, bob = _setup_pair()
        for i in range(5):
            msg = f"message {i}".encode()
            enc = alice.encrypt(msg)
            assert bob.decrypt(enc) == msg

    def test_bidirectional_conversation(self):
        alice, bob = _setup_pair()

        enc1 = alice.encrypt(b"hello bob")
        assert bob.decrypt(enc1) == b"hello bob"

        enc2 = bob.encrypt(b"hello alice")
        assert alice.decrypt(enc2) == b"hello alice"

        enc3 = alice.encrypt(b"how are you")
        assert bob.decrypt(enc3) == b"how are you"

        enc4 = bob.encrypt(b"fine thanks")
        assert alice.decrypt(enc4) == b"fine thanks"

    def test_forward_secrecy_different_keys_per_message(self):
        """Each message in the same direction uses a different chain key."""
        alice, bob = _setup_pair()
        enc1 = alice.encrypt(b"msg1")
        enc2 = alice.encrypt(b"msg2")
        # Different ciphertexts (different keys)
        assert enc1.ciphertext != enc2.ciphertext
        # Same DH key within the same sending chain
        assert enc1.header.dh_public_key == enc2.header.dh_public_key
        assert bob.decrypt(enc1) == b"msg1"
        assert bob.decrypt(enc2) == b"msg2"

    def test_dh_ratchet_advances_on_turn_change(self):
        """DH public key changes when the conversation direction changes."""
        alice, bob = _setup_pair()

        enc_a1 = alice.encrypt(b"a1")
        bob.decrypt(enc_a1)

        enc_b1 = bob.encrypt(b"b1")
        alice.decrypt(enc_b1)

        enc_a2 = alice.encrypt(b"a2")
        # Alice's DH key should have changed after receiving from Bob
        assert enc_a2.header.dh_public_key != enc_a1.header.dh_public_key
        assert bob.decrypt(enc_a2) == b"a2"

    def test_out_of_order_delivery(self):
        """Messages delivered out of order are decrypted correctly."""
        alice, bob = _setup_pair()
        enc0 = alice.encrypt(b"msg0")
        enc1 = alice.encrypt(b"msg1")
        enc2 = alice.encrypt(b"msg2")

        # Deliver in reverse order
        assert bob.decrypt(enc2) == b"msg2"
        assert bob.decrypt(enc0) == b"msg0"
        assert bob.decrypt(enc1) == b"msg1"

    def test_max_skip_exceeded_raises(self):
        """Exceeding max_skip raises RuntimeError."""
        alice, bob = _setup_pair()
        bob._max_skip = 2

        alice.encrypt(b"skip1")
        alice.encrypt(b"skip2")
        alice.encrypt(b"skip3")
        enc4 = alice.encrypt(b"msg4")

        with pytest.raises(RuntimeError, match="Too many skipped"):
            bob.decrypt(enc4)

    def test_tampered_ciphertext_rejected(self):
        """Modified ciphertext fails authentication."""
        alice, bob = _setup_pair()
        enc = alice.encrypt(b"secret")

        tampered = EncryptedMessage(
            header=enc.header,
            ciphertext=enc.ciphertext[:-1] + bytes([enc.ciphertext[-1] ^ 0xFF]),
        )
        with pytest.raises(Exception):
            bob.decrypt(tampered)

    def test_associated_data(self):
        """Messages with associated data encrypt/decrypt correctly."""
        alice, bob = _setup_pair()
        ad = b"did:mesh:alice|did:mesh:bob"
        enc = alice.encrypt(b"governed message", associated_data=ad)
        plaintext = bob.decrypt(enc, associated_data=ad)
        assert plaintext == b"governed message"

    def test_wrong_associated_data_rejected(self):
        """Wrong associated data fails decryption."""
        alice, bob = _setup_pair()
        enc = alice.encrypt(b"secret", associated_data=b"correct_ad")
        with pytest.raises(Exception):
            bob.decrypt(enc, associated_data=b"wrong_ad")

    def test_empty_message(self):
        """Empty plaintext encrypts and decrypts."""
        alice, bob = _setup_pair()
        enc = alice.encrypt(b"")
        assert bob.decrypt(enc) == b""

    def test_large_message(self):
        """Large messages work correctly."""
        alice, bob = _setup_pair()
        big = b"A" * 100_000
        enc = alice.encrypt(big)
        assert bob.decrypt(enc) == big


class TestRatchetStateSerialization:
    def test_state_roundtrip(self):
        alice, _ = _setup_pair()
        d = alice.state.to_dict()
        restored = RatchetState.from_dict(d)
        assert restored.root_key == alice.state.root_key
        assert restored.dh_self_public == alice.state.dh_self_public
        assert restored.send_message_number == alice.state.send_message_number

    def test_state_with_skipped_keys_roundtrip(self):
        alice, bob = _setup_pair()
        # Create skipped keys by out-of-order delivery
        enc0 = alice.encrypt(b"msg0")
        enc1 = alice.encrypt(b"msg1")
        enc2 = alice.encrypt(b"msg2")
        bob.decrypt(enc2)  # Skip 0 and 1

        d = bob.state.to_dict()
        restored = RatchetState.from_dict(d)
        assert len(restored.skipped_keys) == 2

    def test_resumed_session_decrypts(self):
        """A ratchet restored from serialized state can continue decrypting."""
        alice, bob = _setup_pair()
        enc1 = alice.encrypt(b"before save")
        bob.decrypt(enc1)

        # Save and restore Bob's state
        saved = bob.state.to_dict()
        bob2 = DoubleRatchet(RatchetState.from_dict(saved))

        enc2 = alice.encrypt(b"after restore")
        assert bob2.decrypt(enc2) == b"after restore"
