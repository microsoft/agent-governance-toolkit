# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for KeyRotationManager — automatic key rotation for long-lived agents."""

import time
from unittest.mock import patch

import pytest

from agentmesh.exceptions import IdentityError
from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.identity.rotation import KeyRotationManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_identity() -> AgentIdentity:
    return AgentIdentity.create(
        name="test-agent",
        sponsor="sponsor@example.com",
        capabilities=["read", "write"],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestKeyRotationManager:
    """Tests for KeyRotationManager."""

    def test_rotation_generates_new_keys(self) -> None:
        identity = _create_identity()
        mgr = KeyRotationManager(identity)
        old_pub = identity.public_key

        mgr.rotate()

        assert identity.public_key != old_pub

    def test_did_preserved_after_rotation(self) -> None:
        identity = _create_identity()
        did_before = str(identity.did)
        mgr = KeyRotationManager(identity)

        mgr.rotate()

        assert str(identity.did) == did_before

    def test_rotation_proof_is_valid(self) -> None:
        identity = _create_identity()
        mgr = KeyRotationManager(identity)
        old_pub = identity.public_key

        mgr.rotate()
        new_pub = identity.public_key
        proof = mgr.get_rotation_proof()

        assert KeyRotationManager.verify_rotation(old_pub, new_pub, proof) is True

    def test_old_key_verifies_old_signatures(self) -> None:
        identity = _create_identity()
        msg = b"important-message"
        old_sig = identity.sign(msg)

        mgr = KeyRotationManager(identity)
        mgr.rotate()

        # Old signature can still be verified using stored old public key
        history = mgr.get_key_history()
        old_pub = history[0]["public_key"]

        from cryptography.hazmat.primitives.asymmetric import ed25519
        import base64

        pub_bytes = base64.b64decode(old_pub)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(old_sig)
        # Should not raise
        pub_key.verify(sig_bytes, msg)

    def test_new_key_signs_new_messages(self) -> None:
        identity = _create_identity()
        mgr = KeyRotationManager(identity)
        mgr.rotate()

        msg = b"new-message"
        sig = identity.sign(msg)
        assert identity.verify_signature(msg, sig) is True

    def test_needs_rotation_respects_ttl(self) -> None:
        identity = _create_identity()
        mgr = KeyRotationManager(identity, rotation_ttl_seconds=1)

        assert mgr.needs_rotation() is False
        time.sleep(1.1)
        assert mgr.needs_rotation() is True

    def test_key_history_tracks_rotations(self) -> None:
        identity = _create_identity()
        mgr = KeyRotationManager(identity)

        keys_seen = [identity.public_key]
        for _ in range(3):
            mgr.rotate()
            keys_seen.append(identity.public_key)

        history = mgr.get_key_history()
        assert len(history) == 3
        for i, entry in enumerate(history):
            assert entry["public_key"] == keys_seen[i]
            assert "rotated_at" in entry

    def test_max_history_limit(self) -> None:
        identity = _create_identity()
        mgr = KeyRotationManager(identity, max_history=2)

        for _ in range(5):
            mgr.rotate()

        history = mgr.get_key_history()
        assert len(history) == 2

    def test_verify_rotation_invalid_proof_fails(self) -> None:
        identity = _create_identity()
        mgr = KeyRotationManager(identity)
        old_pub = identity.public_key

        mgr.rotate()
        new_pub = identity.public_key
        proof = mgr.get_rotation_proof()

        # Tamper with the proof signature
        bad_proof = {**proof, "signature": "AAAA" + proof["signature"][4:]}
        assert KeyRotationManager.verify_rotation(old_pub, new_pub, bad_proof) is False

    def test_verify_rotation_wrong_keys_fails(self) -> None:
        identity = _create_identity()
        mgr = KeyRotationManager(identity)
        mgr.rotate()
        proof = mgr.get_rotation_proof()

        other = _create_identity()
        assert KeyRotationManager.verify_rotation(other.public_key, identity.public_key, proof) is False

    def test_get_rotation_proof_before_rotation_raises(self) -> None:
        identity = _create_identity()
        mgr = KeyRotationManager(identity)

        with pytest.raises(IdentityError, match="No rotation has occurred"):
            mgr.get_rotation_proof()

    def test_init_without_private_key_raises(self) -> None:
        identity = _create_identity()
        identity._private_key = None

        with pytest.raises(IdentityError, match="private key"):
            KeyRotationManager(identity)
