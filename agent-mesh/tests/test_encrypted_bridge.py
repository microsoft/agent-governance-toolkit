# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for EncryptedTrustBridge — handshake + encrypted channel integration."""

import pytest
from nacl.signing import SigningKey

from agentmesh.encryption.bridge import EncryptedPeerSession, EncryptedTrustBridge
from agentmesh.encryption.channel import SecureChannel
from agentmesh.encryption.x3dh import X3DHKeyManager


def _make_manager() -> X3DHKeyManager:
    sk = SigningKey.generate()
    return X3DHKeyManager.from_ed25519_keys(
        bytes(sk) + bytes(sk.verify_key), bytes(sk.verify_key)
    )


def _make_bridge(did: str) -> tuple[EncryptedTrustBridge, X3DHKeyManager]:
    mgr = _make_manager()
    bridge = EncryptedTrustBridge(agent_did=did, key_manager=mgr, min_trust_score=500)
    return bridge, mgr


class TestEncryptedTrustBridge:
    @pytest.mark.asyncio
    async def test_open_and_accept_channel(self):
        """Full flow: Alice opens channel, Bob accepts, they exchange messages."""
        alice_bridge, alice_mgr = _make_bridge("did:mesh:alice")
        bob_bridge, bob_mgr = _make_bridge("did:mesh:bob")

        bob_bundle = bob_bridge.publish_prekey_bundle()

        alice_ch = await alice_bridge.open_secure_channel(
            "did:mesh:bob", bob_bundle, skip_handshake=True
        )
        alice_session = alice_bridge.get_session("did:mesh:bob")
        assert alice_session is not None

        bob_ch = bob_bridge.accept_secure_channel(
            "did:mesh:alice", alice_session.establishment
        )

        enc = alice_ch.send(b"hello bob")
        assert bob_ch.receive(enc) == b"hello bob"

        enc2 = bob_ch.send(b"hello alice")
        assert alice_ch.receive(enc2) == b"hello alice"

    @pytest.mark.asyncio
    async def test_bidirectional_conversation(self):
        """Multi-turn conversation through encrypted bridge."""
        alice_bridge, _ = _make_bridge("did:mesh:alice")
        bob_bridge, _ = _make_bridge("did:mesh:bob")

        bob_bundle = bob_bridge.publish_prekey_bundle()
        alice_ch = await alice_bridge.open_secure_channel(
            "did:mesh:bob", bob_bundle, skip_handshake=True
        )
        bob_ch = bob_bridge.accept_secure_channel(
            "did:mesh:alice", alice_bridge.get_session("did:mesh:bob").establishment
        )

        for i in range(5):
            enc = alice_ch.send(f"alice-{i}".encode())
            assert bob_ch.receive(enc) == f"alice-{i}".encode()

            enc = bob_ch.send(f"bob-{i}".encode())
            assert alice_ch.receive(enc) == f"bob-{i}".encode()

    @pytest.mark.asyncio
    async def test_close_session(self):
        alice_bridge, _ = _make_bridge("did:mesh:alice")
        bob_bridge, _ = _make_bridge("did:mesh:bob")

        bob_bundle = bob_bridge.publish_prekey_bundle()
        alice_ch = await alice_bridge.open_secure_channel(
            "did:mesh:bob", bob_bundle, skip_handshake=True
        )

        assert alice_bridge.close_session("did:mesh:bob") is True
        assert alice_bridge.get_session("did:mesh:bob") is None
        assert alice_ch.is_closed is True

    @pytest.mark.asyncio
    async def test_close_nonexistent_session(self):
        bridge, _ = _make_bridge("did:mesh:alice")
        assert bridge.close_session("did:mesh:unknown") is False

    @pytest.mark.asyncio
    async def test_close_all_sessions(self):
        alice_bridge, _ = _make_bridge("did:mesh:alice")
        bob_bridge, _ = _make_bridge("did:mesh:bob")
        carol_bridge, _ = _make_bridge("did:mesh:carol")

        bob_bundle = bob_bridge.publish_prekey_bundle()
        carol_bundle = carol_bridge.publish_prekey_bundle()

        await alice_bridge.open_secure_channel(
            "did:mesh:bob", bob_bundle, skip_handshake=True
        )
        await alice_bridge.open_secure_channel(
            "did:mesh:carol", carol_bundle, skip_handshake=True
        )

        assert len(alice_bridge.active_sessions) == 2
        closed = alice_bridge.close_all_sessions()
        assert closed == 2
        assert len(alice_bridge.active_sessions) == 0

    @pytest.mark.asyncio
    async def test_publish_prekey_bundle(self):
        bridge, mgr = _make_bridge("did:mesh:alice")
        bundle = bridge.publish_prekey_bundle(include_otk=True)
        assert len(bundle.identity_key) == 32
        assert len(bundle.signed_pre_key) == 32
        assert bundle.one_time_pre_key is not None

    @pytest.mark.asyncio
    async def test_publish_prekey_bundle_no_otk(self):
        bridge, _ = _make_bridge("did:mesh:alice")
        bundle = bridge.publish_prekey_bundle(include_otk=False)
        assert bundle.one_time_pre_key is None

    @pytest.mark.asyncio
    async def test_active_sessions_property(self):
        bridge, _ = _make_bridge("did:mesh:alice")
        assert len(bridge.active_sessions) == 0

        bob_bridge, _ = _make_bridge("did:mesh:bob")
        bob_bundle = bob_bridge.publish_prekey_bundle()
        await bridge.open_secure_channel("did:mesh:bob", bob_bundle, skip_handshake=True)

        sessions = bridge.active_sessions
        assert "did:mesh:bob" in sessions
        assert isinstance(sessions["did:mesh:bob"], EncryptedPeerSession)

    @pytest.mark.asyncio
    async def test_agent_did_property(self):
        bridge, _ = _make_bridge("did:mesh:test-agent")
        assert bridge.agent_did == "did:mesh:test-agent"

    @pytest.mark.asyncio
    async def test_channel_with_associated_data(self):
        """Channels bind agent DIDs as associated data."""
        alice_bridge, _ = _make_bridge("did:mesh:alice")
        bob_bridge, _ = _make_bridge("did:mesh:bob")

        bob_bundle = bob_bridge.publish_prekey_bundle()
        alice_ch = await alice_bridge.open_secure_channel(
            "did:mesh:bob", bob_bundle, skip_handshake=True
        )
        bob_ch = bob_bridge.accept_secure_channel(
            "did:mesh:alice", alice_bridge.get_session("did:mesh:bob").establishment
        )

        # Messages work because AD matches
        enc = alice_ch.send(b"test")
        assert bob_ch.receive(enc) == b"test"
