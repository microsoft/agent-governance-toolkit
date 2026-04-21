# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Encrypted trust bridge — TrustHandshake + SecureChannel integration.

Extends TrustBridge.verify_peer() to optionally establish an E2E
encrypted SecureChannel after successful authentication. The trust
handshake authenticates the peer (Ed25519 challenge-response + trust
score check), then X3DH + Double Ratchet provide forward-secret
encrypted messaging.

Usage:
    bridge = EncryptedTrustBridge(
        agent_did="did:mesh:alice",
        key_manager=alice_key_manager,
    )
    channel = await bridge.open_secure_channel("did:mesh:bob", bob_bundle)
    ciphertext = channel.send(b"governed action")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from agentmesh.encryption.channel import ChannelEstablishment, SecureChannel
from agentmesh.encryption.x3dh import InMemoryPreKeyStore, PreKeyBundle, PreKeyStore, X3DHKeyManager
from agentmesh.trust.bridge import TrustBridge
from agentmesh.trust.handshake import HandshakeResult

logger = logging.getLogger(__name__)


@dataclass
class EncryptedPeerSession:
    """An active encrypted session with a verified peer."""

    peer_did: str
    channel: SecureChannel
    handshake_result: HandshakeResult
    establishment: ChannelEstablishment | None = None


class EncryptedTrustBridge:
    """Trust bridge that gates encrypted channels on successful handshake.

    Agents must pass the trust handshake (identity verification + trust
    score threshold) before an encrypted channel is established. Peers
    that fail the handshake never reach the key exchange step.
    """

    def __init__(
        self,
        agent_did: str,
        key_manager: X3DHKeyManager,
        trust_bridge: TrustBridge | None = None,
        prekey_store: PreKeyStore | None = None,
        min_trust_score: int = 700,
    ) -> None:
        """Initialize the encrypted trust bridge.

        Args:
            agent_did: This agent's DID.
            key_manager: X3DH key manager with this agent's identity keys.
            trust_bridge: Optional existing TrustBridge instance. If None,
                a new one is created.
            prekey_store: Pre-key storage backend. Defaults to in-memory.
            min_trust_score: Minimum trust score required to open a channel.
        """
        self._agent_did = agent_did
        self._key_manager = key_manager
        self._bridge = trust_bridge or TrustBridge(agent_did=agent_did)
        self._prekey_store = prekey_store or InMemoryPreKeyStore()
        self._min_trust_score = min_trust_score
        self._sessions: dict[str, EncryptedPeerSession] = {}

        # Ensure we have a signed pre-key for receiving channels
        if key_manager.signed_pre_key is None:
            key_manager.generate_signed_pre_key()

    @property
    def agent_did(self) -> str:
        return self._agent_did

    @property
    def active_sessions(self) -> dict[str, EncryptedPeerSession]:
        """Return all active encrypted sessions, keyed by peer DID."""
        return dict(self._sessions)

    def publish_prekey_bundle(self, include_otk: bool = True) -> PreKeyBundle:
        """Generate and publish this agent's pre-key bundle.

        Args:
            include_otk: Whether to include a one-time pre-key.

        Returns:
            The public PreKeyBundle for distribution to peers.
        """
        otk_id = None
        if include_otk:
            otks = self._key_manager.generate_one_time_pre_keys(1)
            otk_id = otks[0].key_id

        bundle = self._key_manager.get_public_bundle(otk_id=otk_id)
        self._prekey_store.store_bundle(self._agent_did, bundle)
        return bundle

    async def open_secure_channel(
        self,
        peer_did: str,
        peer_bundle: PreKeyBundle,
        required_trust_score: int | None = None,
        skip_handshake: bool = False,
    ) -> SecureChannel:
        """Open an E2E encrypted channel to a peer after trust verification.

        The flow is:
        1. Run TrustHandshake (Ed25519 challenge-response + trust check)
        2. If verified, run X3DH key agreement
        3. Initialize Double Ratchet from shared secret
        4. Return SecureChannel ready for send/receive

        Args:
            peer_did: The peer agent's DID.
            peer_bundle: The peer's published pre-key bundle.
            required_trust_score: Override the default trust threshold.
            skip_handshake: If True, skip trust verification (for testing
                or pre-verified peers only).

        Returns:
            A SecureChannel for encrypted communication.

        Raises:
            PermissionError: If the peer fails trust verification.
        """
        threshold = required_trust_score or self._min_trust_score

        # Step 1: Trust verification
        if not skip_handshake:
            result = await self._bridge.verify_peer(
                peer_did=peer_did,
                required_trust_score=threshold,
            )
            if not result.verified:
                raise PermissionError(
                    f"Peer {peer_did} failed trust verification: {result.rejection_reason}"
                )
            handshake_result = result
        else:
            handshake_result = HandshakeResult(
                verified=True,
                peer_did=peer_did,
                trust_score=threshold,
                trust_level="trusted",
            )

        # Step 2: X3DH + Double Ratchet via SecureChannel
        ad = f"{self._agent_did}|{peer_did}".encode()
        channel, establishment = SecureChannel.create_sender(
            self._key_manager, peer_bundle, associated_data=ad
        )

        session = EncryptedPeerSession(
            peer_did=peer_did,
            channel=channel,
            handshake_result=handshake_result,
            establishment=establishment,
        )
        self._sessions[peer_did] = session

        logger.info(
            "Opened encrypted channel to %s (trust=%d, level=%s)",
            peer_did,
            handshake_result.trust_score,
            handshake_result.trust_level,
        )
        return channel

    def accept_secure_channel(
        self,
        peer_did: str,
        establishment: ChannelEstablishment,
        handshake_result: HandshakeResult | None = None,
    ) -> SecureChannel:
        """Accept an incoming encrypted channel from a verified peer.

        Args:
            peer_did: The initiating peer's DID.
            establishment: The ChannelEstablishment from the initiator.
            handshake_result: Optional handshake result if already verified.

        Returns:
            A SecureChannel for encrypted communication.
        """
        ad = f"{peer_did}|{self._agent_did}".encode()
        channel = SecureChannel.create_receiver(
            self._key_manager, establishment, associated_data=ad
        )

        session = EncryptedPeerSession(
            peer_did=peer_did,
            channel=channel,
            handshake_result=handshake_result or HandshakeResult(
                verified=True, peer_did=peer_did,
            ),
        )
        self._sessions[peer_did] = session

        logger.info("Accepted encrypted channel from %s", peer_did)
        return channel

    def get_session(self, peer_did: str) -> EncryptedPeerSession | None:
        """Get an active session with a peer."""
        return self._sessions.get(peer_did)

    def close_session(self, peer_did: str) -> bool:
        """Close an encrypted session and clear key material.

        Returns:
            True if a session existed and was closed.
        """
        session = self._sessions.pop(peer_did, None)
        if session is None:
            return False
        session.channel.close()
        logger.info("Closed encrypted session with %s", peer_did)
        return True

    def close_all_sessions(self) -> int:
        """Close all active sessions. Returns the number closed."""
        count = len(self._sessions)
        for peer_did in list(self._sessions.keys()):
            self.close_session(peer_did)
        return count
