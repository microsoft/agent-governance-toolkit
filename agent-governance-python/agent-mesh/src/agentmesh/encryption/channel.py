# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""SecureChannel — high-level E2E encrypted agent-to-agent messaging.

Combines X3DH key agreement with the Double Ratchet to provide a
simple API for encrypted bidirectional communication between agents.

Usage:
    alice_ch = SecureChannel.create_sender(alice_mgr, bob_bundle, ad)
    bob_ch = SecureChannel.create_receiver(bob_mgr, alice_ik, alice_ek, otk_id, ad)

    ciphertext = alice_ch.send(b"hello")
    plaintext = bob_ch.receive(ciphertext)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from agentmesh.encryption.ratchet import DoubleRatchet, EncryptedMessage
from agentmesh.encryption.x3dh import PreKeyBundle, X3DHKeyManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ChannelEstablishment:
    """Data the initiator sends to the responder to establish the channel."""

    initiator_identity_key: bytes
    ephemeral_public_key: bytes
    used_one_time_key_id: int | None


class SecureChannel:
    """E2E encrypted bidirectional channel between two agents.

    Wraps X3DH (initial key exchange) and Double Ratchet (ongoing
    encryption) into a simple send/receive API.
    """

    def __init__(
        self,
        ratchet: DoubleRatchet,
        associated_data: bytes,
        local_identity_key: bytes,
        remote_identity_key: bytes,
    ) -> None:
        self._ratchet = ratchet
        self._associated_data = associated_data
        self._local_ik = local_identity_key
        self._remote_ik = remote_identity_key
        self._closed = False
        self._message_count = 0

    @classmethod
    def create_sender(
        cls,
        key_manager: X3DHKeyManager,
        peer_bundle: PreKeyBundle,
        associated_data: bytes = b"",
    ) -> tuple[SecureChannel, ChannelEstablishment]:
        """Create a channel as the initiator (sender of the first message).

        Args:
            key_manager: The initiator's X3DH key manager.
            peer_bundle: The responder's published pre-key bundle.
            associated_data: Additional data bound to the channel (e.g., DIDs).

        Returns:
            A tuple of (SecureChannel, ChannelEstablishment). The
            ChannelEstablishment must be sent to the responder out-of-band
            so they can create their side of the channel.
        """
        x3dh_result = key_manager.initiate(peer_bundle)

        ratchet = DoubleRatchet.init_sender(
            shared_secret=x3dh_result.shared_secret,
            remote_dh_public=peer_bundle.signed_pre_key,
        )

        ad = associated_data + x3dh_result.associated_data

        establishment = ChannelEstablishment(
            initiator_identity_key=key_manager.identity_key.public_key,
            ephemeral_public_key=x3dh_result.ephemeral_public_key,
            used_one_time_key_id=x3dh_result.used_one_time_key_id,
        )

        channel = cls(
            ratchet=ratchet,
            associated_data=ad,
            local_identity_key=key_manager.identity_key.public_key,
            remote_identity_key=peer_bundle.identity_key,
        )
        return channel, establishment

    @classmethod
    def create_receiver(
        cls,
        key_manager: X3DHKeyManager,
        establishment: ChannelEstablishment,
        associated_data: bytes = b"",
    ) -> SecureChannel:
        """Create a channel as the responder.

        Args:
            key_manager: The responder's X3DH key manager.
            establishment: The ChannelEstablishment data from the initiator.
            associated_data: Additional data bound to the channel.

        Returns:
            A SecureChannel ready to receive and send messages.
        """
        if key_manager.signed_pre_key is None:
            raise RuntimeError("Responder must have a signed pre-key.")

        x3dh_result = key_manager.respond(
            peer_identity_key=establishment.initiator_identity_key,
            ephemeral_public_key=establishment.ephemeral_public_key,
            used_one_time_key_id=establishment.used_one_time_key_id,
        )

        ratchet = DoubleRatchet.init_receiver(
            shared_secret=x3dh_result.shared_secret,
            dh_key_pair=(
                key_manager.signed_pre_key.key_pair.private_key,
                key_manager.signed_pre_key.key_pair.public_key,
            ),
        )

        ad = associated_data + x3dh_result.associated_data

        return cls(
            ratchet=ratchet,
            associated_data=ad,
            local_identity_key=key_manager.identity_key.public_key,
            remote_identity_key=establishment.initiator_identity_key,
        )

    def send(self, plaintext: bytes) -> EncryptedMessage:
        """Encrypt and send a message.

        Args:
            plaintext: Message content to encrypt.

        Returns:
            An EncryptedMessage ready for transport.

        Raises:
            RuntimeError: If the channel has been closed.
        """
        if self._closed:
            raise RuntimeError("Channel is closed.")
        msg = self._ratchet.encrypt(plaintext, self._associated_data)
        self._message_count += 1
        return msg

    def receive(self, message: EncryptedMessage) -> bytes:
        """Decrypt a received message.

        Args:
            message: The encrypted message from the peer.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            RuntimeError: If the channel has been closed.
        """
        if self._closed:
            raise RuntimeError("Channel is closed.")
        plaintext = self._ratchet.decrypt(message, self._associated_data)
        self._message_count += 1
        return plaintext

    def close(self) -> None:
        """Close the channel and clear key material."""
        self._closed = True
        # Zero out sensitive state
        state = self._ratchet.state
        state.root_key = b"\x00" * len(state.root_key)
        if state.chain_key_send:
            state.chain_key_send = b"\x00" * len(state.chain_key_send)
        if state.chain_key_recv:
            state.chain_key_recv = b"\x00" * len(state.chain_key_recv)
        state.skipped_keys.clear()
        logger.info("SecureChannel closed after %d messages", self._message_count)

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def message_count(self) -> int:
        return self._message_count

    @property
    def local_identity_key(self) -> bytes:
        return self._local_ik

    @property
    def remote_identity_key(self) -> bytes:
        return self._remote_ik
