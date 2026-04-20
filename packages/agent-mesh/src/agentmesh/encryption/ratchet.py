# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Double Ratchet algorithm for per-message forward secrecy.

Implements the Signal Double Ratchet specification for encrypting
agent-to-agent messages with forward secrecy and post-compromise
security. Initialized from an X3DH shared secret.

Reference: https://signal.org/docs/specifications/doubleratchet/
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base

logger = logging.getLogger(__name__)

MAX_SKIP = 100
KDF_INFO_RATCHET = b"AgentMesh_Ratchet_v1"
KDF_INFO_MESSAGE = b"AgentMesh_MsgKeys_v1"
NONCE_LEN = 12
KEY_LEN = 32


@dataclass(frozen=True)
class MessageHeader:
    """Header sent with each encrypted message."""

    dh_public_key: bytes
    previous_chain_length: int
    message_number: int

    def serialize(self) -> bytes:
        """Serialize to bytes for authenticated encryption."""
        return (
            self.dh_public_key
            + struct.pack(">II", self.previous_chain_length, self.message_number)
        )

    @classmethod
    def deserialize(cls, data: bytes) -> MessageHeader:
        """Deserialize from bytes."""
        if len(data) != 40:
            raise ValueError(f"Invalid header length: {len(data)}, expected 40")
        dh_pub = data[:32]
        prev_chain, msg_num = struct.unpack(">II", data[32:40])
        return cls(
            dh_public_key=dh_pub,
            previous_chain_length=prev_chain,
            message_number=msg_num,
        )


@dataclass(frozen=True)
class EncryptedMessage:
    """An encrypted Double Ratchet message."""

    header: MessageHeader
    ciphertext: bytes

    def serialize(self) -> bytes:
        """Serialize the full message (header + ciphertext)."""
        header_bytes = self.header.serialize()
        return (
            struct.pack(">I", len(header_bytes))
            + header_bytes
            + self.ciphertext
        )

    @classmethod
    def deserialize(cls, data: bytes) -> EncryptedMessage:
        """Deserialize from bytes."""
        if len(data) < 4:
            raise ValueError("Message too short")
        header_len = struct.unpack(">I", data[:4])[0]
        if len(data) < 4 + header_len:
            raise ValueError("Message truncated")
        header = MessageHeader.deserialize(data[4 : 4 + header_len])
        ciphertext = data[4 + header_len :]
        return cls(header=header, ciphertext=ciphertext)


@dataclass
class RatchetState:
    """Serializable state of a Double Ratchet session."""

    dh_self_private: bytes
    dh_self_public: bytes
    dh_remote_public: bytes | None
    root_key: bytes
    chain_key_send: bytes | None
    chain_key_recv: bytes | None
    send_message_number: int
    recv_message_number: int
    previous_send_chain_length: int
    skipped_keys: dict[tuple[bytes, int], bytes] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize state to a JSON-safe dict."""
        skipped = {
            f"{dh_pub.hex()}:{n}": mk.hex()
            for (dh_pub, n), mk in self.skipped_keys.items()
        }
        return {
            "dh_self_private": self.dh_self_private.hex(),
            "dh_self_public": self.dh_self_public.hex(),
            "dh_remote_public": self.dh_remote_public.hex() if self.dh_remote_public else None,
            "root_key": self.root_key.hex(),
            "chain_key_send": self.chain_key_send.hex() if self.chain_key_send else None,
            "chain_key_recv": self.chain_key_recv.hex() if self.chain_key_recv else None,
            "send_message_number": self.send_message_number,
            "recv_message_number": self.recv_message_number,
            "previous_send_chain_length": self.previous_send_chain_length,
            "skipped_keys": skipped,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RatchetState:
        """Deserialize state from a dict."""
        skipped = {}
        for k, v in d.get("skipped_keys", {}).items():
            dh_hex, n_str = k.rsplit(":", 1)
            skipped[(bytes.fromhex(dh_hex), int(n_str))] = bytes.fromhex(v)
        return cls(
            dh_self_private=bytes.fromhex(d["dh_self_private"]),
            dh_self_public=bytes.fromhex(d["dh_self_public"]),
            dh_remote_public=bytes.fromhex(d["dh_remote_public"]) if d.get("dh_remote_public") else None,
            root_key=bytes.fromhex(d["root_key"]),
            chain_key_send=bytes.fromhex(d["chain_key_send"]) if d.get("chain_key_send") else None,
            chain_key_recv=bytes.fromhex(d["chain_key_recv"]) if d.get("chain_key_recv") else None,
            send_message_number=d["send_message_number"],
            recv_message_number=d["recv_message_number"],
            previous_send_chain_length=d["previous_send_chain_length"],
            skipped_keys=skipped,
        )


class DoubleRatchet:
    """Double Ratchet session for E2E encrypted messaging.

    Provides per-message forward secrecy via a symmetric-key ratchet
    (HKDF chain) combined with a DH ratchet (X25519) that advances
    on each turn change.
    """

    def __init__(self, state: RatchetState, max_skip: int = MAX_SKIP) -> None:
        self._state = state
        self._max_skip = max_skip

    @classmethod
    def init_sender(
        cls,
        shared_secret: bytes,
        remote_dh_public: bytes,
        max_skip: int = MAX_SKIP,
    ) -> DoubleRatchet:
        """Initialize as the sender (X3DH initiator).

        Args:
            shared_secret: 32-byte shared secret from X3DH.
            remote_dh_public: Responder's signed pre-key (X25519 public).
            max_skip: Maximum skipped message keys to cache.
        """
        dh_self = _generate_dh_pair()
        dh_output = crypto_scalarmult(dh_self[0], remote_dh_public)
        root_key, chain_key_send = _kdf_root(shared_secret, dh_output)

        state = RatchetState(
            dh_self_private=dh_self[0],
            dh_self_public=dh_self[1],
            dh_remote_public=remote_dh_public,
            root_key=root_key,
            chain_key_send=chain_key_send,
            chain_key_recv=None,
            send_message_number=0,
            recv_message_number=0,
            previous_send_chain_length=0,
        )
        return cls(state, max_skip=max_skip)

    @classmethod
    def init_receiver(
        cls,
        shared_secret: bytes,
        dh_key_pair: tuple[bytes, bytes],
        max_skip: int = MAX_SKIP,
    ) -> DoubleRatchet:
        """Initialize as the receiver (X3DH responder).

        Args:
            shared_secret: 32-byte shared secret from X3DH.
            dh_key_pair: (private, public) X25519 key pair (the signed pre-key).
            max_skip: Maximum skipped message keys to cache.
        """
        state = RatchetState(
            dh_self_private=dh_key_pair[0],
            dh_self_public=dh_key_pair[1],
            dh_remote_public=None,
            root_key=shared_secret,
            chain_key_send=None,
            chain_key_recv=None,
            send_message_number=0,
            recv_message_number=0,
            previous_send_chain_length=0,
        )
        return cls(state, max_skip=max_skip)

    @property
    def state(self) -> RatchetState:
        """Return the current ratchet state (for persistence)."""
        return self._state

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> EncryptedMessage:
        """Encrypt a message with the current sending chain.

        Args:
            plaintext: Message bytes to encrypt.
            associated_data: Additional authenticated data (e.g., sender DID).

        Returns:
            An EncryptedMessage with header and ciphertext.
        """
        s = self._state
        if s.chain_key_send is None:
            raise RuntimeError("Send chain not initialized. Receive a message first.")

        message_key, next_chain_key = _kdf_chain(s.chain_key_send)
        s.chain_key_send = next_chain_key

        header = MessageHeader(
            dh_public_key=s.dh_self_public,
            previous_chain_length=s.previous_send_chain_length,
            message_number=s.send_message_number,
        )
        s.send_message_number += 1

        ciphertext = _encrypt(message_key, plaintext, associated_data + header.serialize())
        return EncryptedMessage(header=header, ciphertext=ciphertext)

    def decrypt(self, message: EncryptedMessage, associated_data: bytes = b"") -> bytes:
        """Decrypt a received message.

        Handles DH ratchet steps and out-of-order message delivery
        via cached skipped message keys.

        Args:
            message: The encrypted message to decrypt.
            associated_data: Additional authenticated data.

        Returns:
            Decrypted plaintext bytes.
        """
        s = self._state
        header = message.header

        # Check skipped keys first (out-of-order messages)
        skipped_key = s.skipped_keys.pop((header.dh_public_key, header.message_number), None)
        if skipped_key is not None:
            return _decrypt(skipped_key, message.ciphertext, associated_data + header.serialize())

        # DH ratchet step if the sender's DH key changed
        if s.dh_remote_public is None or header.dh_public_key != s.dh_remote_public:
            self._skip_messages(header.previous_chain_length)
            self._dh_ratchet_step(header.dh_public_key)

        self._skip_messages(header.message_number)

        message_key, next_chain_key = _kdf_chain(s.chain_key_recv)
        s.chain_key_recv = next_chain_key
        s.recv_message_number += 1

        return _decrypt(message_key, message.ciphertext, associated_data + header.serialize())

    def _dh_ratchet_step(self, remote_dh_public: bytes) -> None:
        """Perform a DH ratchet step with a new remote public key."""
        s = self._state
        s.previous_send_chain_length = s.send_message_number
        s.send_message_number = 0
        s.recv_message_number = 0
        s.dh_remote_public = remote_dh_public

        dh_output = crypto_scalarmult(s.dh_self_private, s.dh_remote_public)
        s.root_key, s.chain_key_recv = _kdf_root(s.root_key, dh_output)

        new_dh = _generate_dh_pair()
        s.dh_self_private = new_dh[0]
        s.dh_self_public = new_dh[1]

        dh_output = crypto_scalarmult(s.dh_self_private, s.dh_remote_public)
        s.root_key, s.chain_key_send = _kdf_root(s.root_key, dh_output)

    def _skip_messages(self, until: int) -> None:
        """Cache skipped message keys for out-of-order delivery."""
        s = self._state
        if s.chain_key_recv is None:
            return
        if until - s.recv_message_number > self._max_skip:
            raise RuntimeError(
                f"Too many skipped messages ({until - s.recv_message_number} > {self._max_skip})"
            )
        while s.recv_message_number < until:
            message_key, next_chain_key = _kdf_chain(s.chain_key_recv)
            s.skipped_keys[(s.dh_remote_public, s.recv_message_number)] = message_key
            s.chain_key_recv = next_chain_key
            s.recv_message_number += 1


# ── Primitives ──────────────────────────────────────────────────────


def _generate_dh_pair() -> tuple[bytes, bytes]:
    """Generate a random X25519 key pair. Returns (private, public)."""
    import secrets

    private = secrets.token_bytes(KEY_LEN)
    public = crypto_scalarmult_base(private)
    return private, public


def _kdf_root(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """Root KDF: derive new root key + chain key from DH output."""
    derived = HKDF(
        algorithm=SHA256(),
        length=64,
        salt=root_key,
        info=KDF_INFO_RATCHET,
    ).derive(dh_output)
    return derived[:32], derived[32:]


def _kdf_chain(chain_key: bytes) -> tuple[bytes, bytes]:
    """Chain KDF: derive message key + next chain key."""
    import hmac
    import hashlib

    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return message_key, next_chain_key


def _encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt with ChaCha20-Poly1305."""
    import secrets

    nonce = secrets.token_bytes(NONCE_LEN)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def _decrypt(key: bytes, data: bytes, aad: bytes) -> bytes:
    """Decrypt with ChaCha20-Poly1305."""
    if len(data) < NONCE_LEN:
        raise ValueError("Ciphertext too short")
    nonce = data[:NONCE_LEN]
    ciphertext = data[NONCE_LEN:]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, aad)
