# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""X3DH (Extended Triple Diffie-Hellman) key agreement.

Implements the Signal X3DH specification for establishing shared secrets
between agents. Uses AGT's Ed25519 identity keys converted to X25519
for the Diffie-Hellman operations.

Reference: https://signal.org/docs/specifications/x3dh/
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from typing import Protocol

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import (
    crypto_scalarmult,
    crypto_scalarmult_base,
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519,
)

logger = logging.getLogger(__name__)

X3DH_INFO = b"AgentMesh_X3DH_v1"
KEY_LEN = 32


@dataclass(frozen=True)
class X25519KeyPair:
    """An X25519 key pair for Diffie-Hellman operations."""

    private_key: bytes
    public_key: bytes

    @classmethod
    def generate(cls) -> X25519KeyPair:
        """Generate a new random X25519 key pair."""
        private_key = secrets.token_bytes(KEY_LEN)
        public_key = crypto_scalarmult_base(private_key)
        return cls(private_key=private_key, public_key=public_key)

    @classmethod
    def from_ed25519(cls, ed25519_private: bytes, ed25519_public: bytes) -> X25519KeyPair:
        """Convert an Ed25519 key pair to X25519 via birational map.

        Args:
            ed25519_private: 64-byte Ed25519 secret key.
            ed25519_public: 32-byte Ed25519 public key.

        Returns:
            The corresponding X25519 key pair.
        """
        if len(ed25519_public) != 32:
            raise ValueError("ed25519_public must be 32 bytes")
        if len(ed25519_private) != 64:
            raise ValueError("ed25519_private must be 64 bytes")
        x_private = crypto_sign_ed25519_sk_to_curve25519(ed25519_private)
        x_public = crypto_sign_ed25519_pk_to_curve25519(ed25519_public)
        return cls(private_key=x_private, public_key=x_public)


@dataclass(frozen=True)
class SignedPreKey:
    """A signed pre-key: X25519 public key + Ed25519 signature."""

    key_pair: X25519KeyPair
    signature: bytes
    key_id: int


@dataclass(frozen=True)
class OneTimePreKey:
    """A one-time pre-key consumed during X3DH."""

    key_pair: X25519KeyPair
    key_id: int


@dataclass
class PreKeyBundle:
    """Public pre-key bundle published by an agent for X3DH.

    Contains the agent's identity public key (X25519), a signed pre-key,
    and optionally a one-time pre-key.
    """

    identity_key: bytes
    identity_key_ed: bytes  # Ed25519 signing public key for signature verification
    signed_pre_key: bytes
    signed_pre_key_signature: bytes
    signed_pre_key_id: int
    one_time_pre_key: bytes | None = None
    one_time_pre_key_id: int | None = None


class PreKeyStore(Protocol):
    """Protocol for storing and retrieving pre-key bundles."""

    def get_bundle(self, agent_did: str) -> PreKeyBundle | None:
        """Retrieve a pre-key bundle for the given agent DID."""
        ...

    def store_bundle(self, agent_did: str, bundle: PreKeyBundle) -> None:
        """Store a pre-key bundle for the given agent DID."""
        ...

    def consume_one_time_key(self, agent_did: str, key_id: int) -> bool:
        """Mark a one-time pre-key as consumed. Returns True if it existed."""
        ...


class InMemoryPreKeyStore:
    """Thread-safe in-memory pre-key store for development and testing."""

    def __init__(self) -> None:
        self._bundles: dict[str, PreKeyBundle] = {}
        self._consumed_otks: set[tuple[str, int]] = set()

    def get_bundle(self, agent_did: str) -> PreKeyBundle | None:
        return self._bundles.get(agent_did)

    def store_bundle(self, agent_did: str, bundle: PreKeyBundle) -> None:
        self._bundles[agent_did] = bundle

    def consume_one_time_key(self, agent_did: str, key_id: int) -> bool:
        key = (agent_did, key_id)
        if key in self._consumed_otks:
            return False
        bundle = self._bundles.get(agent_did)
        if bundle is None or bundle.one_time_pre_key_id != key_id:
            return False
        self._consumed_otks.add(key)
        # Remove the OTK from the bundle
        self._bundles[agent_did] = PreKeyBundle(
            identity_key=bundle.identity_key,
            identity_key_ed=bundle.identity_key_ed,
            signed_pre_key=bundle.signed_pre_key,
            signed_pre_key_signature=bundle.signed_pre_key_signature,
            signed_pre_key_id=bundle.signed_pre_key_id,
            one_time_pre_key=None,
            one_time_pre_key_id=None,
        )
        return True


@dataclass(frozen=True)
class X3DHResult:
    """Result of an X3DH key agreement."""

    shared_secret: bytes
    ephemeral_public_key: bytes
    used_one_time_key_id: int | None
    associated_data: bytes


@dataclass
class X3DHKeyManager:
    """Manages X3DH key material for an agent.

    Generates identity keys, signed pre-keys, and one-time pre-keys,
    and performs the X3DH key agreement protocol.
    """

    identity_key: X25519KeyPair
    ed25519_private: bytes
    ed25519_public: bytes
    signed_pre_key: SignedPreKey | None = None
    one_time_pre_keys: dict[int, OneTimePreKey] = field(default_factory=dict)
    _next_spk_id: int = 0
    _next_otk_id: int = 0

    @classmethod
    def from_ed25519_keys(cls, private_key: bytes, public_key: bytes) -> X3DHKeyManager:
        """Create an X3DH key manager from Ed25519 identity keys.

        Args:
            private_key: 64-byte Ed25519 secret key.
            public_key: 32-byte Ed25519 public key.
        """
        identity_key = X25519KeyPair.from_ed25519(private_key, public_key)
        return cls(
            identity_key=identity_key,
            ed25519_private=private_key,
            ed25519_public=public_key,
        )

    def generate_signed_pre_key(self) -> SignedPreKey:
        """Generate a new signed pre-key and sign it with the Ed25519 identity key."""
        from nacl.signing import SigningKey

        key_pair = X25519KeyPair.generate()
        signing_key = SigningKey(self.ed25519_private[:32])
        signed = signing_key.sign(key_pair.public_key)
        signature = signed.signature

        spk = SignedPreKey(
            key_pair=key_pair,
            signature=signature,
            key_id=self._next_spk_id,
        )
        self._next_spk_id += 1
        self.signed_pre_key = spk
        return spk

    def generate_one_time_pre_keys(self, count: int = 10) -> list[OneTimePreKey]:
        """Generate a batch of one-time pre-keys."""
        keys = []
        for _ in range(count):
            key_pair = X25519KeyPair.generate()
            otk = OneTimePreKey(key_pair=key_pair, key_id=self._next_otk_id)
            self._next_otk_id += 1
            self.one_time_pre_keys[otk.key_id] = otk
            keys.append(otk)
        return keys

    def get_public_bundle(self, otk_id: int | None = None) -> PreKeyBundle:
        """Build a public pre-key bundle for distribution.

        Args:
            otk_id: Optional one-time pre-key ID to include.
        """
        if self.signed_pre_key is None:
            raise RuntimeError("No signed pre-key generated. Call generate_signed_pre_key() first.")

        otk_public = None
        otk_key_id = None
        if otk_id is not None and otk_id in self.one_time_pre_keys:
            otk = self.one_time_pre_keys[otk_id]
            otk_public = otk.key_pair.public_key
            otk_key_id = otk.key_id

        return PreKeyBundle(
            identity_key=self.identity_key.public_key,
            identity_key_ed=self.ed25519_public,
            signed_pre_key=self.signed_pre_key.key_pair.public_key,
            signed_pre_key_signature=self.signed_pre_key.signature,
            signed_pre_key_id=self.signed_pre_key.key_id,
            one_time_pre_key=otk_public,
            one_time_pre_key_id=otk_key_id,
        )

    def initiate(self, peer_bundle: PreKeyBundle) -> X3DHResult:
        """Perform X3DH as the initiator.

        Args:
            peer_bundle: The responder's public pre-key bundle.

        Returns:
            X3DHResult with the shared secret and ephemeral public key.
        """
        self._verify_signed_pre_key(peer_bundle)

        ephemeral = X25519KeyPair.generate()

        # 4 (or 3) DH computations
        dh1 = crypto_scalarmult(self.identity_key.private_key, peer_bundle.signed_pre_key)
        dh2 = crypto_scalarmult(ephemeral.private_key, peer_bundle.identity_key)
        dh3 = crypto_scalarmult(ephemeral.private_key, peer_bundle.signed_pre_key)

        dh_concat = dh1 + dh2 + dh3

        used_otk_id = None
        if peer_bundle.one_time_pre_key is not None:
            dh4 = crypto_scalarmult(ephemeral.private_key, peer_bundle.one_time_pre_key)
            dh_concat += dh4
            used_otk_id = peer_bundle.one_time_pre_key_id

        shared_secret = _kdf(dh_concat)
        ad = self.identity_key.public_key + peer_bundle.identity_key

        return X3DHResult(
            shared_secret=shared_secret,
            ephemeral_public_key=ephemeral.public_key,
            used_one_time_key_id=used_otk_id,
            associated_data=ad,
        )

    def respond(
        self,
        peer_identity_key: bytes,
        ephemeral_public_key: bytes,
        used_one_time_key_id: int | None = None,
    ) -> X3DHResult:
        """Perform X3DH as the responder.

        Args:
            peer_identity_key: Initiator's X25519 identity public key.
            ephemeral_public_key: Initiator's ephemeral X25519 public key.
            used_one_time_key_id: ID of the one-time pre-key the initiator used, if any.

        Returns:
            X3DHResult with the same shared secret the initiator derived.
        """
        if self.signed_pre_key is None:
            raise RuntimeError("No signed pre-key available.")

        dh1 = crypto_scalarmult(self.signed_pre_key.key_pair.private_key, peer_identity_key)
        dh2 = crypto_scalarmult(self.identity_key.private_key, ephemeral_public_key)
        dh3 = crypto_scalarmult(self.signed_pre_key.key_pair.private_key, ephemeral_public_key)

        dh_concat = dh1 + dh2 + dh3

        if used_one_time_key_id is not None:
            otk = self.one_time_pre_keys.pop(used_one_time_key_id, None)
            if otk is None:
                raise ValueError(f"One-time pre-key {used_one_time_key_id} not found or already consumed.")
            dh4 = crypto_scalarmult(otk.key_pair.private_key, ephemeral_public_key)
            dh_concat += dh4

        shared_secret = _kdf(dh_concat)
        ad = peer_identity_key + self.identity_key.public_key

        return X3DHResult(
            shared_secret=shared_secret,
            ephemeral_public_key=ephemeral_public_key,
            used_one_time_key_id=used_one_time_key_id,
            associated_data=ad,
        )

    @staticmethod
    def _verify_signed_pre_key(bundle: PreKeyBundle) -> None:
        """Verify the signed pre-key signature against the Ed25519 identity key.

        Fail-closed: if identity_key_ed is missing or verification fails, raises.
        """
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError

        if not hasattr(bundle, "identity_key_ed") or not bundle.identity_key_ed:
            raise ValueError(
                "Missing Ed25519 identity key (identity_key_ed). "
                "Required for signed pre-key signature verification."
            )
        if len(bundle.identity_key_ed) != 32:
            raise ValueError("Invalid Ed25519 identity key length.")
        if len(bundle.signed_pre_key_signature) != 64:
            raise ValueError("Invalid signed pre-key signature length.")
        if len(bundle.signed_pre_key) != 32:
            raise ValueError("Invalid signed pre-key length.")
        if len(bundle.identity_key) != 32:
            raise ValueError("Invalid identity key length.")

        # Verify: the signature was created by ed25519.sign(signed_pre_key, ed25519_private)
        try:
            verify_key = VerifyKey(bundle.identity_key_ed)
            verify_key.verify(bundle.signed_pre_key, bundle.signed_pre_key_signature)
        except BadSignatureError:
            raise ValueError(
                "Signed pre-key signature verification FAILED. "
                "The pre-key was not signed by the claimed identity key."
            )


def _kdf(ikm: bytes) -> bytes:
    """Derive a 32-byte shared secret from the concatenated DH outputs."""
    # Prepend 32 bytes of 0xFF as specified by Signal X3DH
    salt = b"\xff" * 32
    hkdf = HKDF(
        algorithm=SHA256(),
        length=KEY_LEN,
        salt=salt,
        info=X3DH_INFO,
    )
    return hkdf.derive(ikm)
