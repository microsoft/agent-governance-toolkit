# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""TEE-aware key acquisition layer for confidential agent identity.

Provides an async key store abstraction for TEE-bound key material (Secure Key
Release, TEE-generated keys) alongside mock and local adapter implementations
for CI testing.  The existing synchronous ``KeyStore`` is not modified.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentmesh.exceptions import KeyAcquisitionError

from .attestation import KeyOrigin, public_key_hash_hex

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Key handle
# ---------------------------------------------------------------------------


class TEEKeyHandle(ABC):
    """Opaque handle to a key acquired from a TEE key store.

    Callers sign data through :meth:`sign` without direct access to raw
    private key material.  Concrete implementations decide how signing
    happens (in-memory, HSM call, remote signer, etc.).
    """

    @property
    @abstractmethod
    def key_id(self) -> str:
        """Identifier of the acquired key."""

    @property
    @abstractmethod
    def public_key(self) -> bytes:
        """Raw Ed25519 public key bytes (32 bytes)."""

    @property
    @abstractmethod
    def key_origin(self) -> KeyOrigin:
        """Origin classification of this key."""

    @property
    @abstractmethod
    def created_at(self) -> datetime:
        """UTC timestamp of key acquisition."""

    @property
    @abstractmethod
    def expires_at(self) -> datetime | None:
        """UTC expiry, or ``None`` if the handle does not expire."""

    # -- concrete helpers ---------------------------------------------------

    def is_expired(self) -> bool:
        """Return ``True`` when the handle has passed its expiry time."""
        if self.expires_at is None:
            return False
        return datetime.now(UTC) >= self.expires_at

    def public_key_hash(self) -> str:
        """SHA-256 hex digest of the public key for attestation binding."""
        return public_key_hash_hex(self.public_key)

    @abstractmethod
    async def sign(self, data: bytes) -> bytes:
        """Sign *data* using the acquired key.

        Raises:
            KeyAcquisitionError: If the handle has expired.
        """


class SoftwareKeyHandle(TEEKeyHandle):
    """Key handle backed by an in-memory Ed25519 private key.

    Used by :class:`LocalTEEKeyStore` and :class:`MockSKRKeyStore`.
    """

    def __init__(
        self,
        *,
        key_id: str,
        key_origin: KeyOrigin,
        private_key: ed25519.Ed25519PrivateKey,
        created_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        self._key_id = key_id
        self._key_origin = key_origin
        self._private_key = private_key
        self._public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._created_at = created_at or datetime.now(UTC)
        self._expires_at = expires_at

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key(self) -> bytes:
        return self._public_key

    @property
    def key_origin(self) -> KeyOrigin:
        return self._key_origin

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def expires_at(self) -> datetime | None:
        return self._expires_at

    async def sign(self, data: bytes) -> bytes:
        """Sign *data*, rejecting expired handles."""
        if self.is_expired():
            raise KeyAcquisitionError(
                f"Key handle '{self._key_id}' has expired"
            )
        return self._private_key.sign(data)


# ---------------------------------------------------------------------------
# Key store ABC
# ---------------------------------------------------------------------------


class TEEKeyStore(ABC):
    """Async key store for TEE-bound key material.

    Separate from the existing synchronous :class:`~agentmesh.identity.KeyStore`
    because TEE key acquisition is async (network calls to AKV/MAA) and has
    fundamentally different failure modes (SKR denied, attestation expired,
    network errors).
    """

    @abstractmethod
    async def acquire_key(self, key_id: str) -> TEEKeyHandle:
        """Acquire a key from the backend.

        Returns a :class:`TEEKeyHandle` on success.

        Raises:
            KeyAcquisitionError: If the key cannot be acquired.
        """

    @abstractmethod
    def key_origin(self) -> KeyOrigin:
        """Return the :class:`KeyOrigin` for keys from this store."""


# ---------------------------------------------------------------------------
# Local adapter
# ---------------------------------------------------------------------------


class LocalTEEKeyStore(TEEKeyStore):
    """Adapter for non-TEE environments (``key_origin=LOCAL``).

    Wraps in-memory Ed25519 key generation behind the :class:`TEEKeyStore`
    interface so that downstream code (handshake, policy engine) can use a
    uniform async API regardless of whether a real TEE is present.
    """

    def __init__(self) -> None:
        self._keys: dict[str, tuple[ed25519.Ed25519PrivateKey, bytes]] = {}

    async def acquire_key(self, key_id: str) -> TEEKeyHandle:
        """Generate or return a cached in-memory Ed25519 key."""
        if key_id not in self._keys:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._keys[key_id] = (private_key, public_key)
            logger.debug("LocalTEEKeyStore generated key for %s", key_id)

        private_key, _public_key = self._keys[key_id]
        return SoftwareKeyHandle(
            key_id=key_id,
            key_origin=KeyOrigin.LOCAL,
            private_key=private_key,
        )

    def key_origin(self) -> KeyOrigin:
        return KeyOrigin.LOCAL


# ---------------------------------------------------------------------------
# Mock SKR store
# ---------------------------------------------------------------------------


class MockSKRKeyStore(TEEKeyStore):
    """CI-safe mock that simulates Azure Key Vault Secure Key Release.

    Supports configurable latency, error injection, key TTL, and
    ``key_origin`` override for testing downstream policy and handshake
    paths.
    """

    def __init__(
        self,
        *,
        latency_seconds: float = 0.0,
        error: Exception | None = None,
        key_origin_value: KeyOrigin = KeyOrigin.SKR,
        ttl_seconds: int | None = 3600,
    ) -> None:
        if latency_seconds < 0:
            raise ValueError("latency_seconds must not be negative")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive when set")

        self._latency = latency_seconds
        self._error = error
        self._key_origin = key_origin_value
        self._ttl_seconds = ttl_seconds
        self._keys: dict[str, tuple[ed25519.Ed25519PrivateKey, bytes]] = {}

    async def acquire_key(self, key_id: str) -> TEEKeyHandle:
        """Return a mock-released key, simulating SKR latency and errors."""
        if self._latency:
            await asyncio.sleep(self._latency)

        if self._error is not None:
            if isinstance(self._error, KeyAcquisitionError):
                raise self._error
            raise KeyAcquisitionError(
                f"Mock SKR key acquisition failed for '{key_id}'"
            ) from self._error

        if key_id not in self._keys:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._keys[key_id] = (private_key, public_key)

        private_key, _public_key = self._keys[key_id]
        now = datetime.now(UTC)
        expires_at = (
            now + timedelta(seconds=self._ttl_seconds)
            if self._ttl_seconds is not None
            else None
        )

        return SoftwareKeyHandle(
            key_id=key_id,
            key_origin=self._key_origin,
            private_key=private_key,
            created_at=now,
            expires_at=expires_at,
        )

    def key_origin(self) -> KeyOrigin:
        return self._key_origin


# ---------------------------------------------------------------------------
# Policy helper
# ---------------------------------------------------------------------------


def require_tee_bound_key(handle: TEEKeyHandle, context: str = "") -> None:
    """Raise if the key handle is not TEE-bound.

    Intended for use in handshake or policy enforcement layers (PR 4/5).

    Raises:
        KeyAcquisitionError: If ``handle.key_origin`` is not TEE-bound.
    """
    if not handle.key_origin.is_tee_bound:
        msg = (
            f"TEE-bound key required but got key_origin={handle.key_origin.value}"
        )
        if context:
            msg += f" ({context})"
        raise KeyAcquisitionError(msg)
