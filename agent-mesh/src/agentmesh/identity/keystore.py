# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
PKCS#11 Hardware Key Store

Abstract key store with software (in-memory Ed25519) and HSM-backed (PKCS#11) implementations.
All key operations are logged for audit compliance.
"""

from __future__ import annotations

import abc
import logging
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class KeyStore(abc.ABC):
    """Abstract base class for cryptographic key storage backends.

    Defines the interface for generating, signing, verifying, retrieving, and
    deleting Ed25519 keypairs bound to agent identities. Implementations may
    store keys in memory, on disk, or in a hardware security module (HSM).

    Example:
        >>> store = SoftwareKeyStore()
        >>> pub = store.generate_keypair("agent-1")
        >>> sig = store.sign("agent-1", b"hello")
        >>> store.verify(pub, b"hello", sig)
        True
    """

    @abc.abstractmethod
    def generate_keypair(self, agent_id: str) -> bytes:
        """Generate an Ed25519 keypair for the given agent.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            The raw public key bytes (32 bytes for Ed25519).

        Raises:
            ValueError: If a keypair already exists for ``agent_id``.
        """

    @abc.abstractmethod
    def sign(self, agent_id: str, data: bytes) -> bytes:
        """Sign *data* with the private key of *agent_id*.

        Args:
            agent_id: Unique identifier of the agent whose key is used.
            data: Arbitrary bytes to sign.

        Returns:
            The Ed25519 signature bytes.

        Raises:
            KeyError: If no keypair exists for ``agent_id``.
        """

    @abc.abstractmethod
    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature against a public key.

        Args:
            public_key: Raw Ed25519 public key bytes.
            data: The original data that was signed.
            signature: The signature to verify.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """

    @abc.abstractmethod
    def get_public_key(self, agent_id: str) -> bytes:
        """Retrieve the raw public key bytes for *agent_id*.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            Raw Ed25519 public key bytes.

        Raises:
            KeyError: If no keypair exists for ``agent_id``.
        """

    @abc.abstractmethod
    def delete_key(self, agent_id: str) -> None:
        """Delete the keypair for *agent_id*.

        Args:
            agent_id: Unique identifier of the agent.

        Raises:
            KeyError: If no keypair exists for ``agent_id``.
        """


class SoftwareKeyStore(KeyStore):
    """In-memory Ed25519 key store (default backend).

    Keys are generated and held in process memory using the ``cryptography``
    library. Suitable for development, testing, and non-HSM deployments.

    Example:
        >>> store = SoftwareKeyStore()
        >>> pub = store.generate_keypair("agent-1")
        >>> sig = store.sign("agent-1", b"payload")
        >>> store.verify(pub, b"payload", sig)
        True
    """

    def __init__(self) -> None:
        self._keys: dict[str, ed25519.Ed25519PrivateKey] = {}

    def generate_keypair(self, agent_id: str) -> bytes:
        """Generate an Ed25519 keypair and store it in memory.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            Raw public key bytes (32 bytes).

        Raises:
            ValueError: If a key already exists for ``agent_id``.
        """
        if agent_id in self._keys:
            raise ValueError(f"Keypair already exists for agent: {agent_id}")

        private_key = ed25519.Ed25519PrivateKey.generate()
        self._keys[agent_id] = private_key

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        logger.info("Generated software keypair for agent %s", agent_id)
        return public_key_bytes

    def sign(self, agent_id: str, data: bytes) -> bytes:
        """Sign data with the in-memory private key.

        Args:
            agent_id: Agent whose private key is used.
            data: Data to sign.

        Returns:
            Ed25519 signature bytes.

        Raises:
            KeyError: If no keypair exists for ``agent_id``.
        """
        if agent_id not in self._keys:
            raise KeyError(f"No keypair found for agent: {agent_id}")

        signature = self._keys[agent_id].sign(data)
        logger.debug("Signed %d bytes for agent %s", len(data), agent_id)
        return signature

    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature.

        Args:
            public_key: Raw Ed25519 public key bytes.
            data: Original data that was signed.
            signature: Signature to verify.

        Returns:
            ``True`` if valid, ``False`` otherwise.
        """
        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, data)
            return True
        except Exception:
            return False

    def get_public_key(self, agent_id: str) -> bytes:
        """Retrieve the public key for an agent.

        Args:
            agent_id: Agent identifier.

        Returns:
            Raw Ed25519 public key bytes.

        Raises:
            KeyError: If no keypair exists for ``agent_id``.
        """
        if agent_id not in self._keys:
            raise KeyError(f"No keypair found for agent: {agent_id}")

        return self._keys[agent_id].public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def delete_key(self, agent_id: str) -> None:
        """Delete an agent's keypair from memory.

        Args:
            agent_id: Agent identifier.

        Raises:
            KeyError: If no keypair exists for ``agent_id``.
        """
        if agent_id not in self._keys:
            raise KeyError(f"No keypair found for agent: {agent_id}")

        del self._keys[agent_id]
        logger.info("Deleted keypair for agent %s", agent_id)


class PKCS11KeyStore(KeyStore):
    """HSM-backed key store using the PKCS#11 interface.

    Delegates key generation, signing, and (where supported) verification to a
    hardware security module via a PKCS#11 shared library. The ``pkcs11``
    Python package is imported lazily so the dependency is optional.

    Args:
        library_path: Filesystem path to the PKCS#11 shared library
            (e.g. ``/usr/lib/softhsm/libsofthsm2.so``).
        slot: PKCS#11 slot index to use. Defaults to ``0``.
        pin: User PIN for the token. Defaults to ``None``.

    Raises:
        ImportError: If the ``pkcs11`` package is not installed.

    Example:
        >>> store = PKCS11KeyStore(  # doctest: +SKIP
        ...     library_path="/usr/lib/softhsm/libsofthsm2.so",
        ...     slot=0,
        ...     pin="1234",
        ... )
    """

    def __init__(
        self,
        library_path: str,
        slot: int = 0,
        pin: Optional[str] = None,
    ) -> None:
        try:
            import pkcs11 as _pkcs11  # type: ignore[import-untyped]

            self._pkcs11 = _pkcs11
        except ImportError as exc:
            raise ImportError(
                "The 'pkcs11' package is required for PKCS11KeyStore. "
                "Install it with: pip install python-pkcs11"
            ) from exc

        self._library_path = library_path
        self._slot = slot
        self._pin = pin
        self._lib = self._pkcs11.lib(library_path)
        self._handles: dict[str, tuple] = {}  # agent_id -> (pub_handle, priv_handle)
        logger.info(
            "Initialized PKCS#11 key store (library=%s, slot=%d)",
            library_path,
            slot,
        )

    def _open_session(self):
        """Open a read/write session on the configured slot.

        Returns:
            A PKCS#11 session context manager.
        """
        token = self._lib.get_slots()[self._slot]
        return token.open(rw=True, user_pin=self._pin)

    def generate_keypair(self, agent_id: str) -> bytes:
        """Generate an Ed25519 keypair on the HSM.

        Args:
            agent_id: Unique identifier of the agent.

        Returns:
            Raw public key bytes exported from the HSM.

        Raises:
            ValueError: If a keypair already exists for ``agent_id``.
        """
        if agent_id in self._handles:
            raise ValueError(f"Keypair already exists for agent: {agent_id}")

        with self._open_session() as session:
            pub, priv = session.generate_keypair(
                self._pkcs11.KeyType.EC_EDWARDS,
                label=agent_id,
            )
            self._handles[agent_id] = (pub, priv)
            public_key_bytes = pub[self._pkcs11.Attribute.EC_POINT]

        logger.info("Generated PKCS#11 keypair for agent %s", agent_id)
        return public_key_bytes

    def sign(self, agent_id: str, data: bytes) -> bytes:
        """Sign data using the HSM-held private key.

        Args:
            agent_id: Agent whose private key is used.
            data: Data to sign.

        Returns:
            Signature bytes produced by the HSM.

        Raises:
            KeyError: If no keypair exists for ``agent_id``.
        """
        if agent_id not in self._handles:
            raise KeyError(f"No keypair found for agent: {agent_id}")

        _, priv = self._handles[agent_id]
        with self._open_session():
            signature = priv.sign(data, mechanism=self._pkcs11.Mechanism.EDDSA)

        logger.debug("PKCS#11 signed %d bytes for agent %s", len(data), agent_id)
        return signature

    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature (software fallback).

        Verification is performed in software using the ``cryptography``
        library rather than round-tripping to the HSM.

        Args:
            public_key: Raw Ed25519 public key bytes.
            data: The original signed data.
            signature: The signature to verify.

        Returns:
            ``True`` if valid, ``False`` otherwise.
        """
        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, data)
            return True
        except Exception:
            return False

    def get_public_key(self, agent_id: str) -> bytes:
        """Retrieve the public key from the HSM for an agent.

        Args:
            agent_id: Agent identifier.

        Returns:
            Raw public key bytes.

        Raises:
            KeyError: If no keypair exists for ``agent_id``.
        """
        if agent_id not in self._handles:
            raise KeyError(f"No keypair found for agent: {agent_id}")

        pub, _ = self._handles[agent_id]
        return pub[self._pkcs11.Attribute.EC_POINT]

    def delete_key(self, agent_id: str) -> None:
        """Delete an agent's keypair from the HSM.

        Args:
            agent_id: Agent identifier.

        Raises:
            KeyError: If no keypair exists for ``agent_id``.
        """
        if agent_id not in self._handles:
            raise KeyError(f"No keypair found for agent: {agent_id}")

        pub, priv = self._handles[agent_id]
        with self._open_session():
            pub.destroy()
            priv.destroy()

        del self._handles[agent_id]
        logger.info("Deleted PKCS#11 keypair for agent %s", agent_id)
