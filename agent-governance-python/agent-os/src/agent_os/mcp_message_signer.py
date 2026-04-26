# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""HMAC signing and replay protection for MCP messages."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from agent_os.mcp_protocols import InMemoryNonceStore, MCPNonceStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MCPSignedEnvelope:
    """A signed MCP message envelope."""

    payload: str
    nonce: str
    timestamp: datetime
    signature: str
    sender_id: str | None = None


@dataclass(frozen=True)
class MCPVerificationResult:
    """The result of verifying a signed MCP envelope."""

    is_valid: bool
    payload: str | None = None
    sender_id: str | None = None
    failure_reason: str | None = None

    @classmethod
    def success(cls, payload: str, sender_id: str | None) -> "MCPVerificationResult":
        return cls(is_valid=True, payload=payload, sender_id=sender_id)

    @classmethod
    def failed(cls, reason: str) -> "MCPVerificationResult":
        return cls(is_valid=False, failure_reason=reason)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MCPMessageSigner:
    """Sign and verify MCP messages with replay protection.

    The signer produces tamper-evident envelopes and tracks nonces inside a
    replay window so previously accepted messages cannot be replayed
    indefinitely. Persistence and nonce generation are injectable to support
    deterministic tests and external storage backends.
    """

    def __init__(
        self,
        signing_key: bytes,
        *,
        replay_window: timedelta = timedelta(minutes=5),
        nonce_cache_cleanup_interval: timedelta = timedelta(minutes=10),
        max_nonce_cache_size: int = 10_000,
        nonce_store: MCPNonceStore | None = None,
        nonce_generator: Callable[[], str] | None = None,
    ) -> None:
        """Initialize the signer and replay-protection settings.

        Args:
            signing_key: Shared secret used to compute HMAC signatures.
            replay_window: Maximum permitted clock skew and replay horizon.
            nonce_cache_cleanup_interval: Minimum interval between automatic
                nonce cleanup passes.
            max_nonce_cache_size: Maximum number of nonces retained by the
                default in-memory nonce store.
            nonce_store: Optional nonce persistence backend. Defaults to the
                in-memory LRU nonce store.
            nonce_generator: Optional nonce factory for deterministic testing
                or custom nonce generation strategies.
        """
        if signing_key is None:
            raise ValueError("signing_key must not be None")
        if len(signing_key) < 32:
            raise ValueError("signing_key must be at least 32 bytes")
        if replay_window <= timedelta(0):
            raise ValueError("replay_window must be positive")
        if nonce_cache_cleanup_interval <= timedelta(0):
            raise ValueError("nonce_cache_cleanup_interval must be positive")
        if max_nonce_cache_size <= 0:
            raise ValueError("max_nonce_cache_size must be positive")

        self._signing_key = signing_key
        self.replay_window = replay_window
        self.nonce_cache_cleanup_interval = nonce_cache_cleanup_interval
        self.max_nonce_cache_size = max_nonce_cache_size
        self._lock = threading.Lock()
        self._nonce_store = nonce_store or InMemoryNonceStore(
            max_entries=max_nonce_cache_size,
        )
        self._nonce_generator = nonce_generator or (lambda: uuid.uuid4().hex)
        self._last_cleanup = _utcnow()

    @classmethod
    def from_base64_key(cls, base64_key: str) -> "MCPMessageSigner":
        """Build a signer from a base64-encoded shared secret.

        Args:
            base64_key: Shared secret encoded as ASCII base64 text.

        Returns:
            A configured ``MCPMessageSigner`` instance using the decoded key
            bytes.
        """
        if not base64_key or not base64_key.strip():
            raise ValueError("base64_key must not be empty")
        decoded = base64.b64decode(base64_key.encode("ascii"), validate=True)
        return cls(decoded)

    @staticmethod
    def generate_key() -> bytes:
        """Return a new 256-bit signing key.

        Returns:
            A cryptographically random 32-byte signing key.
        """
        return secrets.token_bytes(32)

    @property
    def cached_nonce_count(self) -> int:
        """Return the number of tracked nonces.

        Returns:
            The number of replay-protection nonces currently retained by the
            backing store when the store exposes a ``count`` helper.
        """
        with self._lock:
            count = getattr(self._nonce_store, "count", None)
            return int(count()) if callable(count) else 0

    def sign_message(self, payload: str, sender_id: str | None = None) -> MCPSignedEnvelope:
        """Create a signed message envelope.

        Args:
            payload: Serialized MCP payload to sign.
            sender_id: Optional sender identifier included in the signature.

        Returns:
            A signed envelope containing the payload, nonce, timestamp, and
            computed signature.
        """
        if payload is None:
            raise ValueError("payload must not be None")
        if not payload.strip():
            raise ValueError("payload must not be empty")

        timestamp = _utcnow()
        nonce = self._nonce_generator()
        signature = self._compute_signature(
            nonce=nonce,
            timestamp=timestamp,
            sender_id=sender_id,
            payload=payload,
        )
        return MCPSignedEnvelope(
            payload=payload,
            nonce=nonce,
            timestamp=timestamp,
            sender_id=sender_id,
            signature=signature,
        )

    def verify_message(self, envelope: MCPSignedEnvelope) -> MCPVerificationResult:
        """Verify an envelope's signature and replay metadata.

        Args:
            envelope: Signed message envelope to validate.

        Returns:
            ``MCPVerificationResult`` describing whether the envelope is valid
            and, on success, exposing the verified payload and sender identity.
            Invalid signatures, replayed nonces, or unexpected errors fail
            closed.
        """
        if envelope is None:
            raise ValueError("envelope must not be None")

        try:
            now = _utcnow()
            age = now - envelope.timestamp
            if age > self.replay_window or age < -self.replay_window:
                return MCPVerificationResult.failed("Message timestamp outside replay window.")

            with self._lock:
                self._maybe_cleanup_locked(now)
                if self._nonce_store.has(envelope.nonce):
                    logger.warning("Duplicate MCP nonce detected: %s", envelope.nonce)
                    return MCPVerificationResult.failed("Duplicate nonce (replay detected).")
                self._nonce_store.add(
                    envelope.nonce,
                    envelope.timestamp + self.replay_window,
                )

            expected_signature = self._compute_signature(
                nonce=envelope.nonce,
                timestamp=envelope.timestamp,
                sender_id=envelope.sender_id,
                payload=envelope.payload,
            )
            if not hmac.compare_digest(expected_signature, envelope.signature):
                return MCPVerificationResult.failed("Invalid signature.")

            return MCPVerificationResult.success(envelope.payload, envelope.sender_id)
        except Exception as exc:
            logger.error("MCP signature verification failed closed", exc_info=True)
            return MCPVerificationResult.failed(f"Verification error (fail-closed): {exc}")

    def cleanup_nonce_cache(self) -> int:
        """Remove expired nonces and return the number removed.

        Returns:
            The number of expired nonces removed from the backing store.
        """
        with self._lock:
            return self._cleanup_nonce_cache_locked(_utcnow())

    def _compute_signature(
        self,
        *,
        nonce: str,
        timestamp: datetime,
        sender_id: str | None,
        payload: str,
    ) -> str:
        canonical = self._build_canonical_string(
            nonce=nonce,
            timestamp=timestamp,
            sender_id=sender_id,
            payload=payload,
        )
        digest = hmac.new(
            self._signing_key,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return base64.b64encode(digest).decode("ascii")

    @staticmethod
    def _build_canonical_string(
        *,
        nonce: str,
        timestamp: datetime,
        sender_id: str | None,
        payload: str,
    ) -> str:
        timestamp_ms = int(timestamp.timestamp() * 1000)
        return f"{nonce}|{timestamp_ms}|{sender_id or ''}|{payload}"

    def _maybe_cleanup_locked(self, now: datetime) -> None:
        if now - self._last_cleanup >= self.nonce_cache_cleanup_interval:
            self._cleanup_nonce_cache_locked(now)

    def _cleanup_nonce_cache_locked(self, now: datetime) -> int:
        expired = self._nonce_store.cleanup()
        self._last_cleanup = now
        return expired
