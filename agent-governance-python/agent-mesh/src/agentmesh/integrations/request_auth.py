# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Canonical request authentication primitives for AgentMesh HTTP integrations.

This module is framework-agnostic and imports only the standard library, so the
Django, Flask, and FastAPI integrations all authenticate requests against the
*same* signed envelope. It owns four things:

* :func:`build_request_signature_payload` — the canonical bytes an agent signs.
* :func:`sanitize_did` — bounds untrusted DID input before it is resolved or logged.
* :class:`ReplayCache` — the atomic single-use nonce interface.
* :class:`InMemoryReplayCache` — a bounded, single-process implementation.

Note that importing it still initialises the ``agentmesh`` package; it is a
stdlib-only *leaf*, not an isolated distribution.

Security note
-------------
``did:mesh`` identifiers are random (see :meth:`AgentDID.generate`), not derived
from the public key, so a DID is **not** self-certifying. A caller-supplied
public key can therefore never authenticate a caller — an attacker would simply
present their own key beside someone else's DID. Verification keys MUST be
resolved from a trusted registry keyed by DID.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
import time
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

REQUEST_SIGNATURE_VERSION = "agentmesh-http-request-v1"

# Ed25519 signatures are always 64 bytes; anything else is malformed.
_ED25519_SIGNATURE_BYTES = 64
_ED25519_PUBLIC_KEY_BYTES = 32
_MAX_TIMESTAMP_CHARS = 64
_MAX_NONCE_CHARS = 128
_MIN_NONCE_BYTES = 16
_MAX_NONCE_BYTES = 64

# Untrusted DIDs arrive in a header and flow into resolver lookups and logs, so
# they are bounded and charset-restricted before either. The cap is generous
# enough for did:web/did:key while still preventing log flooding.
_MAX_DID_CHARS = 256
_DID_PREFIX = "did:"

# How often :class:`InMemoryReplayCache` sweeps expired entries, in seconds.
_PURGE_INTERVAL_SECONDS = 60.0


def sanitize_did(value: str) -> str | None:
    """Return ``value`` if it is a plausible, safely loggable DID, else ``None``.

    This bounds untrusted header input *before* it reaches a resolver or a log
    sink. It deliberately does not pin a single DID method — resolvers are
    pluggable — but it does reject oversized values and any character outside
    printable ASCII, which prevents log injection via CR/LF and terminal
    escapes, and keeps unbounded attacker data out of audit records.
    """
    if not value or len(value) > _MAX_DID_CHARS or not value.startswith(_DID_PREFIX):
        return None
    if any(char < " " or char > "~" for char in value):
        return None
    return value


def capability_satisfied(required: str, granted: tuple[str, ...]) -> bool:
    """Return whether ``granted`` satisfies ``required``.

    Mirrors :meth:`agentmesh.identity.AgentIdentity.has_capability` so that
    registry-sourced capabilities are interpreted identically wherever they are
    enforced: ``*`` grants everything and ``prefix:*`` grants ``prefix:<any>``.
    """
    for capability in granted:
        if capability in ("*", required):
            return True
        if capability.endswith(":*") and len(capability) > 2:
            if required.startswith(capability[:-2] + ":"):
                return True
    return False


class ReplayCacheFull(RuntimeError):
    """Raised when a replay cache cannot accept a nonce because it is at capacity.

    This is distinct from a duplicate nonce: both fail the request closed, but
    only a duplicate indicates an actual replay attempt. Keeping them separate
    stops capacity exhaustion from being recorded as an attack in audit logs.
    """


def build_request_signature_payload(
    *,
    agent_did: str,
    audience: str,
    timestamp: str,
    nonce: str,
    method: str,
    request_target: str,
    body: bytes,
    content_type: str = "",
) -> bytes:
    """Build the canonical bytes covered by an AgentMesh HTTP signature.

    The envelope binds the caller identity, the intended audience, freshness
    values, and the full HTTP request so a captured signature cannot be
    replayed against a different service, route, method, or body.
    """
    envelope = {
        "agent_did": agent_did,
        "audience": audience,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "content_type": content_type,
        "method": method.upper(),
        "nonce": nonce,
        "request_target": request_target,
        "timestamp": timestamp,
    }
    canonical_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    return f"{REQUEST_SIGNATURE_VERSION}\n{canonical_json}".encode()


def utcnow() -> datetime:
    """Return the current UTC time (patchable seam for deterministic tests)."""
    return datetime.now(UTC)


def decode_signature(signature_b64: str) -> bytes | None:
    """Decode a base64 Ed25519 signature, or ``None`` when malformed."""
    if not signature_b64:
        return None
    try:
        raw = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error):
        return None
    return raw if len(raw) == _ED25519_SIGNATURE_BYTES else None


def decode_public_key(public_key_b64: str) -> bytes | None:
    """Decode a base64 Ed25519 public key, or ``None`` when malformed."""
    if not public_key_b64:
        return None
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except (ValueError, binascii.Error):
        return None
    return raw if len(raw) == _ED25519_PUBLIC_KEY_BYTES else None


def parse_timestamp(timestamp: str, *, window_seconds: int, now: datetime) -> datetime | None:
    """Parse and freshness-check an ISO-8601 timestamp.

    Returns ``None`` when the value is malformed, naive (no timezone), or
    outside ``window_seconds`` in either direction.
    """
    if not timestamp or len(timestamp) > _MAX_TIMESTAMP_CHARS or window_seconds <= 0:
        return None
    normalised = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    if abs((now - parsed).total_seconds()) > window_seconds:
        return None
    return parsed


def decode_nonce(nonce: str) -> bytes | None:
    """Decode a base64url nonce and enforce a minimum entropy length."""
    if not nonce or len(nonce) > _MAX_NONCE_CHARS:
        return None
    try:
        padded = nonce + "=" * (-len(nonce) % 4)
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return None
    return raw if _MIN_NONCE_BYTES <= len(raw) <= _MAX_NONCE_BYTES else None


def replay_key(agent_did: str, audience: str, nonce_bytes: bytes) -> str:
    """Derive an opaque, collision-resistant replay-cache key.

    The nonce is hashed rather than stored verbatim so the cache never retains
    attacker-supplied bytes, and each field is length-delimited so
    ``(did_a, nonce_b)`` cannot collide with ``(did_a_nonce, b)``.

    The audience is part of the key because a nonce is only ever valid for one
    service. Without it, two services sharing a replay cache would let the first
    to see a request burn the nonce for the second, turning a shared cache into
    a cross-service denial-of-service vector.
    """
    material = b"\0".join(
        (agent_did.encode("utf-8"), audience.encode("utf-8"), nonce_bytes),
    )
    return "agentmesh:request-nonce:" + hashlib.sha256(material).hexdigest()


@runtime_checkable
class ReplayCache(Protocol):
    """Atomic single-use nonce store.

    Implementations MUST be atomic: concurrent callers presenting the same key
    must see exactly one ``True``. Back this with Redis ``SET NX`` or memcached
    ``add`` in multi-process deployments.
    """

    def add(self, key: str, ttl_seconds: int) -> bool:
        """Insert ``key`` if absent. Return ``True`` only for the first caller.

        Implementations that cannot accept the key because they are at capacity
        should raise :class:`ReplayCacheFull` rather than returning ``False``,
        so callers can distinguish exhaustion from a genuine replay.
        """
        ...


class InMemoryReplayCache:
    """Bounded, thread-safe, single-process :class:`ReplayCache`.

    Suitable for single-worker deployments and tests. It cannot prevent replay
    across processes, so :class:`~agentmesh.integrations.http_middleware.TrustMiddleware`
    requires an explicit opt-in before using it.

    Entries are expired on a monotonic clock so wall-clock adjustments cannot
    retire a nonce early. Expired entries are swept periodically rather than
    only at capacity, so steady-state memory tracks live nonces instead of
    growing to ``max_entries``. When the cache is genuinely full after a sweep
    the insert raises :class:`ReplayCacheFull`, which fails closed (denies the
    request) rather than silently permitting a replay.
    """

    def __init__(self, max_entries: int = 100_000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()
        self._next_purge = 0.0

    def add(self, key: str, ttl_seconds: int) -> bool:
        if ttl_seconds <= 0:
            return False
        now = time.monotonic()
        with self._lock:
            if now >= self._next_purge:
                self._purge(now)
                self._next_purge = now + _PURGE_INTERVAL_SECONDS
            expiry = self._entries.get(key)
            if expiry is not None and expiry > now:
                return False
            if len(self._entries) >= self._max_entries:
                self._purge(now)
                if len(self._entries) >= self._max_entries:
                    raise ReplayCacheFull(
                        f"replay cache is at capacity ({self._max_entries} entries)",
                    )
            self._entries[key] = now + ttl_seconds
            return True

    def _purge(self, now: float) -> None:
        """Drop expired entries. Caller must hold ``self._lock``."""
        expired = [key for key, expiry in self._entries.items() if expiry <= now]
        for key in expired:
            del self._entries[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


__all__ = [
    "REQUEST_SIGNATURE_VERSION",
    "InMemoryReplayCache",
    "ReplayCache",
    "ReplayCacheFull",
    "build_request_signature_payload",
    "capability_satisfied",
    "decode_nonce",
    "decode_public_key",
    "decode_signature",
    "parse_timestamp",
    "replay_key",
    "sanitize_did",
    "utcnow",
]
