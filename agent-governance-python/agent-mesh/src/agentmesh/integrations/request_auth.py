# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Canonical request authentication primitives for AgentMesh HTTP integrations.

This module is framework-agnostic and imports only the standard library, so the
Django, Flask, and FastAPI integrations all authenticate requests against the
*same* signed envelope. It owns five things:

* :func:`build_request_signature_payload` — the canonical bytes an agent signs.
* :func:`asgi_raw_target` / :func:`wsgi_raw_target` — recovery of the undecoded
  request target the signature binds.
* :func:`sanitize_did` — bounds untrusted DID input before it is resolved or logged.
* :class:`ReplayCache` — the atomic single-use nonce interface.
* :class:`InMemoryReplayCache` — a bounded, single-process implementation.

Note that importing it still initializes the ``agentmesh`` package; it is a
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
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, runtime_checkable

REQUEST_SIGNATURE_VERSION = "agentmesh-http-request-v2"

#: How the signed ``request_target`` was derived.
#:
#: ``"raw"`` is the origin-form target exactly as it appeared on the wire, so
#: ``/files/a%2Fb`` and ``/files/a/b`` sign different bytes. ``"decoded"`` is the
#: percent-decoded path the framework routes on; the two spellings collapse to
#: one value there, so a captured signature covers both. The mode is part of the
#: signed envelope, which means a caller cannot silently downgrade a server that
#: requires ``"raw"`` — the bytes simply fail to verify.
RequestTargetMode = Literal["raw", "decoded"]

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
    """Return ``value`` if it is a plausible DID that is safe to log, else ``None``.

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
    target_mode: RequestTargetMode,
    body: bytes,
    signed_headers: Mapping[str, str],
) -> bytes:
    """Build the canonical bytes covered by an AgentMesh HTTP signature.

    The envelope binds the caller identity, the intended audience, freshness
    values, and the full HTTP request so a captured signature cannot be
    replayed against a different service, route, method, body, or header set.

    ``request_target`` must match ``target_mode``: the origin-form target as
    sent on the wire for ``"raw"``, or the framework-decoded path (plus query)
    for ``"decoded"``. The mode travels inside the signed bytes so the two forms
    can never be confused for one another.

    ``signed_headers`` is the set of request headers the *server* requires to be
    covered, keyed by lowercase name. Only headers present on the request are
    included, so adding or removing one of them changes the envelope and
    invalidates the signature. The caller does not choose this set, which is
    what stops an attacker from narrowing coverage to headers that do not
    matter.

    The envelope is serialised as canonical JSON — sorted keys, no insignificant
    whitespace, ASCII-escaped — so no field value can be shifted into a
    neighboring field the way a delimiter-joined string allows.
    """
    envelope: dict[str, Any] = {
        "agent_did": agent_did,
        "audience": audience,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "method": method.upper(),
        "nonce": nonce,
        "request_target": request_target,
        "signed_headers": {name.lower(): value for name, value in signed_headers.items()},
        "target_mode": target_mode,
        "timestamp": timestamp,
    }
    canonical_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    return f"{REQUEST_SIGNATURE_VERSION}\n{canonical_json}".encode()


def select_signed_headers(
    names: Sequence[str],
    get_header: Callable[[str], str | None],
) -> dict[str, str]:
    """Collect the header values covered by the signature, keyed by lowercase name.

    Headers absent from the request are omitted rather than signed as an empty
    string, so "header not sent" and "header sent empty" are distinguishable
    inside the envelope.
    """
    selected: dict[str, str] = {}
    for name in names:
        key = name.lower()
        value = get_header(key)
        if value is not None:
            selected[key] = value
    return selected


def origin_form_target(target: str) -> str:
    """Reduce a request target to origin form (``/path?query``).

    A proxy may forward an absolute-form target (``https://host/path``). Signing
    it verbatim would make the same request sign differently depending on the
    hop it arrived through, so the scheme and authority are dropped. The
    audience field already binds the request to this service.
    """
    for scheme in ("http://", "https://"):
        if target.startswith(scheme):
            slash = target.find("/", len(scheme))
            return target[slash:] if slash != -1 else "/"
    return target


def asgi_raw_target(scope: Mapping[str, Any]) -> str | None:
    """Return the undecoded origin-form target from an ASGI scope, if available.

    ``raw_path`` is optional in the ASGI spec, but uvicorn, hypercorn, daphne,
    and Starlette's own test client all set it. ``None`` means this server
    cannot prove what was actually on the wire, and the caller must decide
    whether to fail closed.
    """
    raw_path = scope.get("raw_path")
    if isinstance(raw_path, (bytes, bytearray)):
        target = bytes(raw_path).decode("latin-1")
    elif isinstance(raw_path, str) and raw_path:
        target = raw_path
    else:
        return None

    query = scope.get("query_string")
    if isinstance(query, (bytes, bytearray)) and query:
        target = f"{target}?{bytes(query).decode('latin-1')}"
    elif isinstance(query, str) and query:
        target = f"{target}?{query}"
    return origin_form_target(target)


def wsgi_raw_target(environ: Mapping[str, Any]) -> str | None:
    """Return the undecoded origin-form target from a WSGI environ, if available.

    ``PATH_INFO`` is percent-decoded by the WSGI server, so it cannot serve as
    the signed target. ``RAW_URI`` (gunicorn, werkzeug) and ``REQUEST_URI``
    (uWSGI, mod_wsgi) carry the original. Servers that expose neither — Django's
    ``runserver`` and ``RequestFactory`` among them — return ``None``.
    """
    for key in ("RAW_URI", "REQUEST_URI"):
        value = environ.get(key)
        if isinstance(value, str) and value:
            return origin_form_target(value)
    return None


def decoded_target(path: str, query_string: str) -> str:
    """Build the framework-decoded request target used by ``"decoded"`` mode."""
    return f"{path}?{query_string}" if query_string else path


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

    def add(self, key: str, ttl_seconds: int, *, timeout_seconds: float | None = None) -> bool:
        """Insert ``key`` if absent. Return ``True`` only for the first caller.

        Implementations that cannot accept the key because they are at capacity
        should raise :class:`ReplayCacheFull` rather than returning ``False``,
        so callers can distinguish exhaustion from a genuine replay.

        ``timeout_seconds`` is the remaining share of the caller's request
        budget. An implementation that performs network I/O MUST bound that I/O
        by it — for example, a Redis client's socket timeout — and raise on
        expiry. The middleware runs this call synchronously and cannot interrupt
        it, so a store that ignores the deadline can still stall a request for
        as long as its own transport allows. Implementations that never block
        may ignore the argument. Accepting it is optional: the middleware
        detects support once, at construction, and omits it otherwise.
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

    def add(self, key: str, ttl_seconds: int, *, timeout_seconds: float | None = None) -> bool:
        # This cache is a bounded dict behind a lock: it performs no I/O, so it
        # always finishes well inside any deadline and the budget is unused.
        del timeout_seconds
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
    "RequestTargetMode",
    "asgi_raw_target",
    "build_request_signature_payload",
    "capability_satisfied",
    "decode_nonce",
    "decode_public_key",
    "decode_signature",
    "decoded_target",
    "origin_form_target",
    "parse_timestamp",
    "replay_key",
    "sanitize_did",
    "select_signed_headers",
    "utcnow",
    "wsgi_raw_target",
]
