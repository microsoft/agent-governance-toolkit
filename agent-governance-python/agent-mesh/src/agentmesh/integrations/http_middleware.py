# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
HTTP Trust Middleware for AgentMesh
====================================

Framework-agnostic middleware that authenticates incoming HTTP requests with an
Ed25519 signature bound to the caller's DID, this service's audience, a
freshness timestamp, a single-use nonce, and the HTTP request itself.

Provides a generic ``TrustMiddleware`` class plus thin decorators for Flask
(``flask_trust_required``) and FastAPI (``fastapi_trust_required``).  Missing
frameworks are handled gracefully — the decorators simply raise ImportError
at call time if their framework is unavailable.

Required request headers
------------------------
``X-Agent-DID``          caller identity, looked up in the peer registry
``X-Agent-Signature``    base64 Ed25519 signature over the canonical envelope
``X-Agent-Timestamp``    ISO-8601 timestamp with an explicit timezone
``X-Agent-Nonce``        base64url random value, single use

``X-Agent-Public-Key`` and ``X-Agent-Capabilities`` are **not** trust inputs.
``did:mesh`` identifiers are random rather than key-derived, so a caller-supplied
key proves nothing: an attacker would present their own key beside a victim's
DID. Verification keys and capabilities are resolved from the trusted peer
registry, keyed by DID. A supplied ``X-Agent-Public-Key`` is only accepted when
it matches the registered key exactly.
"""

from __future__ import annotations

import hmac
import inspect
import json
import logging
import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import wraps
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.integrations.request_auth import (
    InMemoryReplayCache,
    ReplayCache,
    ReplayCacheFull,
    RequestTargetMode,
    asgi_raw_target,
    build_request_signature_payload,
    capability_satisfied,
    decode_nonce,
    decode_public_key,
    decode_signature,
    decoded_target,
    parse_timestamp,
    replay_key,
    sanitize_did,
    select_signed_headers,
    utcnow,
    wsgi_raw_target,
)

logger = logging.getLogger(__name__)

HEADER_DID = "X-Agent-DID"
HEADER_SIGNATURE = "X-Agent-Signature"
HEADER_TIMESTAMP = "X-Agent-Timestamp"
HEADER_NONCE = "X-Agent-Nonce"
HEADER_PUBLIC_KEY = "X-Agent-Public-Key"
HEADER_CAPABILITIES = "X-Agent-Capabilities"

_DEFAULT_MAX_SIGNED_BODY_BYTES = 2_621_440  # 2.5 MiB


@dataclass(frozen=True)
class PeerCredential:
    """Registry-held facts about a peer agent.

    Attributes
    ----------
    public_key:
        Base64 Ed25519 public key used to verify the peer's request signature.
    capabilities:
        Capabilities the peer is *actually* granted. Never sourced from request
        headers.
    trust_score:
        Score awarded once the signature verifies.
    """

    public_key: str
    capabilities: tuple[str, ...] = ()
    trust_score: float = 1.0

    def has_capability(self, capability: str) -> bool:
        """Whether the registry grants ``capability`` to this peer.

        Delegates to the shared matcher so ``*`` and ``prefix:*`` mean the same
        thing here as they do in :meth:`AgentIdentity.has_capability`.
        """
        return capability_satisfied(capability, self.capabilities)


#: Resolves a DID to its registered credential, or ``None`` when unknown.
#:
#: A resolver may additionally accept a ``timeout_seconds`` keyword. When it
#: does, the middleware passes the remaining share of the request budget and the
#: resolver MUST bound its I/O by it — the middleware calls the resolver
#: synchronously and cannot interrupt it. Support is detected once, at
#: construction, so a plain ``Callable[[str], PeerCredential | None]`` keeps
#: working unchanged.
class PeerResolver(Protocol):
    def __call__(self, did: str, /) -> PeerCredential | None: ...


_TIMEOUT_KWARG = "timeout_seconds"


def _accepts_timeout(func: Any) -> bool:
    """Whether ``func`` can be passed the remaining request budget.

    Introspection runs once per middleware, never per request. A callable that
    cannot be introspected is assumed not to accept the deadline, which is the
    safe assumption: passing an unexpected keyword would raise on every request.
    """
    try:
        parameters = inspect.signature(func).parameters
    except (TypeError, ValueError):
        return False
    keyword = parameters.get(_TIMEOUT_KWARG)
    if keyword is not None and keyword.kind is not inspect.Parameter.POSITIONAL_ONLY:
        return True
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values())


@dataclass(frozen=True)
class TrustConfig:
    """Configuration for trust verification.

    Frozen: the ``permissive_mode`` guard below is an invariant, and a mutable
    dataclass would let a caller reconstruct the exact configuration it exists
    to forbid by assigning the field after construction.

    Field order matters. ``required_trust_score``, ``required_capabilities``,
    and ``permissive_mode`` keep the positions they held before request signing
    was introduced, so an existing positional ``TrustConfig(0.8, ["admin"])``
    still means what it always meant. Every field added since is appended.
    """

    required_trust_score: float = 0.5
    required_capabilities: tuple[str, ...] = ()
    #: Allow requests that carry *no* DID header through as unauthenticated.
    #: Such results always have ``authenticated=False`` and ``trust_score=0.0``.
    permissive_mode: bool = False
    #: Identifier of *this* service, covered by the caller's signature. Required.
    audience: str = ""
    #: Accepted clock skew and nonce retention, in seconds.
    replay_window_seconds: int = 300
    max_signed_body_bytes: int = _DEFAULT_MAX_SIGNED_BODY_BYTES
    #: Request headers the signature must cover, lowercase. The *server* fixes
    #: this set, so a caller cannot narrow coverage to headers that do not
    #: matter. Add any header the endpoint acts on — a tenant, an API version,
    #: an idempotency key — and it becomes tamper-evident.
    signed_header_names: tuple[str, ...] = ("content-type",)
    #: Which form of the request target the signature binds. ``"raw"`` requires
    #: the server to expose the undecoded target and is the secure default;
    #: ``"decoded"`` is an explicit opt-out for servers that cannot.
    request_target_mode: RequestTargetMode = "raw"
    #: Budget, in seconds, for the I/O verification performs: peer resolution,
    #: the replay-store claim, and reading the request body.
    io_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        # A bare str is iterable, so tuple("admin") would silently become five
        # single-character capabilities that no peer can ever satisfy.
        if isinstance(self.required_capabilities, str):
            raise ValueError(
                "required_capabilities must be a sequence of strings, not a single string"
            )
        # Accept any iterable (lists are common at call sites) but store an
        # immutable tuple so the authorization set cannot be mutated later.
        object.__setattr__(self, "required_capabilities", tuple(self.required_capabilities))
        if isinstance(self.signed_header_names, str):
            raise ValueError(
                "signed_header_names must be a sequence of header names, not a single string"
            )
        # Lowercase and de-duplicate: HTTP header names are case-insensitive, so
        # "Content-Type" and "content-type" are one covered header, not two.
        normalised: list[str] = []
        for name in self.signed_header_names:
            key = name.strip().lower()
            if not key:
                raise ValueError("signed_header_names entries must be non-empty header names")
            if key not in normalised:
                normalised.append(key)
        object.__setattr__(self, "signed_header_names", tuple(normalised))
        if self.request_target_mode not in ("raw", "decoded"):
            raise ValueError(
                "request_target_mode must be 'raw' or 'decoded', not "
                f"{self.request_target_mode!r}"
            )
        if self.replay_window_seconds <= 0:
            raise ValueError("replay_window_seconds must be positive")
        if self.max_signed_body_bytes <= 0:
            raise ValueError("max_signed_body_bytes must be positive")
        if self.io_timeout_seconds <= 0:
            raise ValueError("io_timeout_seconds must be positive")
        if self.permissive_mode:
            # An anonymous caller has no proven capabilities and a trust score
            # of 0.0, so pairing permissive mode with an authorization gate is
            # always contradictory: it reads as "require admin" while admitting
            # callers who proved nothing. Rather than silently resolving the
            # contradiction, refuse the configuration so the operator has to
            # state which behaviour they actually want.
            if self.required_capabilities:
                raise ValueError(
                    "permissive_mode cannot be combined with required_capabilities: "
                    "anonymous callers have no registry-granted capabilities, so the "
                    "requirement would silently not apply to them"
                )
            if self.required_trust_score > 0:
                raise ValueError(
                    "permissive_mode requires required_trust_score=0.0: anonymous callers "
                    "score 0.0, so any positive threshold would silently not apply to them"
                )


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of a trust verification check.

    ``verified`` means "allowed to proceed". ``authenticated`` means "identity
    was cryptographically proven". They differ only in permissive mode, where an
    anonymous caller is allowed through without proving anything — downstream
    code must branch on ``authenticated`` before trusting ``peer_did``.

    As with :class:`TrustConfig`, the four original fields keep their positions
    and the two that request signing added are appended, so existing positional
    construction still binds the values its author intended.
    """

    verified: bool
    trust_score: float = 0.0
    reason: str = ""
    peer_did: str = ""
    authenticated: bool = False
    capabilities: tuple[str, ...] = ()


def registry_resolver(
    registry: Any,
    *,
    default_trust_score: float = 1.0,
) -> PeerResolver:
    """Build a :data:`PeerResolver` backed by an ``IdentityRegistry``.

    Revoked, expired, or untrusted identities resolve to ``None`` so they fail
    closed exactly like unknown DIDs.
    """

    def resolve(did: str) -> PeerCredential | None:
        identity = registry.get(did)
        if identity is None:
            return None
        is_trusted = getattr(registry, "is_trusted", None)
        if callable(is_trusted) and not is_trusted(did):
            return None
        is_active = getattr(identity, "is_active", None)
        if callable(is_active) and not is_active():
            return None
        return PeerCredential(
            public_key=identity.public_key,
            capabilities=tuple(getattr(identity, "capabilities", ()) or ()),
            trust_score=default_trust_score,
        )

    return resolve


def _header(headers: Mapping[str, str], name: str) -> str:
    """Case-insensitive header lookup, empty string when absent.

    Starlette lowercases header keys while Werkzeug preserves the wire casing,
    so an exact-match lookup silently misses on one framework or the other.
    """
    value = _optional_header(headers, name)
    return value if value is not None else ""


def _optional_header(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive header lookup that distinguishes absent from empty.

    The signed-header set needs that distinction: a header sent as ``""`` and a
    header not sent at all must not produce the same signed envelope.
    """
    value = headers.get(name)
    if value is not None:
        return value
    target = name.lower()
    for key, candidate in headers.items():
        if key.lower() == target:
            return candidate
    return None


def _remaining(deadline: float) -> float:
    """Seconds left in the request budget, never negative."""
    return max(0.0, deadline - time.monotonic())


def _expired(deadline: float) -> bool:
    """Whether the request budget is spent."""
    return time.monotonic() >= deadline


class TrustMiddleware:
    """Framework-agnostic HTTP request authentication.

    Parameters
    ----------
    identity : AgentIdentity, optional
        Local agent identity, used only to attach outgoing response headers.
    config : TrustConfig, optional
        Verification thresholds and behaviour knobs. ``audience`` is required.
    peer_resolver : PeerResolver, optional
        Resolves a caller DID to its registered credential. Required — a
        middleware with no trust anchor cannot authenticate anyone.
    replay_cache : ReplayCache, optional
        Atomic single-use nonce store. Use Redis/memcached in multi-process
        deployments.
    allow_insecure_replay_cache : bool
        Opt in to the bounded in-process nonce cache. It cannot detect replay
        across workers, so it is refused unless explicitly requested.
    """

    def __init__(
        self,
        identity: AgentIdentity | None = None,
        config: TrustConfig | None = None,
        *,
        peer_resolver: PeerResolver | None = None,
        replay_cache: ReplayCache | None = None,
        allow_insecure_replay_cache: bool = False,
    ) -> None:
        self.identity = identity
        self.config = config or TrustConfig()
        if not self.config.audience.strip():
            raise ValueError(
                "TrustConfig.audience must identify this service; it is covered by the "
                "caller's signature so a signature captured elsewhere cannot be replayed here"
            )
        if peer_resolver is None:
            raise ValueError(
                "peer_resolver is required: verification keys must come from a trusted "
                "registry keyed by DID, never from request headers"
            )
        self._resolve_peer = peer_resolver

        if replay_cache is None:
            if not allow_insecure_replay_cache:
                raise ValueError(
                    "replay_cache is required: supply a shared atomic store (Redis SET NX or "
                    "memcached add), or pass allow_insecure_replay_cache=True to accept the "
                    "in-process cache, which cannot detect replay across workers"
                )
            replay_cache = InMemoryReplayCache()
        self._replay_cache = replay_cache
        # Introspect the ports once here rather than on every request: the
        # deadline is only passed to implementations that declare they accept
        # it, so existing plain resolvers and caches keep working.
        self._resolver_accepts_timeout = _accepts_timeout(peer_resolver)
        self._replay_cache_accepts_timeout = _accepts_timeout(replay_cache.add)

    @classmethod
    def from_registry(
        cls,
        registry: Any,
        config: TrustConfig | None = None,
        *,
        identity: AgentIdentity | None = None,
        replay_cache: ReplayCache | None = None,
        allow_insecure_replay_cache: bool = False,
    ) -> TrustMiddleware:
        """Construct middleware anchored on an ``IdentityRegistry``."""
        return cls(
            identity=identity,
            config=config,
            peer_resolver=registry_resolver(registry),
            replay_cache=replay_cache,
            allow_insecure_replay_cache=allow_insecure_replay_cache,
        )

    # -- core verification (framework-independent) -------------------------

    def verify_request(
        self,
        headers: Mapping[str, str],
        config_override: TrustConfig | None = None,
        *,
        method: str | None = None,
        request_target: str | None = None,
        body: bytes | None = None,
    ) -> tuple[VerificationResult, dict[str, Any] | None]:
        """Authenticate a request and return *(result, error_body | None)*.

        *error_body* is a JSON-serialisable dict when verification fails, or
        ``None`` on success.  It carries a ``status`` hint (401 for failed
        authentication, 403 for failed authorization) that callers may use to
        build a framework-specific response.

        ``method``, ``request_target`` and ``body`` are required: the signature
        covers the full request, so verification fails closed without them.
        ``request_target`` must be in the form named by
        :attr:`TrustConfig.request_target_mode` — the undecoded origin-form
        target for ``"raw"``, the decoded path (plus query) for ``"decoded"``.
        The covered headers are taken from ``headers`` using
        :attr:`TrustConfig.signed_header_names`; the caller does not choose them.

        Never raises. Every input to this method is attacker-controlled, so an
        unexpected error is converted into a denial rather than being allowed to
        surface as a 500 with a stack trace.
        """
        try:
            return self._verify_request(
                headers,
                config_override,
                method=method,
                request_target=request_target,
                body=body,
            )
        except Exception:
            # Recovering the DID is best-effort: `headers` is attacker-supplied
            # and may itself be what raised, so a failure here must not escape
            # and void this method's never-raise guarantee.
            try:
                peer_did = sanitize_did(_header(headers, HEADER_DID)) or ""
            except Exception:
                peer_did = ""
            _denial_signal.log_exception(
                "verify_request",
                "Unexpected error during trust verification for agent %r; denying request",
                peer_did,
            )
            # 503, not 401: this is a server fault, and reporting it as a
            # credential failure would hide an authentication outage inside
            # normal auth-failure telemetry.
            return self._deny(
                "Trust verification raised an unexpected error",
                status=503,
                peer_did=peer_did,
            )

    def _verify_request(
        self,
        headers: Mapping[str, str],
        config_override: TrustConfig | None = None,
        *,
        method: str | None = None,
        request_target: str | None = None,
        body: bytes | None = None,
    ) -> tuple[VerificationResult, dict[str, Any] | None]:
        cfg = config_override or self.config
        # Everything from here to the protected action shares one budget, so a
        # slow registry cannot be paid for twice by also spending the replay
        # store's share.
        deadline = time.monotonic() + cfg.io_timeout_seconds
        if not cfg.audience.strip():
            return self._deny("Middleware misconfigured: audience is not set", status=500)

        raw_did = _header(headers, HEADER_DID)
        if not raw_did:
            if cfg.permissive_mode:
                return (
                    VerificationResult(verified=True, authenticated=False, reason="anonymous"),
                    None,
                )
            return self._deny(f"Missing {HEADER_DID} header", status=401)

        # Bound and charset-check the DID before it reaches a resolver or a log
        # sink, so an unauthenticated caller cannot flood logs or inject control
        # characters into audit records.
        peer_did = sanitize_did(raw_did)
        if peer_did is None:
            return self._deny(f"Malformed {HEADER_DID} header", status=401)

        if method is None or request_target is None or body is None:
            logger.error(
                "verify_request called without request context; cannot bind signature to request"
            )
            return self._deny(
                "Middleware misconfigured: request method, target and body are required",
                status=500,
                peer_did=peer_did,
            )

        if len(body) > cfg.max_signed_body_bytes:
            return self._deny("Request body exceeds signed-body limit", status=413, peer_did=peer_did)

        signature = decode_signature(_header(headers, HEADER_SIGNATURE))
        if signature is None:
            return self._deny(f"Missing or malformed {HEADER_SIGNATURE} header", status=401,
                              peer_did=peer_did)

        raw_timestamp = _header(headers, HEADER_TIMESTAMP)
        now = utcnow()
        timestamp = parse_timestamp(
            raw_timestamp, window_seconds=cfg.replay_window_seconds, now=now
        )
        if timestamp is None:
            return self._deny(f"Missing, malformed or stale {HEADER_TIMESTAMP} header",
                              status=401, peer_did=peer_did)

        raw_nonce = _header(headers, HEADER_NONCE)
        nonce_bytes = decode_nonce(raw_nonce)
        if nonce_bytes is None:
            return self._deny(f"Missing or malformed {HEADER_NONCE} header", status=401,
                              peer_did=peer_did)

        credential = self._resolve_credential(peer_did, deadline)
        if credential is None:
            # Pre-authentication failures are logged at DEBUG: the caller has
            # proven nothing, so anyone on the network could otherwise drive
            # unbounded WARNING volume. Post-authentication events (see
            # _consume_nonce) stay at WARNING because reaching them requires a
            # valid signature.
            logger.debug("No registered credential for agent %s", peer_did)
            return self._deny("Unknown or untrusted agent DID", status=401, peer_did=peer_did)

        verify_key_bytes = decode_public_key(credential.public_key)
        if verify_key_bytes is None:
            logger.error("Registered public key for %s is malformed", peer_did)
            return self._deny("Unknown or untrusted agent DID", status=401, peer_did=peer_did)

        # A presented key is a hint only; it must match the registered key.
        # Compare decoded bytes, not the base64 text: header values decode as
        # latin-1, so a non-ASCII byte would make compare_digest() raise on
        # str inputs, and base64 padding/alphabet variance would otherwise
        # cause false mismatches for a correct key.
        raw_presented_key = _header(headers, HEADER_PUBLIC_KEY)
        if raw_presented_key:
            presented_key = decode_public_key(raw_presented_key)
            if presented_key is None or not hmac.compare_digest(presented_key, verify_key_bytes):
                logger.debug("Presented public key does not match registry for agent %s", peer_did)
                return self._deny("Presented public key does not match the registered key",
                                  status=401, peer_did=peer_did)

        payload = build_request_signature_payload(
            agent_did=peer_did,
            audience=cfg.audience,
            timestamp=raw_timestamp,
            nonce=raw_nonce,
            method=method,
            request_target=request_target,
            target_mode=cfg.request_target_mode,
            body=body,
            signed_headers=select_signed_headers(
                cfg.signed_header_names,
                lambda name: _optional_header(headers, name),
            ),
        )
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(verify_key_bytes).verify(signature, payload)
        except (InvalidSignature, ValueError):
            logger.debug("Signature verification failed for agent %s", peer_did)
            return self._deny("Signature verification failed", status=401, peer_did=peer_did)

        # The resolver may have consumed the whole budget. Check before claiming
        # the nonce so a stalled registry cannot burn a caller's single-use
        # nonce on a request that is about to be refused anyway.
        if _expired(deadline):
            return self._deny(
                "Trust verification exceeded its time budget", status=503, peer_did=peer_did
            )

        # Burn the nonce only after the signature proves the caller holds the
        # key, so an unauthenticated attacker cannot exhaust or poison the cache.
        nonce_denial = self._consume_nonce(peer_did, nonce_bytes, timestamp, now, cfg, deadline)
        if nonce_denial is not None:
            reason, status = nonce_denial
            return self._deny(reason, status=status, peer_did=peer_did)

        # Guard against verification taking longer than the freshness window.
        if abs((utcnow() - timestamp).total_seconds()) > cfg.replay_window_seconds:
            return self._deny("Missing, malformed or stale X-Agent-Timestamp header",
                              status=401, peer_did=peer_did)

        # Authorization uses registry-held capabilities; the X-Agent-Capabilities
        # header is self-asserted and is deliberately ignored.
        missing = [c for c in cfg.required_capabilities if not credential.has_capability(c)]
        if missing:
            # Post-authentication, so WARNING is safe and warranted: reaching
            # here required a valid signature, an anonymous caller cannot flood
            # it, and repeated capability probing by a known agent is exactly
            # the governance event an operator needs to see.
            logger.warning(
                "Agent %s denied: missing capabilities %s", peer_did, missing
            )
            return (
                VerificationResult(
                    verified=False,
                    authenticated=True,
                    peer_did=peer_did,
                    trust_score=credential.trust_score,
                    capabilities=credential.capabilities,
                    reason=f"Missing capabilities: {missing}",
                ),
                {
                    "error": "Insufficient capabilities",
                    "reason": f"Missing capabilities: {missing}",
                    "missing": missing,
                    "status": 403,
                },
            )

        if credential.trust_score < cfg.required_trust_score:
            return (
                VerificationResult(
                    verified=False,
                    authenticated=True,
                    peer_did=peer_did,
                    trust_score=credential.trust_score,
                    capabilities=credential.capabilities,
                    reason="Trust score too low",
                ),
                {
                    "error": "Insufficient trust score",
                    "reason": "Trust score too low",
                    "required": cfg.required_trust_score,
                    "actual": credential.trust_score,
                    "status": 403,
                },
            )

        return (
            VerificationResult(
                verified=True,
                authenticated=True,
                peer_did=peer_did,
                trust_score=credential.trust_score,
                capabilities=credential.capabilities,
            ),
            None,
        )

    # -- internals ---------------------------------------------------------

    def _resolve_credential(self, peer_did: str, deadline: float) -> PeerCredential | None:
        """Resolve the peer's registered credential within the request budget.

        A resolver that *raises* is a registry fault, not a credential fault, so
        the exception is allowed to reach ``verify_request``'s never-raise
        boundary and is reported as 503. Swallowing it into 401 would make a
        total authentication outage look like "every caller has bad
        credentials", hiding it from any alert keyed on 5xx. Only an explicit
        ``None`` — this DID is not registered — is an authentication failure.
        """
        if self._resolver_accepts_timeout:
            return self._resolve_peer(peer_did, timeout_seconds=_remaining(deadline))  # type: ignore[call-arg]
        return self._resolve_peer(peer_did)

    def _consume_nonce(
        self,
        peer_did: str,
        nonce_bytes: bytes,
        timestamp: Any,
        now: Any,
        cfg: TrustConfig,
        deadline: float,
    ) -> tuple[str, int] | None:
        """Atomically claim the nonce.

        Returns ``None`` on success, or a ``(reason, status)`` denial. A replay
        is reported as 401 and blamed on the caller; a cache that is unavailable,
        full, or too slow is reported as 503, because the caller did nothing
        wrong and recording it as an attack would corrupt the audit trail.
        """
        # Retain the nonce for the signed timestamp's whole validity interval,
        # including accepted future clock skew.
        ttl = max(1, math.ceil((timestamp - now).total_seconds() + cfg.replay_window_seconds))
        key = replay_key(peer_did, cfg.audience, nonce_bytes)
        try:
            if self._replay_cache_accepts_timeout:
                claimed = self._replay_cache.add(
                    key, ttl, timeout_seconds=_remaining(deadline)
                )
            else:
                claimed = self._replay_cache.add(key, ttl)
        except ReplayCacheFull:
            logger.error("Replay cache is at capacity; denying request from agent %s", peer_did)
            return ("Replay protection unavailable", 503)
        except TimeoutError:
            logger.error("Replay cache timed out while verifying agent %s", peer_did)
            return ("Replay protection unavailable", 503)
        except Exception:
            # Post-authentication, but a cache outage under real traffic would
            # otherwise amplify one fault into a traceback per request.
            _denial_signal.log_exception(
                "replay_cache", "Replay cache failure while verifying agent %s", peer_did
            )
            return ("Replay protection unavailable", 503)
        if not claimed:
            # Reaching this requires a valid signature, so it is an
            # authenticated event and safe to log at WARNING.
            logger.warning("Replay detected for agent %s", peer_did)
            return ("Replayed or expired request", 401)
        # The claim itself may have overrun the budget. Refuse rather than admit
        # a request whose freshness we can no longer vouch for; the nonce stays
        # burned, so this cannot be retried into a replay.
        if _expired(deadline):
            return ("Trust verification exceeded its time budget", 503)
        return None

    @staticmethod
    def _deny(
        reason: str,
        *,
        status: int,
        peer_did: str = "",
    ) -> tuple[VerificationResult, dict[str, Any]]:
        """Build a denial, keeping the precise reason server-side.

        The caller-visible body carries only a coarse error string. The specific
        reason distinguishes "this DID is not registered" from "your signature
        is wrong", which would let an unauthenticated prober enumerate which
        DIDs exist. It is preserved on :class:`VerificationResult` and in logs
        for operators.
        """
        error = {
            401: "Authentication failed",
            403: "Trust verification failed",
            413: "Request too large",
            500: "Trust middleware misconfigured",
            503: "Trust verification temporarily unavailable",
        }.get(status, "Trust verification failed")
        body: dict[str, Any] = {"error": error, "status": status}
        # 401 is the only pre-authentication status, so it is the only one that
        # can be used as an oracle. Everything else may safely explain itself.
        if status != 401:
            body["reason"] = reason
        _denial_signal.record(status, reason)
        return (
            VerificationResult(verified=False, authenticated=False, reason=reason,
                               peer_did=peer_did),
            body,
        )

    def response_headers(self) -> dict[str, str]:
        """Return trust headers to attach to outgoing responses."""
        if not self.identity:
            return {}
        return {
            HEADER_DID: str(self.identity.did),
            HEADER_PUBLIC_KEY: self.identity.public_key,
            HEADER_CAPABILITIES: ",".join(self.identity.capabilities),
        }


class _DenialSignal:
    """Rate-limited WARNING for denials that are otherwise only logged at DEBUG.

    Pre-authentication failures log at DEBUG so an unauthenticated caller cannot
    flood the log, but that alone leaves a default (INFO) deployment with no
    signal at all that it is under attack. This emits at most one WARNING per
    reason per interval and reports how many were suppressed, so a 401 storm is
    visible without handing an attacker a way to flood it.

    Keyed only on the middleware's own fixed reason strings — never on
    attacker-supplied data — so the map is inherently bounded.
    """

    def __init__(self, min_interval_seconds: float = 60.0) -> None:
        self._min_interval = min_interval_seconds
        self._last: dict[tuple[int, str], float] = {}
        self._suppressed: dict[tuple[int, str], int] = {}
        self._traceback_last: dict[str, float] = {}
        self._lock = threading.Lock()

    def _claim(self, store: dict[Any, float], key: Any, now: float) -> bool:
        """Return True when *key* may emit now, recording the emission."""
        last = store.get(key)
        if last is not None and now - last < self._min_interval:
            return False
        store[key] = now
        return True

    def log_exception(self, key: str, message: str, *args: Any) -> None:
        """Emit a throttled traceback for an unauthenticated failure path.

        ``logger.exception`` writes a full traceback at ERROR. Calling it once
        per request lets an unauthenticated caller — who can pick a DID that
        makes a resolver raise, or simply disconnect mid-body — drive unbounded
        log volume, which is the exact flood this class exists to prevent. The
        first occurrence in each interval keeps its traceback so the fault is
        always diagnosable; the rest degrade to DEBUG.

        Keyed on a fixed internal call-site label, never on caller input.
        """
        with self._lock:
            emit = self._claim(self._traceback_last, key, time.monotonic())
        if emit:
            logger.exception(message, *args)
        else:
            # Defer formatting to logging, exactly as the emit branch does: a
            # future call site with a mismatched format string must not raise
            # here and breach verify_request's never-raise guarantee.
            logger.debug(message + " (traceback suppressed)", *args)

    def record(self, status: int, reason: str) -> None:
        key = (status, reason)
        now = time.monotonic()
        with self._lock:
            last = self._last.get(key)
            if last is not None and now - last < self._min_interval:
                self._suppressed[key] = self._suppressed.get(key, 0) + 1
                return
            suppressed = self._suppressed.pop(key, 0)
            self._last[key] = now
        logger.warning(
            "Trust verification denied: %s (status=%d); %d further identical denials "
            "suppressed in the preceding %.0fs",
            reason, status, suppressed, self._min_interval,
        )


_denial_signal = _DenialSignal()


def _error_status(err: Mapping[str, Any]) -> int:
    status = err.get("status", 403)
    return status if isinstance(status, int) else 403


_BODY_TOO_LARGE: dict[str, Any] = {
    "error": "Request too large",
    "reason": "Request body exceeds signed-body limit",
    "status": 413,
}

_NOT_AUTHENTICATED: dict[str, Any] = {
    "error": "Authentication failed",
    "status": 401,
}

# 503: the caller's credentials were never assessed. Reporting an unreadable
# body as an auth failure would hide transport faults in auth telemetry.
_BODY_UNREADABLE: dict[str, Any] = {
    "error": "Trust verification unavailable",
    "reason": "Request body could not be read",
    "status": 503,
}

_BODY_READ_TIMEOUT: dict[str, Any] = {
    "error": "Trust verification unavailable",
    "reason": "Request body was not received within the verification time budget",
    "status": 503,
}

#: ASGI scope key set by :class:`SignedBodyLimitMiddleware` to prove the body is
#: bounded ahead of routing. The FastAPI dependency refuses to run without it.
BODY_LIMIT_SCOPE_KEY = "agentmesh.signed_body_limit"

_BODY_GUARD_MISSING: dict[str, Any] = {
    "error": "Trust middleware misconfigured",
    "reason": (
        "SignedBodyLimitMiddleware is not installed. FastAPI reads a declared request body "
        "before it solves dependencies, so without that ASGI guard an unauthenticated caller "
        "can make the server buffer an unbounded body. Use install_fastapi_trust(app, ...), "
        "or add the middleware explicitly."
    ),
    "status": 500,
}

_RAW_TARGET_UNAVAILABLE: dict[str, Any] = {
    "error": "Trust middleware misconfigured",
    "reason": (
        "This server does not expose the undecoded request target (ASGI 'raw_path', or WSGI "
        "'RAW_URI'/'REQUEST_URI'), so a signature over it cannot be checked. Run behind a "
        "server that provides it (uvicorn, hypercorn, gunicorn, uWSGI, mod_wsgi), or set "
        "TrustConfig.request_target_mode='decoded' to accept a target that cannot tell "
        "'/a%2Fb' from '/a/b'."
    ),
    "status": 500,
}


def _signed_target(cfg: TrustConfig, *, raw: str | None, decoded: str) -> str | None:
    """Pick the request target to sign, or ``None`` when the raw form is required
    but this server cannot supply it."""
    if cfg.request_target_mode == "raw":
        return raw
    return decoded


# -- Framework-specific decorators -----------------------------------------

def _read_flask_body(request: Any, limit: int) -> bytes | None:
    """Read at most ``limit`` bytes of the Flask request body.

    Returns ``None`` when the body is over the limit. The signature covers the
    body, so the body must be read before the caller is authenticated; bounding
    it here stops an unauthenticated caller from allocating arbitrary memory per
    in-flight request. Mirrors the Django integration's ``_read_request_body``.
    """
    from werkzeug.exceptions import RequestEntityTooLarge  # noqa: E402

    content_length = request.content_length
    if content_length is not None and content_length > limit:
        return None
    try:
        # Werkzeug >= 3.1 enforces this per request inside get_data(). The
        # per-request value *replaces* the app's MAX_CONTENT_LENGTH in both
        # directions, so clamp rather than assign: an app that caps bodies at
        # 1 KiB must not have that cap raised to this middleware's default.
        existing = request.max_content_length
        request.max_content_length = limit if existing is None else min(limit, existing)
    except (AttributeError, TypeError):  # pragma: no cover - Flask < 3.1
        pass
    try:
        data = request.get_data(cache=True)
    except RequestEntityTooLarge:
        return None
    return data if len(data) <= limit else None


async def _read_starlette_body(request: Any, limit: int, timeout_seconds: float) -> bytes | None:
    """Read at most ``limit`` bytes of the Starlette/FastAPI request body.

    ``Request.body()`` buffers without bound and waits without bound, so the
    body is streamed against both a size budget and the caller's time budget,
    then cached on the request so the endpoint can still read it normally.

    Returns ``None`` when the body exceeds ``limit``. Raises ``TimeoutError``
    when a client stops sending, so a stalled upload cannot pin the verifier
    open indefinitely.

    This is defence in depth, not a complete bound. FastAPI reads the body
    inside its route handler *before* dependencies are solved, so for any route
    that declares a body parameter the request is already buffered by the time
    a dependency runs. :class:`SignedBodyLimitMiddleware` bounds those routes;
    it runs ahead of routing, which is the only layer that can.
    """
    raw_length = request.headers.get("content-length")
    if raw_length is not None:
        try:
            if int(raw_length) > limit:
                return None
        except ValueError:
            return None

    cached = getattr(request, "_body", None)
    if cached is not None:
        return cached if len(cached) <= limit else None

    # Imported here, not at module scope: this module must stay importable for
    # Flask- and Django-only deployments, which have no ASGI stack. Starlette
    # depends on anyio, so on this code path it is always present.
    import anyio  # noqa: PLC0415

    buffer = bytearray()
    with anyio.fail_after(timeout_seconds):
        async for chunk in request.stream():
            buffer.extend(chunk)
            if len(buffer) > limit:
                return None
    body = bytes(buffer)
    # Prime Starlette's own cache so downstream `await request.body()` works.
    request._body = body
    return body


class _BodyTooLarge(Exception):
    """Internal signal raised from the bounded ASGI receive channel."""


class SignedBodyLimitMiddleware:
    """Pure-ASGI guard that bounds the request body *before* routing.

    ``fastapi_trust_required`` cannot bound memory on its own: FastAPI reads the
    body in ``get_request_handler`` before it solves dependencies, so on any
    route that declares a Pydantic or form body the request has already been
    buffered in full by the time the trust dependency runs. This middleware runs
    ahead of the router, which is the only layer where the bound is enforceable.

    Install it alongside the trust dependency::

        app.add_middleware(SignedBodyLimitMiddleware, max_body_bytes=config.max_signed_body_bytes)

    It is framework-agnostic ASGI, so it also works with plain Starlette.
    """

    def __init__(self, app: Any, max_body_bytes: int = _DEFAULT_MAX_SIGNED_BODY_BYTES) -> None:
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        limit = self.max_body_bytes
        # Proof-of-installation for the trust dependency downstream. It runs
        # after FastAPI has already buffered any declared body, so it can only
        # verify that this guard ran, not impose the bound itself.
        scope[BODY_LIMIT_SCOPE_KEY] = limit
        if self._declared_length_exceeds(scope, limit):
            await self._reject(send)
            return

        received = 0
        response_started = False

        async def bounded_receive() -> Any:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Any) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, bounded_receive, tracking_send)
        except _BodyTooLarge:
            # Only safe to write a response if the app has not begun one.
            if not response_started:
                await self._reject(send)

    @staticmethod
    def _declared_length_exceeds(scope: Any, limit: int) -> bool:
        for name, value in scope.get("headers") or ():
            if name.lower() != b"content-length":
                continue
            try:
                return int(value) > limit
            except ValueError:
                # A malformed Content-Length is refused rather than trusted.
                return True
        return False

    @staticmethod
    async def _reject(send: Any) -> None:
        body = json.dumps(_BODY_TOO_LARGE).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})


def _flask_verify(
    middleware: TrustMiddleware,
    config: TrustConfig | None,
    request: Any,
) -> tuple[VerificationResult | None, dict[str, Any] | None]:
    """Verify a Flask request, never raising.

    ``TrustMiddleware.verify_request`` guarantees it never raises, but the body
    read runs *before* it and is not covered by that guarantee (a client
    disconnect mid-body raises ``ClientDisconnected``). The decorators are what
    users actually deploy, so the guarantee is extended to cover them here.
    """
    cfg = config or middleware.config
    try:
        body = _read_flask_body(request, cfg.max_signed_body_bytes)
    except Exception:
        _denial_signal.log_exception(
            "flask_body_read", "Failed to read Flask request body; denying request"
        )
        return None, dict(_BODY_UNREADABLE)
    if body is None:
        return None, dict(_BODY_TOO_LARGE)
    # latin-1 never fails and round-trips arbitrary bytes; the Starlette path
    # decodes the same way so both frameworks sign identical bytes.
    query = request.query_string.decode("latin-1")
    target = _signed_target(
        cfg,
        raw=wsgi_raw_target(request.environ),
        decoded=decoded_target(request.path, query),
    )
    if target is None:
        return None, dict(_RAW_TARGET_UNAVAILABLE)
    return middleware.verify_request(
        dict(request.headers),
        config,
        method=request.method,
        request_target=target,
        body=body,
    )


def flask_trust_required(
    middleware: TrustMiddleware,
    config: TrustConfig | None = None,
) -> Callable:
    """Flask decorator that admits only cryptographically authenticated callers.

    Requests that fail verification, and anonymous requests admitted by
    ``permissive_mode``, are both rejected with 401. Use
    :func:`flask_trust_optional` if anonymous callers should reach the view.
    """
    from flask import g, jsonify, request  # noqa: E402

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result, err = _flask_verify(middleware, config, request)
            if err:
                return jsonify(err), _error_status(err)
            # Fail closed rather than assert: assertions are stripped under -O.
            if result is None or not result.authenticated:
                return jsonify(dict(_NOT_AUTHENTICATED)), 401
            g.trust_result = result
            g.peer_did = result.peer_did
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def flask_trust_optional(
    middleware: TrustMiddleware,
    config: TrustConfig | None = None,
) -> Callable:
    """Flask decorator that allows anonymous callers through under permissive mode.

    The view MUST branch on ``g.trust_result.authenticated`` before trusting
    ``g.peer_did``: it is an empty string for anonymous callers. Requests that
    present a DID are still fully verified — permissive mode never weakens
    verification, it only allows the complete absence of credentials.
    """
    from flask import g, jsonify, request  # noqa: E402

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result, err = _flask_verify(middleware, config, request)
            if err:
                return jsonify(err), _error_status(err)
            g.trust_result = result
            g.peer_did = result.peer_did if result else ""
            return fn(*args, **kwargs)
        return wrapper
    return decorator


async def _fastapi_verify(
    middleware: TrustMiddleware,
    config: TrustConfig | None,
    request: Any,
) -> tuple[VerificationResult | None, dict[str, Any] | None]:
    """Verify a Starlette/FastAPI request, never raising.

    See :func:`_flask_verify` — the body read is outside ``verify_request``'s
    never-raise guarantee (``ClientDisconnect``, ``RuntimeError`` on an
    already-consumed stream), so it is wrapped here.
    """
    cfg = config or middleware.config
    # FastAPI reads a declared body before it solves dependencies, so by the
    # time this runs the bound must already exist upstream. Refuse rather than
    # pretend to enforce a limit we cannot enforce here.
    if request.scope.get(BODY_LIMIT_SCOPE_KEY) is None:
        return None, dict(_BODY_GUARD_MISSING)
    try:
        body = await _read_starlette_body(
            request, cfg.max_signed_body_bytes, cfg.io_timeout_seconds
        )
    except TimeoutError:
        logger.warning("ASGI request body was not received within the verification budget")
        return None, dict(_BODY_READ_TIMEOUT)
    except Exception:
        _denial_signal.log_exception(
            "asgi_body_read", "Failed to read ASGI request body; denying request"
        )
        return None, dict(_BODY_UNREADABLE)
    if body is None:
        return None, dict(_BODY_TOO_LARGE)
    # Read the raw scope rather than ``request.url``: constructing Starlette's
    # URL decodes query_string as strict UTF-8, so a non-UTF-8 query byte raises
    # there before we ever see it. latin-1 never fails, round-trips arbitrary
    # bytes, and matches how the Flask path decodes the same field.
    query = request.scope.get("query_string", b"").decode("latin-1")
    path = request.scope.get("path", "")
    target = _signed_target(
        cfg,
        raw=asgi_raw_target(request.scope),
        decoded=decoded_target(path, query),
    )
    if target is None:
        return None, dict(_RAW_TARGET_UNAVAILABLE)
    return middleware.verify_request(
        dict(request.headers),
        config,
        method=request.method,
        request_target=target,
        body=body,
    )


def _with_resolved_request_annotation(dependency: Callable, request_cls: type) -> Callable:
    """Bind ``request``'s annotation to the real class before FastAPI reads it.

    This module uses ``from __future__ import annotations``, so the dependency's
    ``request: Request`` annotation is stored as the *string* ``"Request"``, and
    ``fastapi`` is imported lazily inside the factory so this module stays
    importable without it. FastAPI resolves string annotations against the
    function's module globals, where ``Request`` therefore does not exist — it
    falls back to treating ``request`` as a query parameter and every call
    returns ``422``. Substituting the resolved class keeps both properties.
    """
    dependency.__annotations__["request"] = request_cls
    return dependency


def fastapi_trust_required(
    middleware: TrustMiddleware,
    config: TrustConfig | None = None,
) -> Callable:
    """FastAPI dependency that admits only cryptographically authenticated callers.

    Requests that fail verification, and anonymous requests admitted by
    ``permissive_mode``, are both rejected with 401. Use
    :func:`fastapi_trust_optional` if anonymous callers should reach the route.
    """
    from fastapi import Request  # noqa: E402

    async def dependency(request: Request) -> VerificationResult:
        result, err = await _fastapi_verify(middleware, config, request)
        if err:
            raise _fastapi_http_exc(_error_status(err), err)
        # Fail closed rather than assert: assertions are stripped under -O.
        if result is None or not result.authenticated:
            raise _fastapi_http_exc(401, dict(_NOT_AUTHENTICATED))
        return result

    return _with_resolved_request_annotation(dependency, Request)


def fastapi_trust_optional(
    middleware: TrustMiddleware,
    config: TrustConfig | None = None,
) -> Callable:
    """FastAPI dependency that allows anonymous callers under permissive mode.

    The route MUST branch on ``result.authenticated`` before trusting
    ``result.peer_did``: it is an empty string for anonymous callers. Requests
    that present a DID are still fully verified.
    """
    from fastapi import Request  # noqa: E402

    async def dependency(request: Request) -> VerificationResult | None:
        result, err = await _fastapi_verify(middleware, config, request)
        if err:
            raise _fastapi_http_exc(_error_status(err), err)
        return result

    return _with_resolved_request_annotation(dependency, Request)


def install_fastapi_trust(
    app: Any,
    middleware: TrustMiddleware,
    config: TrustConfig | None = None,
    *,
    optional: bool = False,
) -> Callable:
    """Install the body guard and return the matching trust dependency.

    The guard and the dependency are two halves of one control: FastAPI reads a
    declared request body *before* it solves dependencies, so the dependency
    alone cannot bound memory, and the guard alone does not authenticate. Wiring
    them separately makes it possible to ship half of it, so this installs both::

        trust = install_fastapi_trust(app, middleware, config)

        @app.post("/task")
        async def run(payload: Task, result: VerificationResult = Depends(trust)):
            ...

    Set ``optional=True`` for the permissive-mode dependency, which lets
    anonymous callers reach the route; the route must then branch on
    ``result.authenticated`` before trusting ``result.peer_did``.

    Installing twice is harmless — the guard is idempotent and the second
    instance simply re-asserts the same bound — but the second call's
    ``max_signed_body_bytes`` wins, because ASGI middleware is applied
    outermost-last.
    """
    cfg = config or middleware.config
    app.add_middleware(SignedBodyLimitMiddleware, max_body_bytes=cfg.max_signed_body_bytes)
    if optional:
        return fastapi_trust_optional(middleware, config)
    return fastapi_trust_required(middleware, config)


def _fastapi_http_exc(status: int, detail: Any) -> Exception:
    from fastapi import HTTPException  # noqa: E402
    return HTTPException(status_code=status, detail=detail)


__all__ = [
    "BODY_LIMIT_SCOPE_KEY",
    "HEADER_CAPABILITIES",
    "HEADER_DID",
    "HEADER_NONCE",
    "HEADER_PUBLIC_KEY",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP",
    "PeerCredential",
    "PeerResolver",
    "SignedBodyLimitMiddleware",
    "TrustConfig",
    "TrustMiddleware",
    "VerificationResult",
    "fastapi_trust_optional",
    "fastapi_trust_required",
    "flask_trust_optional",
    "flask_trust_required",
    "install_fastapi_trust",
    "registry_resolver",
]
