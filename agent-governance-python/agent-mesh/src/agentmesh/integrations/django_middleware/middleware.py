# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentTrustMiddleware for Django
===============================

Validates incoming HTTP requests against AgentMesh trust headers.
Configurable via Django settings; returns 403 JSON on trust failure.
"""

from __future__ import annotations

import base64
import binascii
import logging
import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from typing import Any

from django.conf import settings
from django.core.cache import InvalidCacheBackendError, caches
from django.core.cache.backends.locmem import LocMemCache
from django.core.cache.backends.memcached import BaseMemcachedCache
from django.core.cache.backends.redis import RedisCache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse, JsonResponse

from agentmesh.integrations.request_auth import (
    RequestTargetMode,
    decoded_target,
    select_signed_headers,
    wsgi_raw_target,
)

from .request_auth import build_request_signature_payload, replay_key

logger = logging.getLogger(__name__)

# Marker attribute set by @trust_exempt decorator
_TRUST_EXEMPT_ATTR = "_agentmesh_trust_exempt"
# Marker attribute set by @trust_required decorator (per-view min score)
_TRUST_REQUIRED_ATTR = "_agentmesh_min_trust_score"

#: Score awarded to a caller whose Ed25519 signature verified over the full
#: envelope. Unauthenticated callers never reach a score comparison at all.
_VERIFIED_TRUST_SCORE = 750


@dataclass(frozen=True, slots=True)
class TrustEvaluation:
    """Outcome of verifying one request.

    ``authenticated`` is deliberately separate from ``score``. A score alone
    cannot express "this caller proved nothing": zero is a perfectly valid
    threshold, so a policy of ``@trust_required(min_score=0)`` would admit an
    unauthenticated caller if the gate were a numeric comparison only. Callers
    must check :attr:`authenticated` first.
    """

    authenticated: bool
    score: int
    reason: str
    status: int = 403

    @classmethod
    def denied(cls, reason: str, status: int = 403) -> TrustEvaluation:
        return cls(authenticated=False, score=0, reason=reason, status=status)

    @classmethod
    def verified(cls) -> TrustEvaluation:
        return cls(
            authenticated=True,
            score=_VERIFIED_TRUST_SCORE,
            reason="",
            status=200,
        )


def _get_setting(name: str, default: Any) -> Any:
    """Read a Django setting with a fallback default."""
    return getattr(settings, name, default)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AgentTrustMiddleware:
    """Django middleware that enforces AgentMesh trust verification.

    Configuration via Django settings:

    - ``AGENTMESH_MIN_TRUST_SCORE`` — minimum trust score (0-1000, default 500)
    - ``AGENTMESH_DID_HEADER`` — request header carrying the agent DID
      (default ``"X-Agent-DID"``)
    - ``AGENTMESH_SIGNATURE_HEADER`` — request header carrying the agent
      signature (default ``"X-Agent-Signature"``)
        - ``AGENTMESH_TIMESTAMP_HEADER`` — request header carrying the signed
            ISO-8601 timestamp (default ``"X-Agent-Timestamp"``)
        - ``AGENTMESH_NONCE_HEADER`` — request header carrying a unique, random
            base64url nonce (default ``"X-Agent-Nonce"``)
        - ``AGENTMESH_AUDIENCE`` — required service identifier covered by the
            request signature
        - ``AGENTMESH_REPLAY_CACHE_ALIAS`` — required Django cache alias used for
            atomic replay detection
        - ``AGENTMESH_REPLAY_WINDOW_SECONDS`` — accepted timestamp window and
            replay-cache lifetime (default 300)
        - ``AGENTMESH_MAX_SIGNED_BODY_BYTES`` — maximum request body size covered
            by signature verification (default 2.5 MiB)
        - ``AGENTMESH_REQUEST_TARGET_MODE`` — ``"raw"`` (default) verifies the
            signature over the undecoded request target, which requires a WSGI
            server that sets ``RAW_URI`` or ``REQUEST_URI`` (gunicorn, uWSGI,
            mod_wsgi). Django's ``runserver`` does not, so development setups
            must either accept a 500 or set ``"decoded"``, which signs the
            percent-decoded path and therefore cannot distinguish ``/a%2Fb``
            from ``/a/b``.
        - ``AGENTMESH_SIGNED_HEADERS`` — additional headers covered by the
            signature (default ``("content-type",)``)
    - ``AGENTMESH_EXEMPT_PATHS`` — list of URL path prefixes that skip
      trust verification (default ``[]``)

    On success the middleware sets ``request.agent_did``,
    ``request.agent_trust_score`` and ``request.agent_authenticated`` for
    downstream views. On every other path — exempt views, exempt paths, and
    denials — it sets ``agent_did`` and ``agent_trust_score`` to ``None`` and
    ``agent_authenticated`` to ``False``. Views must check
    ``request.agent_authenticated`` before acting on ``request.agent_did``.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        if not str(_get_setting("AGENTMESH_AUDIENCE", "")).strip():
            raise ImproperlyConfigured("AGENTMESH_AUDIENCE must identify this service")
        if self._replay_window_seconds() <= 0:
            raise ImproperlyConfigured("AGENTMESH_REPLAY_WINDOW_SECONDS must be positive")
        if self._max_signed_body_bytes() <= 0:
            raise ImproperlyConfigured("AGENTMESH_MAX_SIGNED_BODY_BYTES must be positive")
        # Raises on an invalid value; better at startup than per request.
        self._request_target_mode()
        cache_alias = str(_get_setting("AGENTMESH_REPLAY_CACHE_ALIAS", "")).strip()
        if not cache_alias:
            raise ImproperlyConfigured(
                "AGENTMESH_REPLAY_CACHE_ALIAS must name a shared Django cache backend"
            )
        try:
            self._replay_cache = caches[cache_alias]
        except InvalidCacheBackendError as exc:
            raise ImproperlyConfigured(
                f"AGENTMESH_REPLAY_CACHE_ALIAS references an invalid cache: {cache_alias}"
            ) from exc
        if isinstance(self._replay_cache, LocMemCache):
            if _get_setting("AGENTMESH_ALLOW_LOCAL_REPLAY_CACHE", False) is not True:
                raise ImproperlyConfigured(
                    "The local-memory cache cannot prevent replay across workers; configure a "
                    "shared AGENTMESH_REPLAY_CACHE_ALIAS or explicitly set "
                    "AGENTMESH_ALLOW_LOCAL_REPLAY_CACHE=True for development"
                )
        elif not isinstance(self._replay_cache, (RedisCache, BaseMemcachedCache)):
            raise ImproperlyConfigured(
                "AGENTMESH_REPLAY_CACHE_ALIAS must use Django's RedisCache or a shared memcached "
                "backend with atomic add() semantics"
            )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _min_trust_score() -> int:
        return int(_get_setting("AGENTMESH_MIN_TRUST_SCORE", 500))

    @staticmethod
    def _did_header() -> str:
        return str(_get_setting("AGENTMESH_DID_HEADER", "X-Agent-DID"))

    @staticmethod
    def _signature_header() -> str:
        return str(_get_setting("AGENTMESH_SIGNATURE_HEADER", "X-Agent-Signature"))

    @staticmethod
    def _timestamp_header() -> str:
        return str(_get_setting("AGENTMESH_TIMESTAMP_HEADER", "X-Agent-Timestamp"))

    @staticmethod
    def _nonce_header() -> str:
        return str(_get_setting("AGENTMESH_NONCE_HEADER", "X-Agent-Nonce"))

    @staticmethod
    def _replay_window_seconds() -> int:
        return int(_get_setting("AGENTMESH_REPLAY_WINDOW_SECONDS", 300))

    @staticmethod
    def _max_signed_body_bytes() -> int:
        return int(_get_setting("AGENTMESH_MAX_SIGNED_BODY_BYTES", 2_621_440))

    @staticmethod
    def _request_target_mode() -> RequestTargetMode:
        mode = str(_get_setting("AGENTMESH_REQUEST_TARGET_MODE", "raw"))
        if mode not in ("raw", "decoded"):
            raise ImproperlyConfigured(
                f"AGENTMESH_REQUEST_TARGET_MODE must be 'raw' or 'decoded', not {mode!r}"
            )
        return mode  # type: ignore[return-value]

    @staticmethod
    def _signed_header_names() -> tuple[str, ...]:
        """Headers covered by the signature, beyond the always-covered fields.

        Server-chosen, never client-declared: a caller who could pick which
        headers are signed could simply decline to sign the ones that matter.
        """
        names = _get_setting("AGENTMESH_SIGNED_HEADERS", ("content-type",))
        return tuple(str(name).strip().lower() for name in names if str(name).strip())

    @staticmethod
    def _exempt_paths() -> list[str]:
        return list(_get_setting("AGENTMESH_EXEMPT_PATHS", []))

    @staticmethod
    def _trusted_proxies() -> list[str]:
        """Return list of trusted proxy IPs/CIDRs.

        When set, DID headers are only trusted from these source IPs.
        Empty list (default) means trust headers from any source — set
        this in production to prevent header spoofing.
        """
        return list(_get_setting("AGENTMESH_TRUSTED_PROXIES", []))

    # ------------------------------------------------------------------
    # request processing
    # ------------------------------------------------------------------

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Check path-based exemptions first
        for prefix in self._exempt_paths():
            if request.path.startswith(prefix):
                # Nothing was verified, so nothing is asserted about the caller.
                self._mark_unverified(request)
                return self.get_response(request)

        # V17: Validate request comes from a trusted proxy when configured
        trusted_proxies = self._trusted_proxies()
        if trusted_proxies:
            remote_addr = request.META.get("REMOTE_ADDR", "")
            if remote_addr not in trusted_proxies:
                logger.warning(
                    "Rejecting agent DID header from untrusted source: %s",
                    remote_addr,
                )
                return JsonResponse(
                    {"error": "Untrusted proxy", "detail": "Request source is not in AGENTMESH_TRUSTED_PROXIES."},
                    status=403,
                )

        did_header = self._did_header()
        sig_header = self._signature_header()
        timestamp_header = self._timestamp_header()
        nonce_header = self._nonce_header()

        # Django normalises headers to META keys: HTTP_X_AGENT_DID
        agent_did: str = request.META.get(
            "HTTP_" + did_header.upper().replace("-", "_"), ""
        )
        agent_sig: str = request.META.get(
            "HTTP_" + sig_header.upper().replace("-", "_"), ""
        )
        agent_timestamp: str = request.META.get(
            "HTTP_" + timestamp_header.upper().replace("-", "_"), ""
        )
        agent_nonce: str = request.META.get(
            "HTTP_" + nonce_header.upper().replace("-", "_"), ""
        )

        if not agent_did:
            self._mark_unverified(request)
            return JsonResponse(
                {
                    "error": "Missing agent DID",
                    "detail": f"The {did_header} header is required.",
                },
                status=403,
            )

        # Resolve per-view override via @trust_required decorator
        view_func = self._resolve_view_func(request)
        if view_func is not None and getattr(view_func, _TRUST_EXEMPT_ATTR, False):
            # @trust_exempt — skip verification entirely. The DID header is
            # unverified attacker-controlled input on this path, so it is not
            # published to the view; doing so would let anyone impersonate any
            # agent simply by hitting an exempt endpoint.
            self._mark_unverified(request)
            return self.get_response(request)

        per_view_score: int | None = None
        if view_func is not None:
            per_view_score = getattr(view_func, _TRUST_REQUIRED_ATTR, None)

        min_score = per_view_score if per_view_score is not None else self._min_trust_score()

        evaluation = self._evaluate_trust(
            request,
            agent_did,
            agent_sig,
            agent_timestamp,
            agent_nonce,
        )

        # Authentication is checked before the score, and never as a score.
        # A threshold of 0 is a legitimate policy ("any authenticated agent");
        # it must not become "any caller who typed a DID header".
        if not evaluation.authenticated:
            logger.warning(
                "Trust verification failed for %s: %s", agent_did, evaluation.reason
            )
            self._mark_unverified(request)
            return JsonResponse(
                {"error": "Trust verification failed", "detail": evaluation.reason},
                status=evaluation.status,
            )

        if evaluation.score < min_score:
            logger.warning(
                "Trust verification failed for %s: score %d < required %d",
                agent_did,
                evaluation.score,
                min_score,
            )
            self._mark_unverified(request)
            return JsonResponse(
                {"error": "Trust verification failed"},
                status=403,
            )

        # Attach trust info to request for downstream views
        request.agent_did = agent_did  # type: ignore[attr-defined]
        request.agent_trust_score = evaluation.score  # type: ignore[attr-defined]
        request.agent_authenticated = True  # type: ignore[attr-defined]
        return self.get_response(request)

    @staticmethod
    def _mark_unverified(request: HttpRequest) -> None:
        """Publish an explicitly unauthenticated identity to downstream code.

        The attributes are always set, never left absent, so a view reading
        ``request.agent_did`` gets ``None`` rather than an ``AttributeError``
        or — worse — a value carried over from an unverified header.
        """
        request.agent_did = None  # type: ignore[attr-defined]
        request.agent_trust_score = None  # type: ignore[attr-defined]
        request.agent_authenticated = False  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _evaluate_trust(
        self,
        request: HttpRequest,
        agent_did: str,
        agent_sig: str,
        agent_timestamp: str,
        agent_nonce: str,
    ) -> TrustEvaluation:
        """Verify the request and report whether the caller is authenticated.

        Verifies an Ed25519 signature over a versioned envelope binding the
        agent identity, audience, freshness values, and HTTP request.

        The verifying public key is looked up via the Django setting
        ``AGENTMESH_AGENT_KEYS``, a dict mapping DID → Ed25519PublicKey.
        Every failure returns an unauthenticated result; only a verified
        signature and a successfully claimed nonce produce ``authenticated``.
        """
        if not all((agent_did, agent_sig, agent_timestamp, agent_nonce)):
            return TrustEvaluation.denied("Incomplete trust headers")

        audience = str(_get_setting("AGENTMESH_AUDIENCE", "")).strip()
        if not audience:
            logger.error("AGENTMESH_AUDIENCE is required for request verification")
            return TrustEvaluation.denied("Trust verification is misconfigured", status=500)

        target_mode = self._request_target_mode()
        replay_window = self._replay_window_seconds()
        if replay_window <= 0:
            return TrustEvaluation.denied("Trust verification is misconfigured", status=500)
        if len(agent_timestamp) > 64:
            return TrustEvaluation.denied("Malformed timestamp")
        timestamp_value = (
            agent_timestamp[:-1] + "+00:00"
            if agent_timestamp.endswith("Z")
            else agent_timestamp
        )
        try:
            timestamp = datetime.fromisoformat(timestamp_value)
        except ValueError:
            return TrustEvaluation.denied("Malformed timestamp")
        if timestamp.tzinfo is None:
            return TrustEvaluation.denied("Timestamp is missing a timezone")
        if abs((_utcnow() - timestamp).total_seconds()) > replay_window:
            return TrustEvaluation.denied("Timestamp is outside the replay window")

        if len(agent_nonce) > 128:
            return TrustEvaluation.denied("Malformed nonce")
        try:
            padded_nonce = agent_nonce + "=" * (-len(agent_nonce) % 4)
            nonce_bytes = base64.b64decode(padded_nonce, altchars=b"-_", validate=True)
        except (ValueError, binascii.Error):
            return TrustEvaluation.denied("Malformed nonce")
        if not 16 <= len(nonce_bytes) <= 64:
            return TrustEvaluation.denied("Malformed nonce")

        agent_keys: dict = _get_setting("AGENTMESH_AGENT_KEYS", {})
        public_key = agent_keys.get(agent_did)
        if public_key is None:
            logger.warning("No public key registered for agent %s", agent_did)
            return TrustEvaluation.denied("Unknown agent")

        request_target = self._signed_target(request, target_mode)
        if request_target is None:
            logger.error(
                "This WSGI server does not expose the undecoded request target "
                "(neither RAW_URI nor REQUEST_URI is set in META), so a signature over it "
                "cannot be checked. Run behind gunicorn, uWSGI, or mod_wsgi, or set "
                "AGENTMESH_REQUEST_TARGET_MODE='decoded'."
            )
            return TrustEvaluation.denied("Trust verification is misconfigured", status=500)

        body = self._read_request_body(request)
        if body is None:
            return TrustEvaluation.denied("Request body could not be verified")

        try:
            sig_bytes = base64.b64decode(agent_sig, validate=True)
            if len(sig_bytes) != 64:
                return TrustEvaluation.denied("Malformed signature")
            payload = build_request_signature_payload(
                agent_did=agent_did,
                audience=audience,
                timestamp=agent_timestamp,
                nonce=agent_nonce,
                method=request.method,
                request_target=request_target,
                target_mode=target_mode,
                body=body,
                signed_headers=select_signed_headers(
                    self._signed_header_names(),
                    lambda name: request.headers.get(name),
                ),
            )
            public_key.verify(sig_bytes, payload)
        except Exception:
            logger.warning("Signature verification failed for agent %s", agent_did)
            return TrustEvaluation.denied("Signature verification failed")

        now = _utcnow()
        age_seconds = abs((now - timestamp).total_seconds())
        if age_seconds > replay_window:
            return TrustEvaluation.denied("Timestamp is outside the replay window")

        # Retain the nonce until the signed timestamp's complete validity
        # interval ends, including any accepted future clock skew.
        replay_timeout = max(
            1,
            math.ceil((timestamp - now).total_seconds() + replay_window),
        )

        replay_cache_key = replay_key(agent_did, audience, nonce_bytes)
        try:
            if not self._replay_cache.add(replay_cache_key, True, timeout=replay_timeout):
                logger.warning("Replay detected for agent %s", agent_did)
                return TrustEvaluation.denied("Replayed or expired request")
        except Exception:
            logger.exception("Replay cache failure while verifying agent %s", agent_did)
            # The caller did nothing wrong; a cache outage is our fault, and
            # recording it as an attack would corrupt the audit trail.
            return TrustEvaluation.denied("Replay protection unavailable", status=503)
        if abs((_utcnow() - timestamp).total_seconds()) > replay_window:
            return TrustEvaluation.denied("Timestamp is outside the replay window")
        return TrustEvaluation.verified()

    @staticmethod
    def _signed_target(request: HttpRequest, mode: RequestTargetMode) -> str | None:
        """Return the request target to verify, or ``None`` when the raw form is
        required but this server does not provide it."""
        if mode == "raw":
            return wsgi_raw_target(request.META)
        return decoded_target(request.path, request.META.get("QUERY_STRING", ""))

    def _read_request_body(self, request: HttpRequest) -> bytes | None:
        max_body_bytes = self._max_signed_body_bytes()
        content_length = request.META.get("CONTENT_LENGTH")
        if content_length:
            try:
                if int(content_length) > max_body_bytes:
                    return None
            except (TypeError, ValueError):
                return None

        if hasattr(request, "_body"):
            body = request.body
            return body if len(body) <= max_body_bytes else None
        if request._read_started:
            return None

        body = request.read(max_body_bytes + 1)
        request._stream.close()
        if len(body) > max_body_bytes:
            return None
        request._body = body
        request._stream = BytesIO(body)
        return body

    @staticmethod
    def _resolve_view_func(request: HttpRequest) -> Callable[..., Any] | None:
        """Resolve the view function for the current request, if possible."""
        from django.urls import Resolver404, resolve

        try:
            match = resolve(request.path)
            return match.func  # type: ignore[return-value]
        except Resolver404:
            return None
