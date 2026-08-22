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
import hashlib
import logging
import math
from collections.abc import Callable
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

from .request_auth import build_request_signature_payload

logger = logging.getLogger(__name__)

# Marker attribute set by @trust_exempt decorator
_TRUST_EXEMPT_ATTR = "_agentmesh_trust_exempt"
# Marker attribute set by @trust_required decorator (per-view min score)
_TRUST_REQUIRED_ATTR = "_agentmesh_min_trust_score"


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
    - ``AGENTMESH_EXEMPT_PATHS`` — list of URL path prefixes that skip
      trust verification (default ``[]``)

    On success the middleware sets ``request.agent_did`` and
    ``request.agent_trust_score`` for downstream views.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        if not str(_get_setting("AGENTMESH_AUDIENCE", "")).strip():
            raise ImproperlyConfigured("AGENTMESH_AUDIENCE must identify this service")
        if self._replay_window_seconds() <= 0:
            raise ImproperlyConfigured("AGENTMESH_REPLAY_WINDOW_SECONDS must be positive")
        if self._max_signed_body_bytes() <= 0:
            raise ImproperlyConfigured("AGENTMESH_MAX_SIGNED_BODY_BYTES must be positive")
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
            # @trust_exempt — skip verification entirely
            request.agent_did = agent_did  # type: ignore[attr-defined]
            request.agent_trust_score = None  # type: ignore[attr-defined]
            return self.get_response(request)

        per_view_score: int | None = None
        if view_func is not None:
            per_view_score = getattr(view_func, _TRUST_REQUIRED_ATTR, None)

        min_score = per_view_score if per_view_score is not None else self._min_trust_score()

        # Derive trust score — simple heuristic:
        # agents that provide a valid DID get a baseline score; agents that
        # also provide a signature get a higher score.
        trust_score = self._evaluate_trust(
            request,
            agent_did,
            agent_sig,
            agent_timestamp,
            agent_nonce,
        )

        if trust_score < min_score:
            logger.warning(
                "Trust verification failed for %s: score %d < required %d",
                agent_did,
                trust_score,
                min_score,
            )
            return JsonResponse(
                {"error": "Trust verification failed"},
                status=403,
            )

        # Attach trust info to request for downstream views
        request.agent_did = agent_did  # type: ignore[attr-defined]
        request.agent_trust_score = trust_score  # type: ignore[attr-defined]
        return self.get_response(request)

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
    ) -> int:
        """Return trust score for the given agent.

        Verifies an Ed25519 signature over a versioned envelope binding the
        agent identity, audience, freshness values, and HTTP request.

        The verifying public key is looked up via the Django setting
        ``AGENTMESH_AGENT_KEYS``, a dict mapping DID → Ed25519PublicKey.
        Agents not in the registry or with invalid signatures receive a
        score of 0.
        """
        if not all((agent_did, agent_sig, agent_timestamp, agent_nonce)):
            return 0

        audience = str(_get_setting("AGENTMESH_AUDIENCE", "")).strip()
        if not audience:
            logger.error("AGENTMESH_AUDIENCE is required for request verification")
            return 0

        replay_window = self._replay_window_seconds()
        if replay_window <= 0 or len(agent_timestamp) > 64:
            return 0
        timestamp_value = (
            agent_timestamp[:-1] + "+00:00"
            if agent_timestamp.endswith("Z")
            else agent_timestamp
        )
        try:
            timestamp = datetime.fromisoformat(timestamp_value)
        except ValueError:
            return 0
        if timestamp.tzinfo is None:
            return 0
        if abs((_utcnow() - timestamp).total_seconds()) > replay_window:
            return 0

        if len(agent_nonce) > 128:
            return 0
        try:
            padded_nonce = agent_nonce + "=" * (-len(agent_nonce) % 4)
            nonce_bytes = base64.b64decode(padded_nonce, altchars=b"-_", validate=True)
        except (ValueError, binascii.Error):
            return 0
        if not 16 <= len(nonce_bytes) <= 64:
            return 0

        agent_keys: dict = _get_setting("AGENTMESH_AGENT_KEYS", {})
        public_key = agent_keys.get(agent_did)
        if public_key is None:
            logger.warning("No public key registered for agent %s", agent_did)
            return 0

        try:
            sig_bytes = base64.b64decode(agent_sig, validate=True)
            if len(sig_bytes) != 64:
                return 0
            query_string = request.META.get("QUERY_STRING", "")
            request_target = request.path
            if query_string:
                request_target = f"{request_target}?{query_string}"
            body = self._read_request_body(request)
            if body is None:
                return 0
            payload = build_request_signature_payload(
                agent_did=agent_did,
                audience=audience,
                timestamp=agent_timestamp,
                nonce=agent_nonce,
                method=request.method,
                request_target=request_target,
                body=body,
                content_type=request.META.get("CONTENT_TYPE", ""),
            )
            public_key.verify(sig_bytes, payload)
        except Exception:
            logger.warning("Signature verification failed for agent %s", agent_did)
            return 0

        now = _utcnow()
        age_seconds = abs((now - timestamp).total_seconds())
        if age_seconds > replay_window:
            return 0

        # Retain the nonce until the signed timestamp's complete validity
        # interval ends, including any accepted future clock skew.
        replay_timeout = max(
            1,
            math.ceil((timestamp - now).total_seconds() + replay_window),
        )

        replay_key_material = agent_did.encode("utf-8") + b"\0" + nonce_bytes
        replay_key = "agentmesh:request-nonce:" + hashlib.sha256(replay_key_material).hexdigest()
        try:
            if not self._replay_cache.add(replay_key, True, timeout=replay_timeout):
                logger.warning("Replay detected for agent %s", agent_did)
                return 0
        except Exception:
            logger.exception("Replay cache failure while verifying agent %s", agent_did)
            return 0
        if abs((_utcnow() - timestamp).total_seconds()) > replay_window:
            return 0
        return 750

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
