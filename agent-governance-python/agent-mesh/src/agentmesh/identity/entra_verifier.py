# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Entra-signed JWT verifier for the AgentMesh relay.

Opt-in: when ``AGENTMESH_ENTRA_AUDIENCE`` is set in the relay's
environment, the relay's ``connect`` frame handler delegates the
``token`` field to :func:`verify_token`, which validates the JWT
against Microsoft Entra's published JWKS, pins the configured tenant
and audience, and returns the claims dict on success (raising
``EntraTokenError`` on any failure).

When ``AGENTMESH_ENTRA_AUDIENCE`` is unset, this module is never
imported and the relay falls back to its existing legacy behavior
(``AGENTMESH_RELAY_TOKEN`` shared-secret compare, or fully open).
Backward compatibility is the default.

Implementation notes
--------------------
* JWKS fetched once on first use and cached in-process for
  ``AGENTMESH_ENTRA_JWKS_TTL_SECS`` (default 3600s = 1 h). On expiry
  the next verifier call refetches; failures during refetch fall back
  to the last successful cache to avoid availability cliffs.
* Refetch is serialized behind an :class:`asyncio.Lock` so a token
  spike against a cold cache does not stampede Entra (mesh-flood
  guard — see Azure/kars commentary).
* Standard PyJWT verification covers signature + ``exp`` + ``iat``,
  plus we explicitly pin ``tid`` and ``aud`` and validate against
  ``allowed_signing_algorithms`` (RS256 / RS384 / RS512 only).
* Returns the raw ``appid`` claim — caller decides whether to use it
  as the verified DID or just as a label.

Env vars
~~~~~~~~
``AGENTMESH_ENTRA_AUDIENCE``     required — token ``aud`` to accept.
``AGENTMESH_ENTRA_TENANT_ID``    required — token ``tid`` to accept.
``AGENTMESH_ENTRA_AUTHORITY``    optional — default
                                 ``https://login.microsoftonline.com``.
``AGENTMESH_ENTRA_JWKS_TTL_SECS`` optional — int, default 3600.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)


ALLOWED_SIGNING_ALGORITHMS = ("RS256", "RS384", "RS512")


class EntraTokenError(Exception):
    """Raised when an inbound token fails Entra verification."""


@dataclass
class EntraVerifierConfig:
    """Resolved configuration. Build via :meth:`from_env`."""

    audience: str
    tenant_id: str
    authority: str
    jwks_ttl_secs: int
    # Hard upper bound on how long a stale JWKS cache may serve verify
    # requests when refetch keeps failing. Beyond this, fail closed.
    # Bounds Entra key-rotation propagation: a compromised key rotated
    # OUT of the live JWKS remains usable for at most this many seconds
    # even when the refetch path is broken (e.g. egress outage).
    # Default 24h matches the typical Entra signing-key rotation cadence.
    jwks_max_stale_secs: int

    @classmethod
    def from_env(cls) -> "EntraVerifierConfig | None":
        """Return ``None`` if the operator has not opted into verification.

        Both ``AGENTMESH_ENTRA_AUDIENCE`` and ``AGENTMESH_ENTRA_TENANT_ID``
        must be present and non-empty for verification to be enabled —
        a half-configured setup is treated as a misconfiguration and
        explicitly logged so the operator can fix it rather than
        silently running unverified.
        """
        aud = os.environ.get("AGENTMESH_ENTRA_AUDIENCE", "").strip()
        tid = os.environ.get("AGENTMESH_ENTRA_TENANT_ID", "").strip()
        if not aud and not tid:
            return None
        if not aud or not tid:
            logger.error(
                "AGENTMESH_ENTRA_{AUDIENCE,TENANT_ID} must be set together "
                "(got audience=%s tenant_id=%s); refusing to enable verification",
                bool(aud),
                bool(tid),
            )
            return None
        authority = os.environ.get(
            "AGENTMESH_ENTRA_AUTHORITY", "https://login.microsoftonline.com"
        ).rstrip("/")
        ttl_raw = os.environ.get("AGENTMESH_ENTRA_JWKS_TTL_SECS", "3600")
        try:
            ttl = max(60, int(ttl_raw))
        except ValueError:
            logger.warning(
                "AGENTMESH_ENTRA_JWKS_TTL_SECS=%r is not an int; using 3600",
                ttl_raw,
            )
            ttl = 3600
        max_stale_raw = os.environ.get("AGENTMESH_ENTRA_JWKS_MAX_STALE_SECS", "86400")
        try:
            # Floor at the TTL — it makes no sense to allow stale serving
            # for less time than a normal-cadence refresh.
            max_stale = max(ttl, int(max_stale_raw))
        except ValueError:
            logger.warning(
                "AGENTMESH_ENTRA_JWKS_MAX_STALE_SECS=%r is not an int; using 86400",
                max_stale_raw,
            )
            max_stale = 86400
        return cls(
            audience=aud,
            tenant_id=tid,
            authority=authority,
            jwks_ttl_secs=ttl,
            jwks_max_stale_secs=max_stale,
        )

    @property
    def jwks_url(self) -> str:
        """OpenID Connect discovery → JWKS URI for the tenant.

        We hardcode the well-known suffix rather than walking the
        OIDC discovery doc, both for one-fewer-round-trip and so the
        worker does not depend on network reachability during boot.
        Entra's JWKS URL has been stable for years.
        """
        return f"{self.authority}/{self.tenant_id}/discovery/v2.0/keys"


class EntraTokenVerifier:
    """Verifies inbound JWTs against Microsoft Entra.

    The instance is safe to share across coroutines. JWKS refetch is
    serialized via :class:`asyncio.Lock` to avoid stampedes when
    multiple concurrent connects miss a cold cache (the documented
    "mesh-flood when connecting to the registry" failure mode we
    explicitly guard against — see commit message for context).
    """

    def __init__(self, cfg: EntraVerifierConfig) -> None:
        self._cfg = cfg
        self._jwk_client: PyJWKClient | None = None
        self._jwk_cached_at: float = 0.0
        self._jwk_lock = asyncio.Lock()

    @property
    def config(self) -> EntraVerifierConfig:
        return self._cfg

    async def _ensure_jwk_client(self) -> PyJWKClient:
        now = time.monotonic()
        if (
            self._jwk_client is not None
            and (now - self._jwk_cached_at) < self._cfg.jwks_ttl_secs
        ):
            return self._jwk_client
        async with self._jwk_lock:
            # Double-checked: another waiter may have refreshed it.
            now = time.monotonic()
            if (
                self._jwk_client is not None
                and (now - self._jwk_cached_at) < self._cfg.jwks_ttl_secs
            ):
                return self._jwk_client
            try:
                client = await asyncio.to_thread(
                    PyJWKClient, self._cfg.jwks_url, cache_keys=True, lifespan=self._cfg.jwks_ttl_secs
                )
                # Eagerly trigger a fetch so we fail closed here (rather
                # than on first verify) when the JWKS endpoint is
                # unreachable on a cold cache.
                await asyncio.to_thread(client.get_signing_keys)
                self._jwk_client = client
                self._jwk_cached_at = time.monotonic()
                logger.info(
                    "Refreshed Entra JWKS cache from %s (ttl=%ss)",
                    self._cfg.jwks_url,
                    self._cfg.jwks_ttl_secs,
                )
                return client
            except (httpx.HTTPError, jwt.PyJWKClientError, OSError) as exc:
                stale_age = int(time.monotonic() - self._jwk_cached_at)
                if (
                    self._jwk_client is not None
                    and stale_age < self._cfg.jwks_max_stale_secs
                ):
                    # Availability-first within a bounded staleness budget:
                    # transient JWKS-fetch flakes (egress outage, Entra
                    # incident) must not lock every peer out, but a
                    # COMPROMISED key rotated OUT of the live JWKS must
                    # eventually stop being usable. The max-stale ceiling
                    # bounds the window in which a rotated-out key can
                    # still verify. After it expires, we fail closed.
                    logger.error(
                        "Entra JWKS refetch failed (%s); serving from "
                        "stale cache (%ss old, max %ss)",
                        exc,
                        stale_age,
                        self._cfg.jwks_max_stale_secs,
                    )
                    return self._jwk_client
                if self._jwk_client is not None:
                    logger.error(
                        "Entra JWKS refetch failed (%s) AND stale cache "
                        "exceeds max age (%ss > %ss) — failing closed",
                        exc,
                        stale_age,
                        self._cfg.jwks_max_stale_secs,
                    )
                    # Drop the stale client so future calls don't reuse it.
                    self._jwk_client = None
                raise EntraTokenError(
                    f"unable to fetch Entra JWKS from {self._cfg.jwks_url}: {exc}"
                ) from exc

    async def verify(self, token: str) -> dict[str, Any]:
        """Verify ``token`` and return its claims.

        Raises :class:`EntraTokenError` on any failure: signature
        mismatch, expired token, wrong tenant, wrong audience, or
        unsupported algorithm. The error message is suitable for
        logging but MUST NOT be returned to the caller verbatim
        because it can leak details about the JWKS state.
        """
        if not token or not isinstance(token, str):
            raise EntraTokenError("empty or non-string token")
        # Cap token length to prevent DoS via excessively large JWTs.
        # Entra v2.0 tokens are typically 1-2KB; 16KB is generous.
        if len(token) > 16384:
            raise EntraTokenError("token exceeds maximum length (16384 bytes)")
        # Defense-in-depth: validate the JWT header `alg` against our
        # allowlist BEFORE the JWKS lookup. PyJWT's `jwt.decode(...,
        # algorithms=...)` would also reject mismatches, but checking
        # here (a) avoids a wasted network round-trip on the JWKS fetch
        # for obviously-bad tokens and (b) defends against algorithm-
        # confusion attacks where an attacker presents alg=HS256 hoping
        # the JWK material gets reused as an HMAC secret. We use
        # `verify=False` so this peek is cheap and never makes auth
        # decisions based on unverified header fields.
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise EntraTokenError(f"invalid JWT header: {exc}") from exc
        header_alg = unverified_header.get("alg")
        if header_alg not in ALLOWED_SIGNING_ALGORITHMS:
            raise EntraTokenError(
                f"unsupported alg {header_alg!r}; allowed: {ALLOWED_SIGNING_ALGORITHMS}"
            )
        client = await self._ensure_jwk_client()
        try:
            signing_key = await asyncio.to_thread(client.get_signing_key_from_jwt, token)
        except jwt.PyJWKClientError as exc:
            raise EntraTokenError(f"no matching JWKS key: {exc}") from exc
        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(ALLOWED_SIGNING_ALGORITHMS),
                audience=self._cfg.audience,
                issuer=f"{self._cfg.authority}/{self._cfg.tenant_id}/v2.0",
                options={
                    "require": ["exp", "iat", "aud", "tid"],
                    "verify_aud": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_signature": True,
                },
            )
        except jwt.InvalidTokenError as exc:
            raise EntraTokenError(f"invalid token: {exc}") from exc
        actual_tid = str(claims.get("tid", ""))
        if actual_tid.lower() != self._cfg.tenant_id.lower():
            raise EntraTokenError(
                f"tid claim {actual_tid!r} does not match expected {self._cfg.tenant_id!r}"
            )
        return claims


_VERIFIER: EntraTokenVerifier | None = None
_VERIFIER_INIT_LOCK = asyncio.Lock()


async def get_verifier() -> EntraTokenVerifier | None:
    """Singleton accessor. Returns ``None`` when verification is disabled.

    Concurrent initialization is serialized so a connect burst against
    a cold process cannot create competing verifiers (each carrying
    their own ``_jwk_lock`` and racing the JWKS fetch).
    """
    global _VERIFIER
    if _VERIFIER is not None:
        return _VERIFIER
    cfg = EntraVerifierConfig.from_env()
    if cfg is None:
        return None
    async with _VERIFIER_INIT_LOCK:
        if _VERIFIER is None:
            _VERIFIER = EntraTokenVerifier(cfg)
            logger.info(
                "Entra token verifier initialized (audience=%s tenant=%s authority=%s)",
                cfg.audience,
                cfg.tenant_id,
                cfg.authority,
            )
    return _VERIFIER


def reset_verifier_for_tests() -> None:
    """Test-only hook: clears the cached verifier so subsequent
    :func:`get_verifier` calls re-read the environment. Production
    callers MUST NOT call this — the verifier is intentionally
    process-singleton."""
    global _VERIFIER
    _VERIFIER = None
