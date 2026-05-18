"""External JWKS identity provider for cross-org agent federation.

Implements the ExternalJWKSProvider piece of ADR-0007 (External JWKS
federation for cross-org agent identity). Verifies cross-org agent
tokens against DNS-anchored JWKS endpoints using AGT's existing
cryptography primitives — no new dependencies.

This module ships the provider only. The IdentityProviderChain
abstraction and HandshakeResult.external_identity extension proposed
in ADR-0007 are not part of this PR; they are intentional follow-ups
to be discussed in separate proposals. Operators wire this provider
into their handshake flow explicitly.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, urlunparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, Field, HttpUrl


_DEFAULT_JWKS_TTL_SECONDS = 300
_DEFAULT_REVOCATION_TTL_SECONDS = 60
_DEFAULT_HTTP_TIMEOUT_SECONDS = 5.0


def _b64url_decode(s: str) -> bytes:
    """Decode base64url string without padding per RFC 7515.

    Mirrors the helper in agentmesh.identity.jwk for module independence.
    """
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


class DelegationClaims(BaseModel):
    """Typed delegation claims for cross-org authority binding.

    Refines ADR-0007's open `delegation_claims: dict` field. The four
    fields correspond to the structural axes a cross-org authority
    must bind outside identity itself: scope, liveness, policy context,
    and revocation. Identity is established by the surrounding
    ExternalIdentity.

    Backwards-compatible with dict-shaped claims via pydantic
    model_validate; operators on the open schema continue to work.
    """

    authority_scope: list[str] = Field(
        default_factory=list,
        description="Scoped capabilities granted by the issuing org",
    )
    liveness_attestation_ref: Optional[str] = Field(
        default=None,
        description="ADR-0005 heartbeat id binding this identity to a liveness window",
    )
    policy_context_id: Optional[str] = Field(
        default=None,
        description="Opaque id resolvable by the issuing org's policy provider",
    )
    revocation_check_url: Optional[HttpUrl] = Field(
        default=None,
        description=(
            "Signed override for the revocation-list URL. Consulted only after "
            "the token's signature has been verified against the issuer's JWKS."
        ),
    )
    issued_at: Optional[datetime] = Field(
        default=None,
        description="When the issuing org bound these claims to the agent",
    )


class TrustedEndpoint(BaseModel):
    """Configured trusted JWKS endpoint per ADR-0007 federation policy."""

    domain: str
    jwks_url: HttpUrl
    trust_tier: str = "trusted"


class FederationPolicy(BaseModel):
    """Federation policy per ADR-0007 — trusted endpoints, caching, TOFU/open opt-in."""

    trusted_endpoints: list[TrustedEndpoint] = Field(default_factory=list)
    unknown_endpoint_policy: str = "deny"
    jwks_cache_ttl_seconds: int = _DEFAULT_JWKS_TTL_SECONDS
    revocation_cache_ttl_seconds: int = _DEFAULT_REVOCATION_TTL_SECONDS
    require_dnssec: bool = False


class ExternalIdentity(BaseModel):
    """Identity verified via external JWKS federation, per ADR-0007."""

    did_web: str
    jwks_url: HttpUrl
    issuer_domain: str
    federation_tier: str
    verified_at: datetime
    token_expires_at: datetime
    delegation_claims: DelegationClaims = Field(default_factory=DelegationClaims)


class _CacheEntry(BaseModel):
    value: object
    expires_at: float

    model_config = {"arbitrary_types_allowed": True}


class ExternalJWKSProvider:
    """Cross-org JWKS-backed identity provider.

    Verifies tokens by fetching the issuer's JWKS endpoint, validating
    the Ed25519 signature using AGT's existing cryptography primitives,
    and applying federation-policy rules. Federation tier is resolved
    against the configured FederationPolicy. JWKS and revocation lists
    are cached with TTLs; both use the same httpx fetch path.
    """

    def __init__(self, policy: FederationPolicy) -> None:
        self._policy = policy
        self._jwks_cache: dict[str, _CacheEntry] = {}
        self._revocation_cache: dict[str, _CacheEntry] = {}
        self._cache_lock = asyncio.Lock()
        self._http_timeout = _DEFAULT_HTTP_TIMEOUT_SECONDS

    async def verify(self, token: str) -> Optional[ExternalIdentity]:
        """Verify a cross-org token. Returns ExternalIdentity on success."""
        try:
            header, payload, signature, signing_input = self._parse_jwt(token)
        except (ValueError, json.JSONDecodeError):
            return None

        iss = payload.get("iss")
        kid = header.get("kid")
        if not iss or not kid:
            return None

        endpoint = self._resolve_endpoint(iss)
        if endpoint is None:
            return None

        jwks = await self._get_jwks(str(endpoint.jwks_url))
        if jwks is None:
            return None

        jwk = self._find_jwk_by_kid(jwks, kid)
        if jwk is None:
            return None

        if not self._verify_signature(jwk, signature, signing_input):
            return None

        exp = payload.get("exp")
        if not isinstance(exp, (int, float)) or exp < time.time():
            return None

        revocation_url = self._revocation_url_for(endpoint, payload)
        revoked = await self._get_revocation_list(revocation_url)
        if kid in revoked:
            return None

        return self._build_identity(payload, endpoint)

    async def warm_cache(self, jwks_urls: list[str]) -> None:
        """Pre-warm the JWKS cache for known partners.

        Per ADR-0003 200ms handshake SLA: cold-cache fetch is an HTTPS
        round-trip; pre-warming brings first cross-org handshakes inside
        budget.
        """
        await asyncio.gather(
            *(self._get_jwks(url) for url in jwks_urls),
            return_exceptions=True,
        )

    def _parse_jwt(self, token: str) -> tuple[dict, dict, bytes, bytes]:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("malformed JWT")
        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        return header, payload, signature, signing_input

    @staticmethod
    def _find_jwk_by_kid(jwks: dict, kid: str) -> Optional[dict]:
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return key
        return None

    @staticmethod
    def _verify_signature(jwk: dict, signature: bytes, signing_input: bytes) -> bool:
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return False
        try:
            public_bytes = _b64url_decode(jwk["x"])
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            public_key.verify(signature, signing_input)
            return True
        except (InvalidSignature, KeyError, ValueError):
            return False

    @staticmethod
    def _revocation_url_for(endpoint: TrustedEndpoint, verified_payload: dict) -> str:
        """Return revocation URL, preferring a verified claim override.

        Override is taken only from the already-signature-verified payload,
        not from unverified token contents, to prevent attackers steering
        verifiers at attacker-controlled URLs. Default URL is derived by
        rewriting the JWKS URL's path filename — robust against query
        strings, fragments, and non-standard JWKS URL shapes.
        """
        delegation = verified_payload.get("delegation_claims") or {}
        override = delegation.get("revocation_check_url")
        if override:
            return str(override)
        parsed = urlparse(str(endpoint.jwks_url))
        # Replace only the final path segment if it ends in jwks.json; else
        # append the revocation filename to the path. Preserves scheme,
        # netloc, params, query, and fragment.
        path = parsed.path
        if path.endswith("/jwks.json"):
            new_path = path[: -len("/jwks.json")] + "/jwks-revoked.json"
        else:
            new_path = path.rstrip("/") + "/jwks-revoked.json"
        return urlunparse(parsed._replace(path=new_path))

    def _resolve_endpoint(self, iss: str) -> Optional[TrustedEndpoint]:
        domain = urlparse(iss if "://" in iss else f"https://{iss}").netloc
        for endpoint in self._policy.trusted_endpoints:
            if endpoint.domain == domain:
                return endpoint
        if self._policy.unknown_endpoint_policy == "tofu":
            return TrustedEndpoint(
                domain=domain,
                jwks_url=HttpUrl(f"https://{domain}/.well-known/jwks.json"),
                trust_tier="tofu",
            )
        if self._policy.unknown_endpoint_policy == "open":
            return TrustedEndpoint(
                domain=domain,
                jwks_url=HttpUrl(f"https://{domain}/.well-known/jwks.json"),
                trust_tier="open",
            )
        return None

    async def _get_jwks(self, jwks_url: str) -> Optional[dict]:
        async with self._cache_lock:
            entry = self._jwks_cache.get(jwks_url)
            if entry and entry.expires_at > time.monotonic():
                return entry.value  # type: ignore[return-value]

        jwks = await self._fetch_jwks(jwks_url)
        if jwks is None:
            return None

        async with self._cache_lock:
            self._jwks_cache[jwks_url] = _CacheEntry(
                value=jwks,
                expires_at=time.monotonic() + self._policy.jwks_cache_ttl_seconds,
            )
        return jwks

    async def _fetch_jwks(self, jwks_url: str) -> Optional[dict]:
        try:
            async with httpx.AsyncClient(timeout=self._http_timeout) as client:
                resp = await client.get(jwks_url)
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, ValueError):
            return None

    async def _get_revocation_list(self, revocation_url: str) -> set[str]:
        async with self._cache_lock:
            entry = self._revocation_cache.get(revocation_url)
            if entry and entry.expires_at > time.monotonic():
                return entry.value  # type: ignore[return-value]

        revoked = await self._fetch_revocation_list(revocation_url)
        async with self._cache_lock:
            self._revocation_cache[revocation_url] = _CacheEntry(
                value=revoked,
                expires_at=time.monotonic() + self._policy.revocation_cache_ttl_seconds,
            )
        return revoked

    async def _fetch_revocation_list(self, revocation_url: str) -> set[str]:
        try:
            async with httpx.AsyncClient(timeout=self._http_timeout) as client:
                resp = await client.get(revocation_url)
            if resp.status_code == 404:
                return set()
            resp.raise_for_status()
            data = resp.json()
            return {entry["kid"] for entry in data.get("revoked", [])}
        except (httpx.HTTPError, KeyError, ValueError):
            return set()

    def _build_identity(
        self, payload: dict, endpoint: TrustedEndpoint
    ) -> ExternalIdentity:
        delegation = payload.get("delegation_claims") or {}
        return ExternalIdentity(
            did_web=payload.get("sub", f"did:web:{endpoint.domain}"),
            jwks_url=endpoint.jwks_url,
            issuer_domain=endpoint.domain,
            federation_tier=endpoint.trust_tier,
            verified_at=datetime.now(timezone.utc),
            token_expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            delegation_claims=DelegationClaims.model_validate(delegation),
        )
