# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
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
from typing import Optional, Union
from urllib.parse import urlparse, urlunparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from pydantic import BaseModel, Field, HttpUrl, field_validator


_DEFAULT_JWKS_TTL_SECONDS = 300
_DEFAULT_REVOCATION_TTL_SECONDS = 60
_DEFAULT_HTTP_TIMEOUT_SECONDS = 5.0


def _b64url_decode(s: str) -> bytes:
    """Decode base64url string without padding per RFC 7515.

    Mirrors the helper in agentmesh.identity.jwk for module independence.
    """
    pad_len = 4 - len(s) % 4
    if pad_len != 4:
        s += "=" * pad_len
    return base64.urlsafe_b64decode(s)


def _b64url_decode_uint(s: str) -> int:
    """Decode a base64url string into the big-endian unsigned integer it
    encodes, per RFC 7518 section 6.3 (JWK RSA/EC coordinate encoding)."""
    return int.from_bytes(_b64url_decode(s), "big")


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
    """Configured trusted JWKS endpoint per ADR-0007 federation policy.

    `role_claim_path`/`group_claim_path` are dotted paths into the verified
    payload (e.g. "realm_access.roles") for extracting standard OIDC
    role/group claims — different issuers shape these differently (Keycloak
    nests roles under `realm_access`; others put a flat `roles` claim at the
    top level). `None` means "use the policy-level default" — see
    `FederationPolicy.default_role_claim_path`. A path segment containing a
    literal dot (e.g. a Keycloak client id like `resource_access.my.client
    .roles`) can't be expressed as a dotted string; pass a pre-split
    `list[str]` of segments instead (`["resource_access", "my.client",
    "roles"]`).

    `audience` is the client id (or ids) this endpoint's tokens must be
    issued for, checked against the verified token's own `aud` claim
    (`aud` may be a single string or a list, per RFC 7519). **Leaving it
    unset accepts a token minted for ANY client the issuer trusts** — a
    verified RS256 token is otherwise only proof the issuer signed it, not
    that it was meant for this verifier (e.g. a browser SPA's stolen
    access token would verify identically to one this integration
    actually requested). Set it whenever the issuer mints tokens for more
    than one client.
    """

    domain: str
    jwks_url: HttpUrl
    trust_tier: str = "trusted"
    role_claim_path: Optional[Union[str, list[str]]] = None
    group_claim_path: Optional[Union[str, list[str]]] = None
    audience: Optional[Union[str, list[str]]] = None

    @field_validator("audience")
    @classmethod
    def _audience_not_empty(cls, v: Optional[Union[str, list[str]]]):
        # An empty string is a real (if unusual) `aud` value some tokens
        # carry - configuring audience="" would match it, silently
        # trusting a token that asserts no audience at all. An empty
        # list is the opposite footgun: it can never intersect anything,
        # so every token is rejected with no signal that the field is
        # misconfigured rather than intentionally locking things down.
        # Both look "configured" while doing something the caller almost
        # certainly didn't intend - reject them outright instead. A list
        # containing an empty-string member (`[""]`, `["", "x"]`) is the
        # same footgun in disguise - len() alone doesn't catch it.
        if v is None:
            return v
        members = [v] if isinstance(v, str) else v
        if not members or any(m == "" for m in members):
            raise ValueError(
                "audience must not be empty - omit it entirely to accept "
                "a token for any client, rather than an empty string, "
                "empty list, or a list containing an empty-string member"
            )
        return v


class FederationPolicy(BaseModel):
    """Federation policy per ADR-0007 — trusted endpoints, caching, TOFU/open opt-in.

    `default_role_claim_path`/`default_group_claim_path` default to
    Keycloak's shape (`realm_access.roles`, a top-level `groups` claim),
    since it's the most common self-hosted OIDC provider; override per
    endpoint via `TrustedEndpoint.role_claim_path`/`group_claim_path` for
    issuers that shape claims differently.
    """

    trusted_endpoints: list[TrustedEndpoint] = Field(default_factory=list)
    unknown_endpoint_policy: str = "deny"
    jwks_cache_ttl_seconds: int = _DEFAULT_JWKS_TTL_SECONDS
    revocation_cache_ttl_seconds: int = _DEFAULT_REVOCATION_TTL_SECONDS
    require_dnssec: bool = False
    default_role_claim_path: str = "realm_access.roles"
    default_group_claim_path: str = "groups"


class ExternalIdentity(BaseModel):
    """Identity verified via external JWKS federation, per ADR-0007."""

    did_web: str
    jwks_url: HttpUrl
    issuer_domain: str
    federation_tier: str
    verified_at: datetime
    token_expires_at: datetime
    delegation_claims: DelegationClaims = Field(default_factory=DelegationClaims)
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)

    def as_policy_kwargs(self) -> dict:
        """Bridge this verified identity into govern()'s policy context.

        govern()'s context is built purely from caller-supplied kwargs
        (`caller_role`, etc.) — there is no framework-level wiring from a
        verified identity to that context anywhere in this codebase, by
        design (kwargs-only, no hidden magic). Spread the result into a
        governed call: `safe(**identity.as_policy_kwargs(), doc_id=...)`.

        `caller_roles`/`caller_groups` are dicts (`{"admin": True, ...}`),
        not lists: GovernedCallable._build_context passes a dict kwarg
        through to the policy context as-is, and PolicyRule._eval_expression
        only supports scalar equality/membership/comparison on a bare
        dotted path, not a list-membership test — a YAML rule referencing
        `caller_roles.value in [...]` or `caller_roles.value == 'admin'`
        against a *list* value silently never matches. Against this dict
        shape, `caller_roles.admin` resolves through _get_nested and is
        evaluated as a plain (order-independent) boolean attribute.

        That dict-key addressing only reaches names matching `\\w+`
        (letters, digits, underscore) — no dots, slashes, or hyphens —
        since PolicyRule's bare-attribute matcher both splits the path on
        "." and requires each segment to match `\\w+` (governance/policy.py:
        241, 250). Keycloak's own `groups` claim is typically `/path`
        values (e.g. `/engineering/compliance`), and its default roles
        include hyphenated names like `default-roles-company`; neither is
        addressable this way. An allow rule against one silently denies,
        since the condition can never match and the default_action takes
        over. A deny rule against one currently also denies — but only
        because policy.py's unrecognized-condition fallback treats an
        unparseable condition on any non-allow rule as a fail-closed
        match (see `_eval_expression`'s final branch), not because the
        name was actually addressed; that fallback is a general
        hardening measure, not something this module can rely on for a
        specific rule. There is still no list/dict membership operator
        or way to address a hyphenated/slash-containing key directly.
        Only write rules against role/group names that are already
        identifier-shaped; resolve anything else upstream (e.g. via
        role_claim_path/group_claim_path extraction) before it reaches
        govern().

        There is no singular `caller_role`: an earlier version picked
        `roles[0]`, but role order in the verified token is whatever the
        issuer happened to serialize (Keycloak's realm_access.roles comes
        from a Python-side set with no defined order), so a YAML rule
        keyed on a single caller_role gave different decisions for the
        same role set depending on iteration order — a deny-by-role rule
        was bypassable just by how the roles happened to sort that
        request. Write rules against caller_roles.<role> instead.
        """
        return {
            "caller_roles": {role: True for role in self.roles},
            "caller_groups": {group: True for group in self.groups},
        }


class _CacheEntry(BaseModel):
    value: object
    expires_at: float

    model_config = {"arbitrary_types_allowed": True}


class ExternalJWKSProvider:
    """Cross-org JWKS-backed identity provider.

    Verifies tokens by fetching the issuer's JWKS endpoint, validating
    the signature (Ed25519, RS256, or ES256 - see `_verify_signature`)
    using AGT's existing cryptography primitives, and applying
    federation-policy rules. Federation tier is resolved against the
    configured FederationPolicy. JWKS and revocation lists are cached with
    TTLs; both use the same httpx fetch path.
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

        # nbf is optional (RFC 7519 §4.1.5) - absence means valid
        # immediately - but a *present* one is checked the same way exp
        # is above: a non-numeric value fails closed rather than being
        # silently ignored as if unset.
        nbf = payload.get("nbf")
        if nbf is not None and (not isinstance(nbf, (int, float)) or nbf > time.time()):
            return None

        # A verified signature only proves the issuer minted this token,
        # not that it was minted *for this verifier*: without an audience
        # check, a token the issuer signed for any other client (e.g. one
        # lifted from a browser SPA) verifies identically to one actually
        # requested for this integration. See TrustedEndpoint.audience.
        if endpoint.audience is not None and not self._audience_satisfied(
            endpoint.audience, payload.get("aud")
        ):
            return None

        revocation_url = self._revocation_url_for(endpoint, payload)
        if revocation_url is None:
            # Override URL failed validation (different host, non-https,
            # or unparseable). Fail closed rather than fall back silently.
            return None
        revoked = await self._get_revocation_list(revocation_url)
        if revoked is None:
            # Revocation fetch failed (network error, 5xx, malformed body).
            # Fail closed — accepting a token whose revocation status we
            # cannot determine would let revoked credentials pass.
            return None
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
        """Verify against whatever key type the JWKS actually published.

        Dispatches on the JWK's own `kty`/`crv` rather than the JWT
        header's `alg`: the header is unverified at this point, so trusting
        it to pick the verification routine would let a crafted token steer
        itself onto the wrong check (classic algorithm-confusion). Ed25519
        was this module's original scheme (ADR-0007 agent-to-agent
        federation); RSA (RS256) and P-256 EC (ES256) are added so it can
        also verify tokens from a standard OIDC provider (Keycloak, Okta,
        etc.), whose default signing key is RS256, not Ed25519. Only these
        three key types verify; a realm's own PS256/RS512/ES384 keys (or
        anything else) are rejected.
        """
        # A realm's JWKS can publish encryption keys (use="enc", e.g. for
        # RSA-OAEP) alongside its signing keys. Using one to verify a
        # signature makes no cryptographic sense and RFC 7517 §4.2/4.3
        # reserve `use`/`key_ops` to say so; honour that instead of trying
        # every key regardless of its declared purpose.
        use = jwk.get("use")
        if use is not None and use != "sig":
            return False
        key_ops = jwk.get("key_ops")
        if key_ops is not None and (
            not isinstance(key_ops, list) or "verify" not in key_ops
        ):
            # Fail closed on any non-list shape rather than falling into
            # `"verify" not in key_ops` on a bare string - a malformed
            # value like "noverify" would pass that check via substring
            # match ("verify" IS a substring of "noverify"), and a
            # non-iterable value like an int/bool would raise TypeError
            # out of this remote-controlled document instead of denying.
            return False

        kty = jwk.get("kty")
        try:
            if kty == "OKP" and jwk.get("crv") == "Ed25519":
                public_bytes = _b64url_decode(jwk["x"])
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
                public_key.verify(signature, signing_input)
                return True
            if kty == "RSA":
                n = _b64url_decode_uint(jwk["n"])
                e = _b64url_decode_uint(jwk["e"])
                public_key = rsa.RSAPublicNumbers(e, n).public_key()
                public_key.verify(
                    signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
                )
                return True
            if kty == "EC" and jwk.get("crv") == "P-256":
                x = _b64url_decode_uint(jwk["x"])
                y = _b64url_decode_uint(jwk["y"])
                public_key = ec.EllipticCurvePublicNumbers(
                    x, y, ec.SECP256R1()
                ).public_key()
                if len(signature) != 64:
                    return False
                r = int.from_bytes(signature[:32], "big")
                s = int.from_bytes(signature[32:], "big")
                der_signature = utils.encode_dss_signature(r, s)
                public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
                return True
            return False
        except (InvalidSignature, KeyError, ValueError, TypeError):
            return False

    @staticmethod
    def _audience_satisfied(configured: Union[str, list[str]], token_aud: object) -> bool:
        """Whether `token_aud` (the token's own `aud` claim) contains at
        least one of the configured expected audience(s).

        Per RFC 7519 §4.1.3, `aud` may be a single string or an array — a
        multi-audience token is valid for any client named in it, so this
        checks for a non-empty intersection rather than exact equality.
        Anything else for `token_aud` (missing, not a string/list) fails
        closed rather than being coerced into a match.
        """
        configured_set = {configured} if isinstance(configured, str) else set(configured)
        if isinstance(token_aud, str):
            token_aud_set = {token_aud}
        elif isinstance(token_aud, list):
            token_aud_set = {a for a in token_aud if isinstance(a, str)}
        else:
            return False
        return bool(configured_set & token_aud_set)

    @staticmethod
    def _normalize_host(host: Optional[str]) -> Optional[str]:
        """Lowercase a hostname and strip a trailing dot.

        Returns None for empty/None inputs so callers can fail closed.
        """
        if not host:
            return None
        normalized = host.strip().lower()
        if normalized.endswith("."):
            normalized = normalized[:-1]
        return normalized or None

    @classmethod
    def _safe_host_from_url(cls, value: str) -> Optional[str]:
        """Extract a normalized hostname from a URL or bare host string.

        Uses urlparse's `.hostname` property so userinfo (`user@host`) and
        ports are excluded. Returns None for inputs that don't yield a
        parseable host so callers fail closed instead of fetching from
        `https:///...` or attacker-controlled netloc tricks.
        """
        if not value or not isinstance(value, str):
            return None
        candidate = value if "://" in value else f"https://{value}"
        try:
            parsed = urlparse(candidate)
        except ValueError:
            return None
        return cls._normalize_host(parsed.hostname)

    @classmethod
    def _revocation_url_for(
        cls, endpoint: TrustedEndpoint, verified_payload: dict
    ) -> Optional[str]:
        """Return revocation URL, preferring a verified claim override.

        Override is taken only from the already-signature-verified payload.
        Even then, the override is constrained to the same scheme (https)
        and host as the trusted JWKS endpoint — this prevents a malicious
        or compromised issuer from steering verifiers at attacker-controlled
        or internal (SSRF) URLs.

        Returns None when the override is present but fails validation,
        signalling the caller to fail the verification closed rather than
        silently falling back to a default URL.
        """
        delegation = verified_payload.get("delegation_claims") or {}
        override = delegation.get("revocation_check_url")
        jwks_host = cls._safe_host_from_url(str(endpoint.jwks_url))
        if override:
            override_str = str(override)
            try:
                parsed_override = urlparse(override_str)
            except ValueError:
                return None
            override_host = cls._normalize_host(parsed_override.hostname)
            if (
                parsed_override.scheme != "https"
                or not override_host
                or jwks_host is None
                or override_host != jwks_host
            ):
                return None
            return override_str
        parsed = urlparse(str(endpoint.jwks_url))
        path = parsed.path
        if path.endswith("/jwks.json"):
            new_path = path[: -len("/jwks.json")] + "/jwks-revoked.json"
        else:
            new_path = path.rstrip("/") + "/jwks-revoked.json"
        return urlunparse(parsed._replace(path=new_path))

    def _resolve_endpoint(self, iss: str) -> Optional[TrustedEndpoint]:
        domain = self._safe_host_from_url(iss)
        if domain is None:
            return None
        for endpoint in self._policy.trusted_endpoints:
            if self._normalize_host(endpoint.domain) == domain:
                return endpoint
        # TOFU/open construct a JWKS URL from the issuer claim. Only the
        # parsed hostname is reused — never raw `iss` substrings — so
        # crafted values like "attacker.com/path" or "user@trusted.com"
        # cannot smuggle a different netloc into the fetch URL.
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

    async def _get_revocation_list(self, revocation_url: str) -> Optional[set[str]]:
        """Return the revocation set for `revocation_url`.

        Returns:
            - A (possibly empty) set of revoked kids on success or 404.
            - None on transport/parse failure, signalling callers to fail
              closed instead of treating "fetch failed" as "no revocations".
        """
        async with self._cache_lock:
            entry = self._revocation_cache.get(revocation_url)
            if entry and entry.expires_at > time.monotonic():
                return entry.value  # type: ignore[return-value]

        revoked = await self._fetch_revocation_list(revocation_url)
        if revoked is None:
            return None
        async with self._cache_lock:
            self._revocation_cache[revocation_url] = _CacheEntry(
                value=revoked,
                expires_at=time.monotonic() + self._policy.revocation_cache_ttl_seconds,
            )
        return revoked

    async def _fetch_revocation_list(self, revocation_url: str) -> Optional[set[str]]:
        """Fetch a revocation list. Returns None on failure (fail closed).

        A 404 is treated as "no revocation list published yet" and yields
        an empty set, matching the design where issuers may bootstrap
        without one. Any other transport or parse failure returns None so
        the caller can deny the token rather than treat the absence of
        signal as a positive signal.
        """
        try:
            async with httpx.AsyncClient(timeout=self._http_timeout) as client:
                resp = await client.get(revocation_url)
            if resp.status_code == 404:
                return set()
            resp.raise_for_status()
            data = resp.json()
            return {entry["kid"] for entry in data.get("revoked", [])}
        except (httpx.HTTPError, KeyError, ValueError, TypeError):
            return None

    def _build_identity(
        self, payload: dict, endpoint: TrustedEndpoint
    ) -> ExternalIdentity:
        delegation = payload.get("delegation_claims") or {}
        # `is not None`, not `or`: an endpoint that explicitly sets
        # role_claim_path="" to disable role extraction must not fall back
        # to the policy default just because "" is falsy.
        role_path = (
            endpoint.role_claim_path
            if endpoint.role_claim_path is not None
            else self._policy.default_role_claim_path
        )
        group_path = (
            endpoint.group_claim_path
            if endpoint.group_claim_path is not None
            else self._policy.default_group_claim_path
        )
        return ExternalIdentity(
            did_web=payload.get("sub", f"did:web:{endpoint.domain}"),
            jwks_url=endpoint.jwks_url,
            issuer_domain=endpoint.domain,
            federation_tier=endpoint.trust_tier,
            verified_at=datetime.now(timezone.utc),
            token_expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            delegation_claims=DelegationClaims.model_validate(delegation),
            roles=self._extract_claim_list(payload, role_path),
            groups=self._extract_claim_list(payload, group_path),
        )

    @staticmethod
    def _extract_claim_list(payload: dict, dotted_path: Union[str, list[str]]) -> list[str]:
        """Walk `dotted_path` into `payload` and return a list of strings.

        `dotted_path` is either a dotted string ("realm_access.roles") or a
        pre-split `list[str]` of literal segments. The latter is required
        when a segment itself contains a dot — e.g. Keycloak's
        `resource_access.<client_id>.roles`, where `<client_id>` may be
        something like "my.dotted.client": splitting a dotted *string* on
        "." can't tell that dot apart from the path separator and would
        never find the claim.

        Any missing segment, or a final value that isn't a list, yields an
        empty list rather than raising — a malformed or absent claim just
        means no roles/groups, not a verification failure. Non-string
        entries in the list are dropped rather than coerced.
        """
        value: object = payload
        segments = dotted_path if isinstance(dotted_path, list) else dotted_path.split(".")
        for segment in segments:
            if not isinstance(value, dict):
                return []
            value = value.get(segment)
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]
