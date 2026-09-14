"""Tests for ExternalJWKSProvider per ADR-0007.

Uses real Ed25519 keypairs and real JWT serialization. Only the
network layer (httpx.AsyncClient.get) is mocked.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.parse import urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentmesh.identity.external_jwks import (
    DelegationClaims,
    ExternalIdentity,
    ExternalJWKSProvider,
    FederationPolicy,
    TrustedEndpoint,
)


PARTNER_DOMAIN = "partner-corp.example.com"
PARTNER_JWKS_URL = f"https://{PARTNER_DOMAIN}/.well-known/jwks.json"
PARTNER_REVOCATION_URL = f"https://{PARTNER_DOMAIN}/.well-known/jwks-revoked.json"
KEY_ID = "test-key-1"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_keypair(kid: str = KEY_ID) -> tuple[Ed25519PrivateKey, dict]:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url_encode(public_bytes),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }
    return private_key, jwk


def _sign_jwt(private_key: Ed25519PrivateKey, payload: dict, kid: str = KEY_ID) -> str:
    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input)
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _make_policy(unknown: str = "deny") -> FederationPolicy:
    return FederationPolicy(
        trusted_endpoints=[
            TrustedEndpoint(
                domain=PARTNER_DOMAIN,
                jwks_url=PARTNER_JWKS_URL,
                trust_tier="verified_partner",
            )
        ],
        unknown_endpoint_policy=unknown,
    )


def _http_mock(jwks_response: dict, revocation_response: dict | None = None):
    """Build an httpx.AsyncClient.get mock that dispatches by URL.

    Responses include a Request so `raise_for_status()` works.
    """

    async def fake_get(self, url, *args, **kwargs):
        request = httpx.Request("GET", url)
        if "jwks-revoked.json" in url or "revoked" in url:
            if revocation_response is None:
                return httpx.Response(404, request=request)
            return httpx.Response(200, json=revocation_response, request=request)
        if "jwks.json" in url:
            return httpx.Response(200, json=jwks_response, request=request)
        return httpx.Response(404, request=request)

    return fake_get


@pytest.mark.asyncio
async def test_verify_returns_external_identity_for_valid_token():
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": f"did:web:{PARTNER_DOMAIN}:agents:abc",
        "exp": now + 900,
        "iat": now,
        "delegation_claims": {
            "authority_scope": ["read:invoices"],
            "liveness_attestation_ref": "heartbeat-1",
            "policy_context_id": "policy-ctx-99",
            "issued_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        },
    }
    token = _sign_jwt(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert identity.issuer_domain == PARTNER_DOMAIN
    assert identity.federation_tier == "verified_partner"
    assert identity.did_web == f"did:web:{PARTNER_DOMAIN}:agents:abc"


@pytest.mark.asyncio
async def test_verify_returns_none_for_signature_mismatch():
    private_key_a, _ = _make_keypair()
    _, jwk_b = _make_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt(private_key_a, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk_b]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_returns_none_for_expired_token():
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now - 1, "iat": now - 1000}
    token = _sign_jwt(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_returns_none_for_revoked_kid():
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt(private_key, payload)
    revocation = {"revoked": [{"kid": KEY_ID, "ts": now}]}
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]}, revocation)):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_returns_none_for_unknown_issuer_under_allowlist_policy():
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {"iss": "unknown-org.example.com", "sub": "x", "exp": now + 900}
    token = _sign_jwt(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy(unknown="deny"))
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_accepts_unknown_issuer_under_tofu_policy():
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {
        "iss": "newpartner.example.com",
        "sub": "did:web:newpartner.example.com",
        "exp": now + 900,
        "iat": now,
    }
    token = _sign_jwt(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy(unknown="tofu"))
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert identity.federation_tier == "tofu"


@pytest.mark.asyncio
async def test_verify_resolves_typed_delegation_claims():
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "delegation_claims": {
            "authority_scope": ["read", "write"],
            "liveness_attestation_ref": "hb-9",
            "policy_context_id": "ctx-7",
            "issued_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        },
    }
    token = _sign_jwt(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert isinstance(identity.delegation_claims, DelegationClaims)
    assert identity.delegation_claims.authority_scope == ["read", "write"]
    assert identity.delegation_claims.liveness_attestation_ref == "hb-9"
    assert identity.delegation_claims.policy_context_id == "ctx-7"


@pytest.mark.asyncio
async def test_verify_uses_signed_revocation_url_override():
    """A revocation_check_url claim is honored only after signature verify."""
    private_key, jwk = _make_keypair()
    now = int(time.time())
    custom_revocation_url = f"https://{PARTNER_DOMAIN}/custom/revoked.json"
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "delegation_claims": {"revocation_check_url": custom_revocation_url},
    }
    token = _sign_jwt(private_key, payload)

    fetched_urls: list[str] = []

    async def tracking_get(self, url, *args, **kwargs):
        fetched_urls.append(url)
        request = httpx.Request("GET", url)
        if "custom/revoked.json" in url:
            return httpx.Response(200, json={"revoked": []}, request=request)
        if "jwks.json" in url:
            return httpx.Response(200, json={"keys": [jwk]}, request=request)
        return httpx.Response(404, request=request)

    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", tracking_get):
        identity = await provider.verify(token)

    assert identity is not None
    assert any("custom/revoked.json" in u for u in fetched_urls)
    assert not any(u.endswith("/jwks-revoked.json") for u in fetched_urls)


@pytest.mark.asyncio
async def test_warm_cache_populates_jwks_cache():
    private_key, jwk = _make_keypair()
    jwks_response = {"keys": [jwk]}
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock(jwks_response)):
        await provider.warm_cache([PARTNER_JWKS_URL])
    assert PARTNER_JWKS_URL in provider._jwks_cache
    assert provider._jwks_cache[PARTNER_JWKS_URL].value == jwks_response


@pytest.mark.asyncio
async def test_jwks_cache_respects_ttl():
    private_key, jwk = _make_keypair()
    provider = ExternalJWKSProvider(policy=_make_policy())
    provider._policy.jwks_cache_ttl_seconds = 0
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        await provider.warm_cache([PARTNER_JWKS_URL])
    time.sleep(0.01)
    entry = provider._jwks_cache[PARTNER_JWKS_URL]
    assert entry.expires_at <= time.monotonic()


@pytest.mark.asyncio
async def test_verify_path_uses_cached_jwks_no_second_fetch():
    """Confirms warm_cache and verify share a single cache (HIGH-finding regression)."""
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt(private_key, payload)

    fetch_count = {"jwks": 0}

    async def counting_get(self, url, *args, **kwargs):
        request = httpx.Request("GET", url)
        if "jwks.json" in url:
            fetch_count["jwks"] += 1
            return httpx.Response(200, json={"keys": [jwk]}, request=request)
        return httpx.Response(404, request=request)

    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", counting_get):
        await provider.warm_cache([PARTNER_JWKS_URL])
        identity = await provider.verify(token)

    assert identity is not None
    assert fetch_count["jwks"] == 1, "verify should reuse the warmed JWKS cache"


def test_delegation_claims_accepts_dict_for_backwards_compat():
    raw = {
        "authority_scope": ["read"],
        "liveness_attestation_ref": "hb-1",
        "policy_context_id": "ctx-1",
    }
    claims = DelegationClaims.model_validate(raw)
    assert claims.authority_scope == ["read"]
    assert claims.liveness_attestation_ref == "hb-1"
    assert claims.policy_context_id == "ctx-1"
    assert claims.revocation_check_url is None


# ---------------------------------------------------------------------------
# Security regressions — URL / trust-fetch hardening
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_rejects_revocation_url_override_on_different_host():
    """A signed override pointing at a different host must be rejected.

    Even though the override is inside the signature-verified payload, an
    issuer (or attacker holding the issuer's key) must not be able to
    steer verifiers at attacker-controlled or internal SSRF targets.
    """
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "delegation_claims": {
            "revocation_check_url": "https://attacker.example.org/revoked.json",
        },
    }
    token = _sign_jwt(private_key, payload)

    fetched_urls: list[str] = []

    async def tracking_get(self, url, *args, **kwargs):
        fetched_urls.append(url)
        request = httpx.Request("GET", url)
        if "jwks.json" in url and "attacker" not in url:
            return httpx.Response(200, json={"keys": [jwk]}, request=request)
        return httpx.Response(200, json={"revoked": []}, request=request)

    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", tracking_get):
        identity = await provider.verify(token)

    assert identity is None
    assert not any(urlparse(u).hostname == "attacker.example.org" for u in fetched_urls)


@pytest.mark.asyncio
async def test_verify_rejects_revocation_url_override_with_non_https_scheme():
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "delegation_claims": {
            # Same host but http:// must be rejected — downgrade attack.
            "revocation_check_url": f"http://{PARTNER_DOMAIN}/custom/revoked.json",
        },
    }
    token = _sign_jwt(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is None


@pytest.mark.asyncio
async def test_verify_fails_closed_when_revocation_fetch_errors():
    """Network/HTTP failures on revocation lookup must deny, not allow."""
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt(private_key, payload)

    async def failing_get(self, url, *args, **kwargs):
        request = httpx.Request("GET", url)
        if "jwks-revoked.json" in url:
            return httpx.Response(500, request=request)
        if "jwks.json" in url:
            return httpx.Response(200, json={"keys": [jwk]}, request=request)
        return httpx.Response(404, request=request)

    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", failing_get):
        identity = await provider.verify(token)
    assert identity is None


@pytest.mark.asyncio
async def test_verify_fails_closed_when_revocation_body_malformed():
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt(private_key, payload)

    async def bad_body_get(self, url, *args, **kwargs):
        request = httpx.Request("GET", url)
        if "jwks-revoked.json" in url:
            return httpx.Response(200, text="not-json", request=request)
        if "jwks.json" in url:
            return httpx.Response(200, json={"keys": [jwk]}, request=request)
        return httpx.Response(404, request=request)

    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", bad_body_get):
        identity = await provider.verify(token)
    assert identity is None


@pytest.mark.asyncio
async def test_verify_revocation_404_still_allows_token():
    """A 404 on the revocation endpoint means 'no list published' — allow."""
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None


@pytest.mark.asyncio
async def test_verify_tofu_strips_userinfo_from_issuer_claim():
    """`iss` with embedded userinfo must not redirect JWKS fetch.

    Without `.hostname`-based parsing, `attacker.com@trusted.com` would
    end up as a netloc that fools naive matchers. We must fetch from
    `trusted.com` (the actual host), and the trust tier remains 'tofu'.
    """
    private_key, jwk = _make_keypair()
    now = int(time.time())
    target_host = "victim-tenant.example.com"
    payload = {
        "iss": f"https://attacker.example.org@{target_host}",
        "sub": f"did:web:{target_host}",
        "exp": now + 900,
    }
    token = _sign_jwt(private_key, payload)

    fetched_urls: list[str] = []

    async def tracking_get(self, url, *args, **kwargs):
        fetched_urls.append(url)
        request = httpx.Request("GET", url)
        if "jwks.json" in url:
            return httpx.Response(200, json={"keys": [jwk]}, request=request)
        return httpx.Response(404, request=request)

    provider = ExternalJWKSProvider(policy=_make_policy(unknown="tofu"))
    with patch.object(httpx.AsyncClient, "get", tracking_get):
        identity = await provider.verify(token)

    assert identity is not None
    assert identity.issuer_domain == target_host
    # No request should have been issued to the attacker-controlled host.
    assert not any(urlparse(u).hostname == "attacker.example.org" for u in fetched_urls)


@pytest.mark.asyncio
async def test_verify_rejects_issuer_with_no_parseable_host():
    private_key, jwk = _make_keypair()
    now = int(time.time())
    payload = {"iss": "://", "sub": "x", "exp": now + 900}
    token = _sign_jwt(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy(unknown="tofu"))
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is None


def test_resolve_endpoint_matches_trusted_domain_case_insensitively():
    policy = FederationPolicy(
        trusted_endpoints=[
            TrustedEndpoint(
                domain="Partner-Corp.Example.com",
                jwks_url=PARTNER_JWKS_URL,
                trust_tier="verified_partner",
            )
        ],
    )
    provider = ExternalJWKSProvider(policy=policy)
    endpoint = provider._resolve_endpoint("partner-corp.example.com")
    assert endpoint is not None
    assert endpoint.trust_tier == "verified_partner"


# ── RS256/ES256 (standard OIDC providers - Keycloak's default is RS256) ──


def _uint_to_b64url(n: int, byte_len: int) -> str:
    return _b64url_encode(n.to_bytes(byte_len, "big"))


def _make_rsa_keypair(kid: str = KEY_ID):
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

    private_key = rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    byte_len = (numbers.n.bit_length() + 7) // 8
    jwk = {
        "kty": "RSA",
        "n": _uint_to_b64url(numbers.n, byte_len),
        "e": _uint_to_b64url(numbers.e, 3),
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
    }
    return private_key, jwk


def _sign_jwt_rs256(private_key, payload: dict, kid: str = KEY_ID) -> str:
    from cryptography.hazmat.primitives import hashes as hashes_mod
    from cryptography.hazmat.primitives.asymmetric import padding as padding_mod

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input, padding_mod.PKCS1v15(), hashes_mod.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def _make_ec_keypair(kid: str = KEY_ID):
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

    private_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _uint_to_b64url(numbers.x, 32),
        "y": _uint_to_b64url(numbers.y, 32),
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
    }
    return private_key, jwk


def _sign_jwt_es256(private_key, payload: dict, kid: str = KEY_ID) -> str:
    from cryptography.hazmat.primitives import hashes as hashes_mod
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
    from cryptography.hazmat.primitives.asymmetric import utils as utils_mod

    header = {"alg": "ES256", "typ": "JWT", "kid": kid}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    der_signature = private_key.sign(signing_input, ec_mod.ECDSA(hashes_mod.SHA256()))
    r, s = utils_mod.decode_dss_signature(der_signature)
    # JWS ES256 signatures are raw R||S, each a fixed 32 bytes for P-256 -
    # not the DER encoding `cryptography`'s sign() returns.
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{header_b64}.{payload_b64}.{_b64url_encode(raw_signature)}"


@pytest.mark.asyncio
async def test_verify_accepts_rs256_token_keycloak_default_algorithm():
    """Keycloak - and most standard OIDC providers - sign with RS256 by
    default, not the Ed25519 this module originally shipped with."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "did:web:x", "exp": now + 900}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert identity.issuer_domain == PARTNER_DOMAIN


@pytest.mark.asyncio
async def test_verify_rejects_rs256_token_with_wrong_key():
    _, jwk_a = _make_rsa_keypair()
    private_key_b, _ = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt_rs256(private_key_b, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk_a]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_accepts_es256_token():
    private_key, jwk = _make_ec_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "did:web:x", "exp": now + 900}
    token = _sign_jwt_es256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None


@pytest.mark.asyncio
async def test_verify_rejects_unsupported_key_type():
    """An HMAC ('oct') or other unsupported JWK type must not silently
    verify - only OKP/Ed25519, RSA, and EC/P-256 are supported."""
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    header = {"alg": "HS256", "typ": "JWT", "kid": KEY_ID}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    token = f"{header_b64}.{payload_b64}.{_b64url_encode(b'not-a-real-signature')}"
    jwk = {"kty": "oct", "kid": KEY_ID, "k": _b64url_encode(b"shared-secret")}
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


# ── Role/group claim extraction ──────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_extracts_keycloak_shaped_role_and_group_claims_by_default():
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "realm_access": {"roles": ["auditor", "offline_access"]},
        "groups": ["/engineering/compliance"],
    }
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert identity.roles == ["auditor", "offline_access"]
    assert identity.groups == ["/engineering/compliance"]


@pytest.mark.asyncio
async def test_verify_uses_per_endpoint_claim_path_override():
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "roles": ["reader"],
        "team_groups": ["platform"],
    }
    token = _sign_jwt_rs256(private_key, payload)
    policy = FederationPolicy(
        trusted_endpoints=[
            TrustedEndpoint(
                domain=PARTNER_DOMAIN,
                jwks_url=PARTNER_JWKS_URL,
                trust_tier="verified_partner",
                role_claim_path="roles",
                group_claim_path="team_groups",
            )
        ],
    )
    provider = ExternalJWKSProvider(policy=policy)
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert identity.roles == ["reader"]
    assert identity.groups == ["platform"]


@pytest.mark.asyncio
async def test_verify_missing_role_claims_yield_empty_lists_not_an_error():
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert identity.roles == []
    assert identity.groups == []


@pytest.mark.asyncio
async def test_verify_non_list_role_claim_yields_empty_list():
    """A malformed claim (e.g. a bare string instead of a list) must not
    raise - verification already succeeded; a shape mismatch downstream
    of that just means no extractable roles."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "realm_access": {"roles": "not-a-list"},
    }
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert identity.roles == []


def test_as_policy_kwargs_bridges_identity_to_governs_context():
    identity = ExternalIdentity(
        did_web="did:web:x",
        jwks_url=PARTNER_JWKS_URL,
        issuer_domain=PARTNER_DOMAIN,
        federation_tier="verified_partner",
        verified_at=datetime.now(timezone.utc),
        token_expires_at=datetime.now(timezone.utc),
        roles=["auditor", "engineer"],
        groups=["/engineering/compliance"],
    )
    kwargs = identity.as_policy_kwargs()
    assert kwargs == {
        "caller_role": "auditor",
        "caller_roles": ["auditor", "engineer"],
        "caller_groups": ["/engineering/compliance"],
    }


def test_as_policy_kwargs_caller_role_is_none_without_roles():
    identity = ExternalIdentity(
        did_web="did:web:x",
        jwks_url=PARTNER_JWKS_URL,
        issuer_domain=PARTNER_DOMAIN,
        federation_tier="verified_partner",
        verified_at=datetime.now(timezone.utc),
        token_expires_at=datetime.now(timezone.utc),
    )
    kwargs = identity.as_policy_kwargs()
    assert kwargs["caller_role"] is None
    assert kwargs["caller_roles"] == []
    assert kwargs["caller_groups"] == []
