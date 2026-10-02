# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
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
import pydantic
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


@pytest.mark.asyncio
async def test_verify_rejects_encryption_only_jwk():
    """A JWKS can publish an encryption key (use="enc", e.g. RSA-OAEP)
    alongside signing keys - it must never be accepted for signature
    verification just because it happens to parse as an RSA/EC public
    key."""
    private_key, jwk = _make_rsa_keypair()
    jwk["use"] = "enc"
    jwk["alg"] = "RSA-OAEP"
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_rejects_jwk_with_key_ops_excluding_verify():
    private_key, jwk = _make_rsa_keypair()
    del jwk["use"]
    jwk["key_ops"] = ["encrypt"]
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_accepts_jwk_with_no_use_or_key_ops():
    """use/key_ops are both optional per RFC 7517 - a JWK naming neither
    is not thereby excluded from signing, it just declines to say."""
    private_key, jwk = _make_rsa_keypair()
    del jwk["use"]
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None


@pytest.mark.parametrize("bad_key_ops", [123, True, "noverify"])
@pytest.mark.asyncio
async def test_verify_rejects_non_list_key_ops(bad_key_ops):
    """key_ops must be a real list, not just something "verify" not in
    happens to accept: a bare int/bool raised TypeError out of the
    remote-controlled JWKS instead of failing closed, and a string like
    "noverify" passed the substring check ("verify" IS a substring of
    "noverify") and let the key verify anyway."""
    private_key, jwk = _make_rsa_keypair()
    del jwk["use"]
    jwk["key_ops"] = bad_key_ops
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_survives_non_string_jwk_members_typeerror():
    """A malformed JWKS entry (e.g. a numeric or null 'n') must fail
    verification, not raise TypeError out of rsa.RSAPublicNumbers /
    public_key.verify."""
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    header = {"alg": "RS256", "typ": "JWT", "kid": KEY_ID}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    token = f"{header_b64}.{payload_b64}.{_b64url_encode(b'not-a-real-signature')}"
    jwk = {"kty": "RSA", "kid": KEY_ID, "use": "sig", "n": 12345, "e": None}
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


# ── Audience (aud) and not-before (nbf) ─────────────────────────────


def _policy_with_audience(audience) -> FederationPolicy:
    return FederationPolicy(
        trusted_endpoints=[
            TrustedEndpoint(
                domain=PARTNER_DOMAIN,
                jwks_url=PARTNER_JWKS_URL,
                trust_tier="verified_partner",
                audience=audience,
            )
        ],
    )


@pytest.mark.asyncio
async def test_verify_rejects_token_with_wrong_audience():
    """A verified token minted for a different client (e.g. one lifted
    from a browser SPA) must not pass just because the issuer signed it -
    without this check every client sharing an issuer is interchangeable."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "aud": "some-other-webapp",
    }
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_policy_with_audience("this-service"))
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_accepts_token_with_matching_audience():
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "aud": "this-service",
    }
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_policy_with_audience("this-service"))
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None


@pytest.mark.asyncio
async def test_verify_accepts_token_with_aud_as_list_containing_match():
    """`aud` may be an array (RFC 7519 §4.1.3) for a token valid across
    multiple clients; a match anywhere in it is sufficient."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "aud": ["some-other-webapp", "this-service"],
    }
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_policy_with_audience("this-service"))
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None


@pytest.mark.asyncio
async def test_verify_accepts_configured_audience_list_matching_any():
    """endpoint.audience may itself be a list - any one of them is an
    acceptable client for this endpoint."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900, "aud": "service-b"}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(
        policy=_policy_with_audience(["service-a", "service-b"])
    )
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None


@pytest.mark.asyncio
async def test_verify_rejects_missing_audience_claim_when_configured():
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_policy_with_audience("this-service"))
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_accepts_any_audience_when_unconfigured():
    """Documents the default: leaving audience unset accepts a token
    minted for any client the issuer trusts."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900, "aud": "anything"}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None


@pytest.mark.parametrize("empty_audience", ["", [], [""], ["", "x"]])
def test_trusted_endpoint_rejects_empty_audience(empty_audience):
    """audience="" would match a token whose own aud is also "" (a real,
    if unusual, claim value) - silently trusting a token that asserts no
    audience at all. audience=[] is the opposite footgun: it can never
    intersect anything, so every token is rejected with no signal that
    the field is misconfigured rather than intentionally locking things
    down. Both look configured while doing something almost certainly
    unintended - reject at construction instead of accepting silently.
    [""] and ["", "x"] are the same footgun hiding inside a non-empty
    list - len() alone doesn't catch an empty-string member."""
    with pytest.raises(pydantic.ValidationError):
        TrustedEndpoint(
            domain=PARTNER_DOMAIN,
            jwks_url=PARTNER_JWKS_URL,
            audience=empty_audience,
        )


@pytest.mark.asyncio
async def test_verify_rejects_future_nbf():
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900, "nbf": now + 3000}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        result = await provider.verify(token)
    assert result is None


@pytest.mark.asyncio
async def test_verify_accepts_past_nbf():
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900, "nbf": now - 60}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None


@pytest.mark.asyncio
async def test_verify_accepts_token_with_no_nbf_claim():
    """nbf is optional per RFC 7519 §4.1.5 - its absence means valid
    immediately, not rejected."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900}
    token = _sign_jwt_rs256(private_key, payload)
    provider = ExternalJWKSProvider(policy=_make_policy())
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None


@pytest.mark.asyncio
async def test_verify_rejects_non_numeric_nbf():
    """A present-but-malformed nbf must fail closed the same way a
    malformed exp already does, not be treated as though it were
    absent - a string "9999999999" is truthy-adjacent but isn't the
    numeric type verify() actually compares against time.time()."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {"iss": PARTNER_DOMAIN, "sub": "x", "exp": now + 900, "nbf": "9999999999"}
    token = _sign_jwt_rs256(private_key, payload)
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
async def test_verify_claim_path_as_list_reaches_dotted_client_id():
    """resource_access.<client_id>.roles can't be expressed as a dotted
    *string* when the client id itself contains a dot - splitting on "."
    can't tell that dot from the path separator. A pre-split list of
    segments sidesteps the ambiguity entirely."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "resource_access": {"my.dotted.client": {"roles": ["viewer"]}},
    }
    token = _sign_jwt_rs256(private_key, payload)
    policy = FederationPolicy(
        trusted_endpoints=[
            TrustedEndpoint(
                domain=PARTNER_DOMAIN,
                jwks_url=PARTNER_JWKS_URL,
                trust_tier="verified_partner",
                role_claim_path=["resource_access", "my.dotted.client", "roles"],
            )
        ],
    )
    provider = ExternalJWKSProvider(policy=policy)
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert identity.roles == ["viewer"]


@pytest.mark.asyncio
async def test_verify_empty_string_claim_path_disables_extraction():
    """role_claim_path="" must disable extraction for this endpoint, not
    be treated as unset and fall back to the policy default - `or` treats
    "" and None identically, but they mean different things here."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    payload = {
        "iss": PARTNER_DOMAIN,
        "sub": "x",
        "exp": now + 900,
        "realm_access": {"roles": ["would-default-extract"]},
    }
    token = _sign_jwt_rs256(private_key, payload)
    policy = FederationPolicy(
        trusted_endpoints=[
            TrustedEndpoint(
                domain=PARTNER_DOMAIN,
                jwks_url=PARTNER_JWKS_URL,
                trust_tier="verified_partner",
                role_claim_path="",
            )
        ],
    )
    provider = ExternalJWKSProvider(policy=policy)
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    assert identity is not None
    assert identity.roles == []


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
        "caller_roles": {"auditor": True, "engineer": True},
        "caller_groups": {"/engineering/compliance": True},
    }


def test_as_policy_kwargs_empty_dicts_without_roles():
    identity = ExternalIdentity(
        did_web="did:web:x",
        jwks_url=PARTNER_JWKS_URL,
        issuer_domain=PARTNER_DOMAIN,
        federation_tier="verified_partner",
        verified_at=datetime.now(timezone.utc),
        token_expires_at=datetime.now(timezone.utc),
    )
    kwargs = identity.as_policy_kwargs()
    assert kwargs["caller_roles"] == {}
    assert kwargs["caller_groups"] == {}
    assert "caller_role" not in kwargs


def test_as_policy_kwargs_role_membership_is_order_independent():
    """Pins the fix for the caller_role[0] ordering bug: the same role set
    in a different order must bridge to an identical policy context, since
    a YAML rule keyed on role membership must not depend on how the issuer
    happened to serialize the roles claim."""
    common = dict(
        did_web="did:web:x",
        jwks_url=PARTNER_JWKS_URL,
        issuer_domain=PARTNER_DOMAIN,
        federation_tier="verified_partner",
        verified_at=datetime.now(timezone.utc),
        token_expires_at=datetime.now(timezone.utc),
    )
    forward = ExternalIdentity(roles=["contractor", "offline_access"], **common)
    reverse = ExternalIdentity(roles=["offline_access", "contractor"], **common)
    assert forward.as_policy_kwargs() == reverse.as_policy_kwargs()
    assert forward.as_policy_kwargs()["caller_roles"] == {
        "contractor": True,
        "offline_access": True,
    }


def test_as_policy_kwargs_role_membership_matches_through_govern():
    """End-to-end through the public govern() API, per #3954: a policy
    keyed on a verified identity's roles allows a match and denies a
    non-match, regardless of role order."""
    from agentmesh.governance import GovernanceDenied, govern

    policy_yaml = """
apiVersion: governance.toolkit/v1
name: deny-non-auditors
default_action: deny
rules:
  - name: allow-auditors
    condition: "caller_roles.auditor"
    action: allow
"""

    def read_doc(doc_id: str, **policy_ctx):
        return {"doc_id": doc_id}

    safe_read = govern(read_doc, policy=policy_yaml)

    auditor = ExternalIdentity(
        did_web="did:web:x",
        jwks_url=PARTNER_JWKS_URL,
        issuer_domain=PARTNER_DOMAIN,
        federation_tier="verified_partner",
        verified_at=datetime.now(timezone.utc),
        token_expires_at=datetime.now(timezone.utc),
        roles=["offline_access", "auditor"],
    )
    result = safe_read(**auditor.as_policy_kwargs(), doc_id="COMP-042")
    assert result == {"doc_id": "COMP-042"}

    engineer = ExternalIdentity(
        did_web="did:web:y",
        jwks_url=PARTNER_JWKS_URL,
        issuer_domain=PARTNER_DOMAIN,
        federation_tier="verified_partner",
        verified_at=datetime.now(timezone.utc),
        token_expires_at=datetime.now(timezone.utc),
        roles=["engineer"],
    )
    with pytest.raises(GovernanceDenied):
        safe_read(**engineer.as_policy_kwargs(), doc_id="COMP-099")


def test_as_policy_kwargs_group_paths_and_hyphenated_roles_never_match():
    """Pins the documented limit (as_policy_kwargs docstring and
    docs/identity.md): PolicyRule's bare-attribute matcher splits the
    condition on "." and requires each segment to match \\w+, so it can
    never address a Keycloak-shaped "/engineering" group path or a
    hyphenated role like "default-roles-company" - not a crash, just a
    condition that never matches. Both directions land on deny, but for
    different reasons: an allow rule against one can never match, so the
    default_action (deny here) takes over; a deny rule against one also
    can't match syntactically, but policy.py's unrecognized-condition
    fallback (see PolicyRule._eval_expression) treats that as a MATCH for
    any non-allow rule, so the deny fires anyway - fail-closed by
    construction, not because the name was actually addressed. Pinned so
    that if either mechanism regresses, this test catches it rather than
    the gap reappearing as a silent surprise."""
    from agentmesh.governance import GovernanceDenied, govern

    identity = ExternalIdentity(
        did_web="did:web:z",
        jwks_url=PARTNER_JWKS_URL,
        issuer_domain=PARTNER_DOMAIN,
        federation_tier="verified_partner",
        verified_at=datetime.now(timezone.utc),
        token_expires_at=datetime.now(timezone.utc),
        roles=["default-roles-company"],
        groups=["/engineering"],
    )
    kwargs = identity.as_policy_kwargs()
    assert kwargs["caller_groups"] == {"/engineering": True}
    assert kwargs["caller_roles"] == {"default-roles-company": True}

    def action(**policy_ctx):
        return "executed"

    allow_on_group = govern(
        action,
        policy="""
apiVersion: governance.toolkit/v1
name: allow-engineering-group
default_action: deny
rules:
  - name: allow-engineering
    condition: "caller_groups./engineering"
    action: allow
""",
    )
    # The condition can't address the "/engineering" key at all, so the
    # allow rule never fires and the deny default takes over - despite
    # the caller actually holding that group.
    with pytest.raises(GovernanceDenied):
        allow_on_group(**kwargs)

    deny_on_role = govern(
        action,
        policy="""
apiVersion: governance.toolkit/v1
name: deny-non-employee-roles
default_action: allow
rules:
  - name: deny-default-role
    condition: "caller_roles.default-roles-company"
    action: deny
""",
    )
    # Same limitation from the other side: the deny rule can't address
    # the hyphenated key either, but an unrecognized condition on a
    # non-allow rule fails closed (see policy.py's _eval_expression), so
    # the call is still denied - just not because the name was matched.
    with pytest.raises(GovernanceDenied):
        deny_on_role(**kwargs)


@pytest.mark.asyncio
async def test_docs_identity_md_oidc_example_runs_as_written():
    """Pins docs/identity.md's "OIDC for Cross-Org Identity Verification"
    example verbatim: it must actually run, not just look plausible - an
    earlier version raised TypeError (read_doc took no **kwargs) and used
    govern() without importing it."""
    from agentmesh.governance import govern

    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    token = _sign_jwt_rs256(
        private_key,
        {
            "iss": PARTNER_DOMAIN,
            "sub": "x",
            "exp": now + 900,
            "aud": "agent-mesh-service",
            "realm_access": {"roles": ["auditor"]},
        },
    )

    policy = FederationPolicy(
        trusted_endpoints=[
            TrustedEndpoint(
                domain=PARTNER_DOMAIN,
                jwks_url=PARTNER_JWKS_URL,
                trust_tier="verified_partner",
                audience="agent-mesh-service",
            ),
        ],
    )
    provider = ExternalJWKSProvider(policy=policy)
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)
    if identity is None:
        raise PermissionError("token rejected: signature, expiry, or audience check failed")

    def read_doc(doc_id: str, **policy_ctx):
        return {"doc_id": doc_id}

    policy_yaml = """
apiVersion: governance.toolkit/v1
name: allow-all
default_action: allow
rules: []
"""
    safe = govern(read_doc, policy=policy_yaml)
    result = safe(**identity.as_policy_kwargs(), doc_id="COMP-042")
    assert result == {"doc_id": "COMP-042"}


@pytest.mark.asyncio
async def test_docs_identity_md_oidc_example_raises_permission_error_on_rejection():
    """The other half of the same doc example: before the fix, a
    verification failure (here, wrong audience) meant identity was None
    and the example's later identity.as_policy_kwargs() call raised
    AttributeError on the None itself - a confusing crash instead of the
    doc's own promised PermissionError for a rejected token."""
    private_key, jwk = _make_rsa_keypair()
    now = int(time.time())
    token = _sign_jwt_rs256(
        private_key,
        {
            "iss": PARTNER_DOMAIN,
            "sub": "x",
            "exp": now + 900,
            "aud": "some-other-client",
            "realm_access": {"roles": ["auditor"]},
        },
    )

    policy = FederationPolicy(
        trusted_endpoints=[
            TrustedEndpoint(
                domain=PARTNER_DOMAIN,
                jwks_url=PARTNER_JWKS_URL,
                trust_tier="verified_partner",
                audience="agent-mesh-service",
            ),
        ],
    )
    provider = ExternalJWKSProvider(policy=policy)
    with patch.object(httpx.AsyncClient, "get", _http_mock({"keys": [jwk]})):
        identity = await provider.verify(token)

    with pytest.raises(PermissionError):
        if identity is None:
            raise PermissionError(
                "token rejected: signature, expiry, or audience check failed"
            )
