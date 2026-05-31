# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for the Phase 6.c relay Entra-JWT verifier.

These tests exercise the configuration boundary + claim-validation
logic without an Entra round-trip. The JWKS HTTP layer is faked by
seeding the verifier's internal PyJWKClient with an in-process RSA
keypair via attribute injection. Production code paths that touch
``PyJWKClient`` itself are unchanged.
"""

from __future__ import annotations

import time
from typing import Iterator
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agentmesh.identity import entra_verifier
from agentmesh.identity.entra_verifier import (
    EntraTokenError,
    EntraTokenVerifier,
    EntraVerifierConfig,
)


VALID_AUDIENCE = "api://agentmesh"
VALID_TENANT = "11111111-2222-3333-4444-555555555555"
VALID_APPID = "abcdef01-2345-6789-abcd-ef0123456789"


@pytest.fixture(autouse=True)
def _reset_singleton() -> Iterator[None]:
    """Prevent process-singleton leakage across tests."""
    entra_verifier.reset_verifier_for_tests()
    yield
    entra_verifier.reset_verifier_for_tests()


@pytest.fixture
def rsa_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _sign_token(key: rsa.RSAPrivateKey, claims: dict) -> str:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="RS256")


def _good_claims(now: int | None = None) -> dict:
    now = now or int(time.time())
    return {
        "aud": VALID_AUDIENCE,
        "tid": VALID_TENANT,
        "iss": f"https://login.microsoftonline.com/{VALID_TENANT}/v2.0",
        "appid": VALID_APPID,
        "iat": now,
        "exp": now + 3600,
    }


def _build_verifier(rsa_keypair: rsa.RSAPrivateKey) -> EntraTokenVerifier:
    cfg = EntraVerifierConfig(
        audience=VALID_AUDIENCE,
        tenant_id=VALID_TENANT,
        authority="https://login.microsoftonline.com",
        jwks_ttl_secs=3600,
        jwks_max_stale_secs=86400,
    )
    verifier = EntraTokenVerifier(cfg)

    # In-test JWKS shim: pretend the JWKS endpoint already returned
    # our keypair. The verifier asks PyJWKClient for the signing key;
    # we stub the resolver to hand back our RSA public key wrapped in
    # the shape PyJWKClient.get_signing_key_from_jwt returns.
    class _StubSigningKey:
        def __init__(self, key: rsa.RSAPublicKey) -> None:
            self.key = key

    class _StubClient:
        def __init__(self, public_key: rsa.RSAPublicKey) -> None:
            self._pub = public_key

        def get_signing_key_from_jwt(self, _token: str) -> _StubSigningKey:
            return _StubSigningKey(self._pub)

        def get_signing_keys(self) -> list:
            return [_StubSigningKey(self._pub)]

    verifier._jwk_client = _StubClient(rsa_keypair.public_key())  # type: ignore[assignment]
    verifier._jwk_cached_at = time.monotonic()
    return verifier


# ── Config tests ────────────────────────────────────────────────────


class TestConfig:
    def test_from_env_returns_none_when_both_unset(self, monkeypatch):
        monkeypatch.delenv("AGENTMESH_ENTRA_AUDIENCE", raising=False)
        monkeypatch.delenv("AGENTMESH_ENTRA_TENANT_ID", raising=False)
        assert EntraVerifierConfig.from_env() is None

    def test_from_env_refuses_half_configured(self, monkeypatch):
        # Only audience set → operator misconfiguration. Refuse rather
        # than silently running without tenant pinning.
        monkeypatch.setenv("AGENTMESH_ENTRA_AUDIENCE", VALID_AUDIENCE)
        monkeypatch.delenv("AGENTMESH_ENTRA_TENANT_ID", raising=False)
        assert EntraVerifierConfig.from_env() is None

    def test_from_env_populated(self, monkeypatch):
        monkeypatch.setenv("AGENTMESH_ENTRA_AUDIENCE", VALID_AUDIENCE)
        monkeypatch.setenv("AGENTMESH_ENTRA_TENANT_ID", VALID_TENANT)
        monkeypatch.delenv("AGENTMESH_ENTRA_AUTHORITY", raising=False)
        cfg = EntraVerifierConfig.from_env()
        assert cfg is not None
        assert cfg.audience == VALID_AUDIENCE
        assert cfg.tenant_id == VALID_TENANT
        assert cfg.authority == "https://login.microsoftonline.com"
        assert cfg.jwks_url.endswith(f"/{VALID_TENANT}/discovery/v2.0/keys")

    def test_jwks_ttl_floor_at_60s(self, monkeypatch):
        monkeypatch.setenv("AGENTMESH_ENTRA_AUDIENCE", VALID_AUDIENCE)
        monkeypatch.setenv("AGENTMESH_ENTRA_TENANT_ID", VALID_TENANT)
        monkeypatch.setenv("AGENTMESH_ENTRA_JWKS_TTL_SECS", "10")
        cfg = EntraVerifierConfig.from_env()
        assert cfg is not None
        assert cfg.jwks_ttl_secs == 60

    def test_jwks_ttl_falls_back_to_default_on_garbage(self, monkeypatch):
        monkeypatch.setenv("AGENTMESH_ENTRA_AUDIENCE", VALID_AUDIENCE)
        monkeypatch.setenv("AGENTMESH_ENTRA_TENANT_ID", VALID_TENANT)
        monkeypatch.setenv("AGENTMESH_ENTRA_JWKS_TTL_SECS", "not-an-int")
        cfg = EntraVerifierConfig.from_env()
        assert cfg is not None
        assert cfg.jwks_ttl_secs == 3600


# ── Verification tests ──────────────────────────────────────────────


class TestVerify:
    @pytest.mark.asyncio
    async def test_good_token_returns_claims(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        token = _sign_token(rsa_keypair, _good_claims())
        claims = await v.verify(token)
        assert claims["appid"] == VALID_APPID

    @pytest.mark.asyncio
    async def test_wrong_audience_rejected(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        claims = _good_claims()
        claims["aud"] = "api://attacker"
        token = _sign_token(rsa_keypair, claims)
        with pytest.raises(EntraTokenError):
            await v.verify(token)

    @pytest.mark.asyncio
    async def test_wrong_tenant_rejected(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        claims = _good_claims()
        claims["tid"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        token = _sign_token(rsa_keypair, claims)
        with pytest.raises(EntraTokenError) as ei:
            await v.verify(token)
        assert "tid claim" in str(ei.value)

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        past = int(time.time()) - 7200
        token = _sign_token(rsa_keypair, _good_claims(now=past))
        with pytest.raises(EntraTokenError):
            await v.verify(token)

    @pytest.mark.asyncio
    async def test_missing_tid_rejected(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        claims = _good_claims()
        del claims["tid"]
        token = _sign_token(rsa_keypair, claims)
        with pytest.raises(EntraTokenError):
            await v.verify(token)

    @pytest.mark.asyncio
    async def test_wrong_signing_key_rejected(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = _sign_token(other, _good_claims())
        with pytest.raises(EntraTokenError):
            await v.verify(token)

    @pytest.mark.asyncio
    async def test_empty_token_rejected(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        with pytest.raises(EntraTokenError):
            await v.verify("")

    @pytest.mark.asyncio
    async def test_azp_falls_back_when_appid_absent(self, rsa_keypair):
        # Real Entra tokens carry appid; v2.0 tokens use azp. The
        # relay's connect-handler extracts whichever exists.
        v = _build_verifier(rsa_keypair)
        claims = _good_claims()
        del claims["appid"]
        claims["azp"] = "00000000-1111-2222-3333-444444444444"
        token = _sign_token(rsa_keypair, claims)
        out = await v.verify(token)
        assert out.get("azp") == "00000000-1111-2222-3333-444444444444"

    @pytest.mark.asyncio
    async def test_oversized_token_rejected(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        with pytest.raises(EntraTokenError, match="maximum length"):
            await v.verify("x" * 16385)

    @pytest.mark.asyncio
    async def test_wrong_issuer_rejected(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        claims = _good_claims()
        claims["iss"] = "https://evil.example.com/v2.0"
        token = _sign_token(rsa_keypair, claims)
        with pytest.raises(EntraTokenError):
            await v.verify(token)


# ── PR #2659 review fixes: stale-JWKS hard ceiling + alg-confusion guard ──


class TestAlgConfusionGuard:
    """The `alg` header is validated against ALLOWED_SIGNING_ALGORITHMS
    BEFORE the JWKS lookup, so an attacker that smuggles `alg: HS256`
    can't trick PyJWT into using the JWK's public-key bytes as an HMAC
    secret. PyJWT's own algorithms-allowlist also blocks this; the
    pre-check is defense-in-depth that also avoids a wasted network
    round-trip on obviously-bad tokens.
    """

    @pytest.mark.asyncio
    async def test_hs256_token_rejected_before_jwks_lookup(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        # Hand-craft an HS256 header + good claims body. PyJWT itself
        # refuses to encode HS256 with a PEM-shaped key, so the
        # attacker would similarly assemble the token bytes manually
        # — that's the threat model we defend against.
        import base64, hmac, hashlib, json
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps(_good_claims()).encode()
        ).rstrip(b"=").decode()
        pub_pem = rsa_keypair.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sig = hmac.new(pub_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        token = f"{header}.{payload}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
        # Track whether the JWKS resolver was called — it must NOT be.
        called: list[str] = []
        original = v._jwk_client.get_signing_key_from_jwt  # type: ignore[attr-defined]
        def _trip(token_: str):
            called.append(token_)
            return original(token_)
        v._jwk_client.get_signing_key_from_jwt = _trip  # type: ignore[attr-defined]
        with pytest.raises(EntraTokenError, match="unsupported alg"):
            await v.verify(token)
        assert called == [], "JWKS lookup must not be reached for unsupported alg"

    @pytest.mark.asyncio
    async def test_none_alg_token_rejected_before_jwks_lookup(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        # alg=none — historic PyJWT CVE-2022-29217 class.
        token = jwt.encode(_good_claims(), key="", algorithm="none")
        with pytest.raises(EntraTokenError, match="unsupported alg"):
            await v.verify(token)

    @pytest.mark.asyncio
    async def test_missing_alg_header_rejected(self, rsa_keypair):
        v = _build_verifier(rsa_keypair)
        # Hand-craft a token with no alg header.
        import base64, json
        header = base64.urlsafe_b64encode(b'{}').rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(
            json.dumps(_good_claims()).encode()
        ).rstrip(b'=').decode()
        token = f"{header}.{payload}."
        with pytest.raises(EntraTokenError):
            await v.verify(token)


class TestJwksStaleCeiling:
    """Stale cache must serve verify requests within a bounded window
    when JWKS refetch fails (availability over consistency), but MUST
    fail closed beyond that window to bound how long a key rotated
    OUT of the live JWKS remains usable.
    """

    def test_max_stale_floors_at_ttl(self, monkeypatch):
        # Even if operator sets max_stale < ttl, the floor protects
        # the invariant "stale > fresh always".
        monkeypatch.setenv("AGENTMESH_ENTRA_AUDIENCE", VALID_AUDIENCE)
        monkeypatch.setenv("AGENTMESH_ENTRA_TENANT_ID", VALID_TENANT)
        monkeypatch.setenv("AGENTMESH_ENTRA_JWKS_TTL_SECS", "3600")
        monkeypatch.setenv("AGENTMESH_ENTRA_JWKS_MAX_STALE_SECS", "60")
        cfg = EntraVerifierConfig.from_env()
        assert cfg is not None
        assert cfg.jwks_max_stale_secs >= cfg.jwks_ttl_secs

    def test_max_stale_default_24h(self, monkeypatch):
        monkeypatch.setenv("AGENTMESH_ENTRA_AUDIENCE", VALID_AUDIENCE)
        monkeypatch.setenv("AGENTMESH_ENTRA_TENANT_ID", VALID_TENANT)
        monkeypatch.delenv("AGENTMESH_ENTRA_JWKS_MAX_STALE_SECS", raising=False)
        cfg = EntraVerifierConfig.from_env()
        assert cfg is not None
        assert cfg.jwks_max_stale_secs == 86400

    @pytest.mark.asyncio
    async def test_stale_serve_within_budget(self, rsa_keypair):
        # Cache aged 1h with a 24h ceiling — refetch failure should
        # serve from stale cache, NOT fail closed.
        import httpx
        v = _build_verifier(rsa_keypair)
        # Pretend the cache is 1h old (well within 24h budget).
        v._jwk_cached_at = time.monotonic() - 3700  # 1h + 100s (past ttl)
        # Force the refresh path to throw.
        original_client_ctor = entra_verifier.PyJWKClient
        def _explode(*args, **kwargs):
            raise httpx.ConnectError("egress outage")
        with patch.object(entra_verifier, "PyJWKClient", _explode):
            # Should NOT raise — stale cache still in budget.
            client = await v._ensure_jwk_client()
            assert client is not None

    @pytest.mark.asyncio
    async def test_stale_serve_beyond_budget_fails_closed(self, rsa_keypair):
        import httpx
        v = _build_verifier(rsa_keypair)
        # Pretend the cache is 25h old — past the 24h ceiling.
        v._jwk_cached_at = time.monotonic() - (25 * 3600)
        def _explode(*args, **kwargs):
            raise httpx.ConnectError("egress outage")
        with patch.object(entra_verifier, "PyJWKClient", _explode):
            with pytest.raises(EntraTokenError, match="unable to fetch Entra JWKS"):
                await v._ensure_jwk_client()
        # Stale client must be dropped so future calls don't reuse it.
        assert v._jwk_client is None
