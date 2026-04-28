# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AVPProvider."""

import pytest
import httpx
import respx

from agentmesh_avp.provider import AVPProvider, _is_valid_did

BASE = "https://agentveil.dev"
# Valid did:key format: z6Mk + 43 base58btc chars
TEST_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
TEST_NAME = "test_agent"


@pytest.fixture
def provider():
    return AVPProvider(base_url=BASE, min_score_threshold=0.3)


@pytest.fixture
def provider_with_resolvers():
    return AVPProvider(
        base_url=BASE,
        did_resolver=lambda aid: TEST_DID if aid == "lookup_me" else None,
        name_resolver=lambda aid: aid.split(":")[-1] if ":" in aid else aid,
    )


class TestDIDValidation:
    def test_valid_did(self):
        assert _is_valid_did(TEST_DID) is True

    def test_rejects_short_did(self):
        assert _is_valid_did("did:key:z6MkTooShort") is False

    def test_rejects_wrong_prefix(self):
        assert _is_valid_did("did:web:example.com") is False

    def test_rejects_empty(self):
        assert _is_valid_did("") is False

    def test_rejects_plain_string(self):
        assert _is_valid_did("not-a-did") is False


class TestGetTrustScore:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_score(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json={
                "did": TEST_DID,
                "score": 0.75,
                "confidence": 0.5,
            })
        )
        score = await provider.get_trust_score(TEST_DID)
        assert score == 0.75

    @respx.mock
    @pytest.mark.asyncio
    async def test_clamps_to_1(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json={"score": 1.5})
        )
        score = await provider.get_trust_score(TEST_DID)
        assert score == 1.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_clamps_to_0(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json={"score": -0.5})
        )
        score = await provider.get_trust_score(TEST_DID)
        assert score == 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_0_on_404(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(404)
        )
        score = await provider.get_trust_score(TEST_DID)
        assert score == 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_0_on_timeout(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            side_effect=httpx.ReadTimeout("timeout")
        )
        score = await provider.get_trust_score(TEST_DID)
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_returns_0_for_invalid_did(self, provider):
        score = await provider.get_trust_score("not-a-did")
        assert score == 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_did_resolver(self, provider_with_resolvers):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json={"score": 0.6})
        )
        score = await provider_with_resolvers.get_trust_score("lookup_me")
        assert score == 0.6

    @pytest.mark.asyncio
    async def test_resolver_returns_invalid_did(self, provider_with_resolvers):
        """Resolver returns None for unknown agent, score should be 0."""
        score = await provider_with_resolvers.get_trust_score("unknown_agent")
        assert score == 0.0


class TestGetReputation:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_full_profile(self, provider):
        profile = {
            "did": TEST_DID,
            "score": 0.85,
            "confidence": 0.7,
            "flow_score": 1.0,
            "risk_score": 0.0,
            "risk_factors": [],
            "algorithm_ver": "eigentrust_v1",
            "attestation_count": 12,
            "unique_attesters": 8,
        }
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json=profile)
        )
        result = await provider.get_reputation(TEST_DID)
        assert result["score"] == 0.85
        assert result["attestation_count"] == 12
        assert result["algorithm_ver"] == "eigentrust_v1"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_on_error(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(500)
        )
        result = await provider.get_reputation(TEST_DID)
        assert result == {}

    @pytest.mark.asyncio
    async def test_returns_empty_for_invalid_did(self, provider):
        result = await provider.get_reputation("not-a-did")
        assert result == {}


class TestVerifyIdentity:
    @respx.mock
    @pytest.mark.asyncio
    async def test_verified_agent(self, provider):
        respx.get(f"{BASE}/v1/agents/verify/{TEST_NAME}").mock(
            return_value=httpx.Response(200, json={
                "verified": True,
                "agent_name": TEST_NAME,
                "did": TEST_DID,
                "score": 0.8,
                "tier": "trusted",
            })
        )
        result = await provider.verify_identity(TEST_NAME, {})
        assert result is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_unverified_agent(self, provider):
        respx.get(f"{BASE}/v1/agents/verify/{TEST_NAME}").mock(
            return_value=httpx.Response(200, json={
                "verified": False,
                "agent_name": TEST_NAME,
            })
        )
        result = await provider.verify_identity(TEST_NAME, {})
        assert result is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_fallback_to_score_on_http_error(self, provider):
        """When verify endpoint fails, falls back to score-based check."""
        respx.get(f"{BASE}/v1/agents/verify/{TEST_DID}").mock(
            return_value=httpx.Response(500)
        )
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json={"score": 0.5})
        )
        result = await provider.verify_identity(TEST_DID, {})
        assert result is True  # 0.5 >= 0.3 threshold

    @respx.mock
    @pytest.mark.asyncio
    async def test_fallback_fails_below_threshold(self, provider):
        respx.get(f"{BASE}/v1/agents/verify/{TEST_DID}").mock(
            return_value=httpx.Response(500)
        )
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json={"score": 0.1})
        )
        result = await provider.verify_identity(TEST_DID, {})
        assert result is False  # 0.1 < 0.3 threshold


class TestPathInjection:
    """Tests for URL path injection prevention."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_name_with_path_traversal(self, provider):
        """Name containing ../ must be URL-encoded, not passed raw."""
        malicious = "../../admin"
        # quote("../../admin", safe="") → "..%2F..%2Fadmin"
        from urllib.parse import quote
        encoded = quote(malicious, safe="")
        respx.get(f"{BASE}/v1/agents/verify/{encoded}").mock(
            return_value=httpx.Response(200, json={"verified": False})
        )
        result = await provider.verify_identity(malicious, {})
        assert result is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_name_with_slashes(self, provider):
        """Slashes in name must not create new URL path segments."""
        from urllib.parse import quote
        name = "agent/../../secret"
        encoded = quote(name, safe="")
        respx.get(f"{BASE}/v1/agents/verify/{encoded}").mock(
            return_value=httpx.Response(200, json={"verified": False})
        )
        result = await provider.verify_identity(name, {})
        assert result is False


class TestMalformedResponses:
    """Tests for malformed or malicious API responses."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_score_missing_from_response(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json={"did": TEST_DID})
        )
        score = await provider.get_trust_score(TEST_DID)
        assert score == 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_score_is_string(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json={"score": "not_a_number"})
        )
        score = await provider.get_trust_score(TEST_DID)
        assert score == 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_response_is_list_not_dict(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json=[1, 2, 3])
        )
        score = await provider.get_trust_score(TEST_DID)
        assert score == 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_response_is_null(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json=None)
        )
        score = await provider.get_trust_score(TEST_DID)
        assert score == 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_reputation_returns_empty_on_list_response(self, provider):
        respx.get(f"{BASE}/v1/reputation/{TEST_DID}").mock(
            return_value=httpx.Response(200, json=[{"score": 0.5}])
        )
        result = await provider.get_reputation(TEST_DID)
        assert result == {}

    @respx.mock
    @pytest.mark.asyncio
    async def test_verify_returns_false_on_list_response(self, provider):
        respx.get(f"{BASE}/v1/agents/verify/{TEST_NAME}").mock(
            return_value=httpx.Response(200, json=[{"verified": True}])
        )
        result = await provider.verify_identity(TEST_NAME, {})
        assert result is False


class TestClose:
    @pytest.mark.asyncio
    async def test_close(self, provider):
        await provider.close()
        assert provider._client.is_closed
