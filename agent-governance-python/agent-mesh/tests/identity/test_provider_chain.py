# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agentmesh.identity.provider_chain — ADR-0007 chain abstraction."""

from __future__ import annotations

import pytest
from typing import Optional
from unittest.mock import MagicMock, AsyncMock

from agentmesh.identity.provider_chain import (
    IdentityProvider,
    IdentityProviderChain,
    IdentityResult,
    LocalRegistryProvider,
    ExternalJWKSProviderAdapter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _StubProvider(IdentityProvider):
    """Provider that returns a fixed result for a given DID prefix."""

    def __init__(self, prefix: str, result: Optional[IdentityResult]):
        self._prefix = prefix
        self._result = result

    @property
    def name(self) -> str:
        return f"stub-{self._prefix}"

    async def resolve(self, peer_did: str) -> Optional[IdentityResult]:
        if peer_did.startswith(self._prefix):
            return self._result
        return None


class _FailingProvider(IdentityProvider):
    """Provider that always raises so we can test error handling."""

    @property
    def name(self) -> str:
        return "failing"

    async def resolve(self, peer_did: str) -> Optional[IdentityResult]:
        raise RuntimeError("boom")


# ---------------------------------------------------------------------------
# IdentityResult
# ---------------------------------------------------------------------------

def test_identity_result_defaults():
    r = IdentityResult(peer_did="did:mesh:abc", public_key="pk")
    assert r.trust_score == 0
    assert r.capabilities == []
    assert r.is_active is True
    assert r.external_identity is None


# ---------------------------------------------------------------------------
# IdentityProviderChain
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_returns_first_hit():
    hit = IdentityResult(peer_did="did:mesh:aaa", public_key="k1", provider_name="a")
    chain = IdentityProviderChain()
    chain.add(_StubProvider("did:mesh:", hit))
    chain.add(_StubProvider("did:mesh:", IdentityResult(peer_did="did:mesh:bbb", public_key="k2")))

    result = await chain.resolve("did:mesh:aaa")
    assert result is not None
    assert result.peer_did == "did:mesh:aaa"


@pytest.mark.asyncio
async def test_chain_skips_miss():
    hit = IdentityResult(peer_did="did:web:x", public_key="k")
    chain = IdentityProviderChain()
    chain.add(_StubProvider("did:mesh:", None))
    chain.add(_StubProvider("did:web:", hit))

    result = await chain.resolve("did:web:x")
    assert result is not None
    assert result.peer_did == "did:web:x"


@pytest.mark.asyncio
async def test_chain_returns_none_when_no_provider_matches():
    chain = IdentityProviderChain()
    chain.add(_StubProvider("did:mesh:", IdentityResult(peer_did="x", public_key="k")))

    result = await chain.resolve("did:web:unknown")
    assert result is None


@pytest.mark.asyncio
async def test_chain_skips_failing_provider():
    hit = IdentityResult(peer_did="did:mesh:ok", public_key="k", provider_name="stub")
    chain = IdentityProviderChain()
    chain.add(_FailingProvider())
    chain.add(_StubProvider("did:mesh:", hit))

    result = await chain.resolve("did:mesh:ok")
    assert result is not None
    assert result.provider_name == "stub"


@pytest.mark.asyncio
async def test_empty_chain_returns_none():
    chain = IdentityProviderChain()
    assert await chain.resolve("did:mesh:anything") is None


def test_chain_add_returns_self():
    chain = IdentityProviderChain()
    returned = chain.add(_StubProvider("x", None))
    assert returned is chain


def test_providers_property_is_copy():
    chain = IdentityProviderChain()
    p = _StubProvider("x", None)
    chain.add(p)
    providers = chain.providers
    assert len(providers) == 1
    providers.clear()
    assert len(chain.providers) == 1  # original unchanged


# ---------------------------------------------------------------------------
# LocalRegistryProvider
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_local_registry_provider_hit():
    mock_identity = MagicMock()
    mock_identity.public_key = "pk123"
    mock_identity.capabilities = ["read", "write"]
    mock_identity.is_active.return_value = True

    registry = MagicMock()
    registry.get.return_value = mock_identity

    provider = LocalRegistryProvider(registry)
    result = await provider.resolve("did:mesh:abc123")

    assert result is not None
    assert result.public_key == "pk123"
    assert result.capabilities == ["read", "write"]
    assert result.provider_name == "local-registry"


@pytest.mark.asyncio
async def test_local_registry_provider_miss():
    registry = MagicMock()
    registry.get.return_value = None

    provider = LocalRegistryProvider(registry)
    result = await provider.resolve("did:mesh:unknown")
    assert result is None


@pytest.mark.asyncio
async def test_local_registry_provider_ignores_non_mesh():
    registry = MagicMock()
    provider = LocalRegistryProvider(registry)
    result = await provider.resolve("did:web:example.com")
    assert result is None
    registry.get.assert_not_called()


# ---------------------------------------------------------------------------
# ExternalJWKSProviderAdapter
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_external_jwks_adapter_ignores_non_web():
    adapter = ExternalJWKSProviderAdapter(MagicMock())
    result = await adapter.resolve("did:mesh:abc")
    assert result is None


@pytest.mark.asyncio
async def test_external_jwks_adapter_returns_none_without_token():
    adapter = ExternalJWKSProviderAdapter(MagicMock())
    result = await adapter.resolve("did:web:example.com:agent:1")
    assert result is None


@pytest.mark.asyncio
async def test_external_jwks_adapter_delegates_with_token():
    mock_ext_id = MagicMock()
    mock_ext_id.did_web = "did:web:partner.com:agent:xyz"
    mock_ext_id.delegation_claims.authority_scope = ["read"]

    mock_provider = MagicMock()
    mock_provider.verify = AsyncMock(return_value=mock_ext_id)

    adapter = ExternalJWKSProviderAdapter(mock_provider)
    adapter.set_pending_token("jwt.token.here")

    result = await adapter.resolve("did:web:partner.com:agent:xyz")
    assert result is not None
    assert result.peer_did == "did:web:partner.com:agent:xyz"
    assert result.external_identity is mock_ext_id
    assert result.provider_name == "external-jwks"


@pytest.mark.asyncio
async def test_external_jwks_adapter_clears_token_after_use():
    mock_provider = MagicMock()
    mock_provider.verify = AsyncMock(return_value=None)

    adapter = ExternalJWKSProviderAdapter(mock_provider)
    adapter.set_pending_token("tok")

    # First call uses the token
    await adapter.resolve("did:web:x")
    # Second call has no token
    result = await adapter.resolve("did:web:x")
    assert result is None


# ---------------------------------------------------------------------------
# HandshakeResult.external_identity field
# ---------------------------------------------------------------------------

def test_handshake_result_external_identity_default():
    from agentmesh.trust.handshake import HandshakeResult

    result = HandshakeResult(
        verified=True,
        peer_did="did:mesh:test",
    )
    assert result.external_identity is None


def test_handshake_result_success_with_external_identity():
    from agentmesh.trust.handshake import HandshakeResult

    ext_id = {"did_web": "did:web:example.com:agent:1", "issuer": "example.com"}
    result = HandshakeResult.success(
        peer_did="did:web:example.com:agent:1",
        trust_score=700,
        capabilities=["read"],
        external_identity=ext_id,
    )
    assert result.external_identity is ext_id
    assert result.verified is True
    assert result.trust_level == "trusted"
