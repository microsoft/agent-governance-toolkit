# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Agent Registry."""

import os
import sys

import pytest

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.registry import AgentRegistry, RegistrationResult, PeerVerification
from nexus.reputation import ReputationEngine, ReputationHistory
from nexus.schemas.manifest import AgentManifest, AgentIdentity, AgentCapabilities, AgentPrivacy
from nexus.exceptions import (
    AgentAlreadyRegisteredError,
    AgentNotFoundError,
    InvalidManifestError,
    InvalidSignatureError,
    IATPUnverifiedPeerException,
    IATPInsufficientTrustException,
)
from nexus.crypto import generate_keypair
from tests.helpers import make_manifest, reg_sig, dereg_sig


@pytest.fixture
def registry(reputation_engine):
    return AgentRegistry(reputation_engine=reputation_engine)


class TestRegister:
    """Tests for AgentRegistry.register()."""

    @pytest.mark.asyncio
    async def test_successful_registration(self, registry, sample_manifest):
        result = await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        assert result.success is True
        assert result.agent_did == "did:nexus:test-agent-v1"
        assert result.manifest_hash
        assert result.nexus_signature
        assert result.trust_score >= 0

    @pytest.mark.asyncio
    async def test_registration_stores_manifest(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        assert registry.is_registered("did:nexus:test-agent-v1")

    @pytest.mark.asyncio
    async def test_duplicate_registration_raises(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        with pytest.raises(AgentAlreadyRegisteredError):
            await registry.register(sample_manifest, signature=reg_sig(sample_manifest))

    @pytest.mark.asyncio
    async def test_invalid_signature_raises(self, registry, sample_manifest):
        with pytest.raises(InvalidSignatureError):
            await registry.register(sample_manifest, signature="badsignature==")

    @pytest.mark.asyncio
    async def test_wrong_key_signature_raises(self, registry, sample_manifest):
        other_private_key, _ = generate_keypair()
        with pytest.raises(InvalidSignatureError):
            await registry.register(sample_manifest, signature=reg_sig(sample_manifest, other_private_key))

    @pytest.mark.asyncio
    async def test_invalid_did_format_raises(self, registry):
        with pytest.raises((InvalidManifestError, Exception)):
            manifest = AgentManifest(
                identity=AgentIdentity(
                    did="did:nexus:valid",
                    verification_key="ed25519:badkey",
                    owner_id="",
                ),
            )
            await registry.register(manifest, signature="sig_test")

    @pytest.mark.asyncio
    async def test_missing_owner_raises(self, registry):
        manifest = AgentManifest(
            identity=AgentIdentity(
                did="did:nexus:valid",
                verification_key="ed25519:key123",
                owner_id="",
            ),
        )
        with pytest.raises(InvalidManifestError):
            await registry.register(manifest, signature="sig_test")


class TestUpdate:
    """Tests for AgentRegistry.update()."""

    @pytest.mark.asyncio
    async def test_update_existing_agent(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        updated = sample_manifest.model_copy(deep=True)
        updated.capabilities.domains = ["updated-domain"]
        result = await registry.update("did:nexus:test-agent-v1", updated, reg_sig(updated))
        assert result.success is True

    @pytest.mark.asyncio
    async def test_update_nonexistent_raises(self, registry, sample_manifest):
        with pytest.raises(AgentNotFoundError):
            await registry.update("did:nexus:ghost", sample_manifest, reg_sig(sample_manifest))

    @pytest.mark.asyncio
    async def test_update_did_mismatch_raises(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        other = make_manifest(did="did:nexus:other-agent")
        with pytest.raises(InvalidManifestError):
            await registry.update("did:nexus:test-agent-v1", other, reg_sig(other))

    @pytest.mark.asyncio
    async def test_update_preserves_registration_time(self, registry, sample_manifest):
        result = await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        original_reg = result.registered_at
        updated = sample_manifest.model_copy(deep=True)
        result2 = await registry.update("did:nexus:test-agent-v1", updated, reg_sig(updated))
        assert result2.registered_at == original_reg

    @pytest.mark.asyncio
    async def test_update_wrong_signature_raises(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        updated = sample_manifest.model_copy(deep=True)
        other_private_key, _ = generate_keypair()
        with pytest.raises(InvalidSignatureError):
            await registry.update("did:nexus:test-agent-v1", updated, reg_sig(updated, other_private_key))


class TestDeregister:
    """Tests for AgentRegistry.deregister()."""

    @pytest.mark.asyncio
    async def test_deregister_removes_agent(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        result = await registry.deregister(
            "did:nexus:test-agent-v1",
            dereg_sig("did:nexus:test-agent-v1"),
        )
        assert result is True
        assert not registry.is_registered("did:nexus:test-agent-v1")

    @pytest.mark.asyncio
    async def test_deregister_nonexistent_raises(self, registry):
        with pytest.raises(AgentNotFoundError):
            await registry.deregister("did:nexus:ghost", dereg_sig("did:nexus:ghost"))

    @pytest.mark.asyncio
    async def test_deregister_wrong_signature_raises(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        other_private_key, _ = generate_keypair()
        with pytest.raises(InvalidSignatureError):
            await registry.deregister(
                "did:nexus:test-agent-v1",
                dereg_sig("did:nexus:test-agent-v1", other_private_key),
            )


class TestGetManifest:
    """Tests for AgentRegistry.get_manifest()."""

    @pytest.mark.asyncio
    async def test_get_manifest_returns_correct(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        m = await registry.get_manifest("did:nexus:test-agent-v1")
        assert m.identity.did == "did:nexus:test-agent-v1"

    @pytest.mark.asyncio
    async def test_get_manifest_not_found_raises(self, registry):
        with pytest.raises(AgentNotFoundError):
            await registry.get_manifest("did:nexus:ghost")


class TestVerifyPeer:
    """Tests for AgentRegistry.verify_peer()."""

    @pytest.mark.asyncio
    async def test_unregistered_peer_raises(self, registry):
        with pytest.raises(IATPUnverifiedPeerException):
            await registry.verify_peer("did:nexus:unknown-agent")

    @pytest.mark.asyncio
    async def test_low_trust_peer_raises(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        with pytest.raises(IATPInsufficientTrustException):
            await registry.verify_peer("did:nexus:test-agent-v1", min_score=900)

    @pytest.mark.asyncio
    async def test_verified_peer(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        result = await registry.verify_peer("did:nexus:test-agent-v1", min_score=1)
        assert result.verified is True
        assert result.peer_did == "did:nexus:test-agent-v1"
        assert result.trust_score >= 0

    @pytest.mark.asyncio
    async def test_missing_capabilities_not_verified(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        result = await registry.verify_peer(
            "did:nexus:test-agent-v1", min_score=1,
            required_capabilities=["nonexistent-domain"],
        )
        assert result.verified is False
        assert "Missing capabilities" in result.rejection_reason


class TestDiscoverAgents:
    """Tests for AgentRegistry.discover_agents()."""

    @pytest.mark.asyncio
    async def test_discover_by_capability(self, registry):
        m1 = make_manifest(did="did:nexus:agent-a", domains=["code-gen"])
        m2 = make_manifest(did="did:nexus:agent-b", domains=["data-analysis"])
        await registry.register(m1, reg_sig(m1))
        await registry.register(m2, reg_sig(m2))
        results = await registry.discover_agents(capabilities=["code-gen"], min_score=1)
        assert len(results) == 1
        assert results[0].identity.did == "did:nexus:agent-a"

    @pytest.mark.asyncio
    async def test_discover_by_min_score(self, registry):
        m1 = make_manifest(did="did:nexus:agent-a", verification_level="verified_partner")
        m2 = make_manifest(did="did:nexus:agent-b", verification_level="unknown")
        await registry.register(m1, reg_sig(m1))
        await registry.register(m2, reg_sig(m2))
        results = await registry.discover_agents(min_score=500)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_discover_limit(self, registry):
        for i in range(5):
            m = make_manifest(did=f"did:nexus:agent-{i}")
            await registry.register(m, reg_sig(m))
        results = await registry.discover_agents(min_score=1, limit=3)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_discover_by_privacy_policy(self, registry):
        m1 = make_manifest(did="did:nexus:agent-a", retention_policy="ephemeral")
        m2 = make_manifest(did="did:nexus:agent-b", retention_policy="permanent")
        await registry.register(m1, reg_sig(m1))
        await registry.register(m2, reg_sig(m2))
        results = await registry.discover_agents(privacy_policy="ephemeral", min_score=1)
        assert len(results) == 1


class TestRegistryHelpers:
    """Tests for is_registered() and get_agent_count()."""

    @pytest.mark.asyncio
    async def test_is_registered_false(self, registry):
        assert registry.is_registered("did:nexus:ghost") is False

    @pytest.mark.asyncio
    async def test_get_agent_count_empty(self, registry):
        assert registry.get_agent_count() == 0

    @pytest.mark.asyncio
    async def test_get_agent_count_after_register(self, registry, sample_manifest):
        await registry.register(sample_manifest, signature=reg_sig(sample_manifest))
        assert registry.get_agent_count() == 1
