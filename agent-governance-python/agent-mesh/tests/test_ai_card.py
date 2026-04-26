# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for AI Card integration.

Covers: schema models, identity mapping, card signing/verification,
JSON serialization, discovery catalog, and TrustedAgentCard bridging.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.integrations.ai_card.schema import (
    AICard,
    AICardIdentity,
    AICardService,
    AICardSignature,
    AICardVerifiable,
    CapabilityAttestation,
    DelegationRecord,
)
from agentmesh.integrations.ai_card.discovery import AICardDiscovery


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def identity():
    """Create a test AgentIdentity with private key."""
    return AgentIdentity.create(
        name="test-agent",
        sponsor="sponsor@example.com",
        capabilities=["read:data", "write:logs"],
        description="A test agent",
    )


@pytest.fixture
def identity_b():
    """Create a second test AgentIdentity."""
    return AgentIdentity.create(
        name="peer-agent",
        sponsor="peer@example.com",
        capabilities=["execute:sql"],
    )


@pytest.fixture
def signed_card(identity):
    """Create a signed AI Card."""
    return AICard.from_identity(identity, description="Test agent card")


# ── Schema Tests ──────────────────────────────────────────────


class TestAICardSchema:
    """Test AI Card schema model creation."""

    def test_create_minimal_card(self):
        card = AICard(name="minimal-agent")
        assert card.name == "minimal-agent"
        assert card.description == ""
        assert card.version == "1.0.0"
        assert card.identity is None
        assert card.services == []
        assert card.card_signature is None

    def test_create_full_card(self):
        card = AICard(
            name="full-agent",
            description="Full agent",
            version="2.0.0",
            homepage="https://example.com",
            identity=AICardIdentity(
                did="did:mesh:abc123",
                public_key="dGVzdA==",
            ),
            services=[
                AICardService(protocol="a2a", url="https://agent.example.com/a2a"),
                AICardService(protocol="mcp", url="https://agent.example.com/mcp", metadata={"tools": ["search"]}),
            ],
            custom={"org": "test-org"},
        )
        assert card.name == "full-agent"
        assert card.identity.did == "did:mesh:abc123"
        assert len(card.services) == 2
        assert card.services[0].protocol == "a2a"
        assert card.services[1].metadata["tools"] == ["search"]
        assert card.custom["org"] == "test-org"

    def test_identity_model(self):
        ident = AICardIdentity(
            did="did:mesh:abc",
            public_key="key123",
            algorithm="Ed25519",
            key_id="key-001",
        )
        assert ident.did == "did:mesh:abc"
        assert ident.algorithm == "Ed25519"
        assert ident.key_id == "key-001"

    def test_capability_attestation(self):
        att = CapabilityAttestation(
            capability="read:data",
            proof="proof-bytes",
            issuer_did="did:mesh:issuer",
        )
        assert att.capability == "read:data"
        assert att.expires_at is None

    def test_delegation_record(self):
        rec = DelegationRecord(
            delegator_did="did:mesh:root",
            delegatee_did="did:mesh:agent",
            capabilities=["read:data"],
            signature="sig-bytes",
        )
        assert rec.delegator_did == "did:mesh:root"
        assert rec.capabilities == ["read:data"]


# ── Identity Mapping Tests ────────────────────────────────────


class TestIdentityMapping:
    """Test mapping AgentIdentity to AI Card format."""

    def test_from_identity_sets_identity(self, identity):
        card = AICard.from_identity(identity)
        assert card.identity is not None
        assert card.identity.did == str(identity.did)
        assert card.identity.public_key == identity.public_key
        assert card.identity.algorithm == "Ed25519"

    def test_from_identity_preserves_name(self, identity):
        card = AICard.from_identity(identity)
        assert card.name == identity.name

    def test_from_identity_preserves_capabilities(self, identity):
        card = AICard.from_identity(identity)
        assert "read:data" in card.verifiable.capability_attestations
        assert "write:logs" in card.verifiable.capability_attestations

    def test_from_identity_with_description(self, identity):
        card = AICard.from_identity(identity, description="Custom desc")
        assert card.description == "Custom desc"

    def test_from_identity_with_services(self, identity):
        services = [AICardService(protocol="a2a", url="https://example.com/a2a")]
        card = AICard.from_identity(identity, services=services)
        assert len(card.services) == 1
        assert card.services[0].protocol == "a2a"

    def test_key_id_from_identity(self, identity):
        card = AICard.from_identity(identity)
        assert card.identity.key_id == identity.verification_key_id


# ── Card Signing Tests ────────────────────────────────────────


class TestCardSigning:
    """Test cryptographic card signing and verification."""

    def test_sign_sets_signature(self, identity):
        card = AICard(name="test")
        card.sign(identity)
        assert card.card_signature is not None
        assert card.card_signature.signature != ""
        assert card.card_signature.public_key == identity.public_key

    def test_signed_card_verifies(self, signed_card):
        assert signed_card.verify_signature() is True

    def test_tampered_card_fails_verification(self, signed_card):
        signed_card.name = "tampered-name"
        assert signed_card.verify_signature() is False

    def test_unsigned_card_fails_verification(self):
        card = AICard(name="unsigned")
        assert card.verify_signature() is False

    def test_card_without_identity_fails_verification(self):
        card = AICard(
            name="no-identity",
            card_signature=AICardSignature(
                public_key="fake",
                signature="fake",
            ),
        )
        assert card.verify_signature() is False

    def test_sign_rejects_non_identity(self):
        card = AICard(name="test")
        with pytest.raises(TypeError):
            card.sign("not-an-identity")

    def test_from_identity_produces_valid_signature(self, identity):
        card = AICard.from_identity(identity)
        assert card.verify_signature() is True


# ── JSON Serialization Tests ──────────────────────────────────


class TestJSONSerialization:
    """Test AI Card JSON serialization and deserialization."""

    def test_roundtrip_minimal(self):
        card = AICard(name="roundtrip-agent")
        json_str = card.to_json()
        restored = AICard.from_json(json_str)
        assert restored.name == "roundtrip-agent"

    def test_roundtrip_signed_card(self, signed_card):
        json_str = signed_card.to_json()
        restored = AICard.from_json(json_str)
        assert restored.name == signed_card.name
        assert restored.identity.did == signed_card.identity.did
        assert restored.identity.public_key == signed_card.identity.public_key
        assert restored.card_signature.signature == signed_card.card_signature.signature

    def test_roundtrip_with_services(self, identity):
        services = [
            AICardService(protocol="a2a", url="https://a2a.example.com", metadata={"skills": ["search"]}),
            AICardService(protocol="mcp", url="https://mcp.example.com"),
        ]
        card = AICard.from_identity(identity, services=services)
        json_str = card.to_json()
        restored = AICard.from_json(json_str)
        assert len(restored.services) == 2
        assert restored.services[0].protocol == "a2a"
        assert restored.services[0].metadata["skills"] == ["search"]

    def test_roundtrip_with_delegation(self, identity, identity_b):
        card = AICard.from_identity(identity)
        delegation_data = f"{identity.did}:{identity_b.did}:read:data"
        sig = identity.sign(delegation_data.encode())
        card.verifiable.scope_chain.append(
            DelegationRecord(
                delegator_did=str(identity.did),
                delegatee_did=str(identity_b.did),
                capabilities=["read:data"],
                signature=sig,
            )
        )
        json_str = card.to_json()
        restored = AICard.from_json(json_str)
        assert len(restored.verifiable.scope_chain) == 1
        assert restored.verifiable.scope_chain[0].delegator_did == str(identity.did)

    def test_roundtrip_with_custom(self, identity):
        card = AICard.from_identity(identity)
        card.custom = {"org": "acme", "tier": "enterprise"}
        json_str = card.to_json()
        restored = AICard.from_json(json_str)
        assert restored.custom["org"] == "acme"

    def test_to_json_is_valid_json(self, signed_card):
        json_str = signed_card.to_json()
        data = json.loads(json_str)
        assert "name" in data
        assert "identity" in data
        assert "verifiable" in data
        assert "card_signature" in data

    def test_from_json_handles_missing_optional_fields(self):
        minimal_json = json.dumps({"name": "minimal"})
        card = AICard.from_json(minimal_json)
        assert card.name == "minimal"
        assert card.identity is None
        assert card.services == []


# ── TrustedAgentCard Bridge Tests ─────────────────────────────


class TestTrustedAgentCardBridge:
    """Test converting TrustedAgentCard to AI Card."""

    def test_bridge_from_trusted_card(self, identity):
        from agentmesh.trust.cards import TrustedAgentCard

        trusted = TrustedAgentCard.from_identity(identity)
        ai_card = AICard.from_trusted_agent_card(trusted)

        assert ai_card.name == trusted.name
        assert ai_card.description == trusted.description
        assert ai_card.identity is not None
        assert ai_card.identity.did == trusted.agent_did
        assert ai_card.identity.public_key == trusted.public_key
        assert ai_card.verifiable.trust_score == trusted.trust_score

    def test_bridge_preserves_metadata(self, identity):
        from agentmesh.trust.cards import TrustedAgentCard

        trusted = TrustedAgentCard.from_identity(identity)
        trusted.metadata = {"env": "production"}
        ai_card = AICard.from_trusted_agent_card(trusted)
        assert ai_card.custom["env"] == "production"

    def test_bridge_without_identity(self):
        from agentmesh.trust.cards import TrustedAgentCard

        trusted = TrustedAgentCard(name="no-id", description="No identity")
        ai_card = AICard.from_trusted_agent_card(trusted)
        assert ai_card.name == "no-id"
        assert ai_card.identity is None


# ── Discovery Tests ───────────────────────────────────────────


class TestAICardDiscovery:
    """Test AI Card discovery catalog."""

    def test_register_and_get(self, signed_card):
        discovery = AICardDiscovery()
        assert discovery.register(signed_card) is True
        retrieved = discovery.get(signed_card.identity.did)
        assert retrieved is not None
        assert retrieved.name == signed_card.name

    def test_register_rejects_invalid_signature(self):
        card = AICard(
            name="bad-sig",
            identity=AICardIdentity(did="did:mesh:bad", public_key="fake"),
            card_signature=AICardSignature(public_key="fake", signature="fake"),
        )
        discovery = AICardDiscovery()
        assert discovery.register(card) is False

    def test_register_rejects_no_identity(self):
        card = AICard(name="no-identity")
        discovery = AICardDiscovery()
        assert discovery.register(card) is False

    def test_register_without_verify(self):
        card = AICard(
            name="skip-verify",
            identity=AICardIdentity(did="did:mesh:skip", public_key="fake"),
        )
        discovery = AICardDiscovery()
        assert discovery.register(card, verify=False) is True

    def test_get_card_json(self, signed_card):
        discovery = AICardDiscovery()
        discovery.register(signed_card)
        json_str = discovery.get_card_json(signed_card.identity.did)
        assert json_str is not None
        data = json.loads(json_str)
        assert data["name"] == signed_card.name

    def test_get_card_json_not_found(self):
        discovery = AICardDiscovery()
        assert discovery.get_card_json("did:mesh:nonexistent") is None

    def test_catalog_json(self, signed_card):
        discovery = AICardDiscovery()
        discovery.register(signed_card)
        catalog = json.loads(discovery.get_catalog_json())
        assert catalog["total"] == 1
        assert len(catalog["cards"]) == 1
        assert "generated_at" in catalog

    def test_find_by_capability(self, identity, identity_b):
        discovery = AICardDiscovery()
        card_a = AICard.from_identity(identity)
        card_b = AICard.from_identity(identity_b)
        discovery.register(card_a)
        discovery.register(card_b)

        results = discovery.find_by_capability("read:data")
        assert len(results) == 1
        assert results[0].name == "test-agent"

        results = discovery.find_by_capability("execute:sql")
        assert len(results) == 1
        assert results[0].name == "peer-agent"

    def test_find_by_protocol(self, identity):
        discovery = AICardDiscovery()
        card = AICard.from_identity(
            identity,
            services=[AICardService(protocol="a2a", url="https://a2a.example.com")],
        )
        discovery.register(card)

        results = discovery.find_by_protocol("a2a")
        assert len(results) == 1

        results = discovery.find_by_protocol("mcp")
        assert len(results) == 0

    def test_remove(self, signed_card):
        discovery = AICardDiscovery()
        discovery.register(signed_card)
        assert discovery.remove(signed_card.identity.did) is True
        assert discovery.get(signed_card.identity.did) is None

    def test_remove_nonexistent(self):
        discovery = AICardDiscovery()
        assert discovery.remove("did:mesh:nope") is False

    def test_list_cards(self, identity, identity_b):
        discovery = AICardDiscovery()
        discovery.register(AICard.from_identity(identity))
        discovery.register(AICard.from_identity(identity_b))
        assert len(discovery.list_cards()) == 2

    def test_is_verified_caching(self, signed_card):
        discovery = AICardDiscovery()
        discovery.register(signed_card)
        assert discovery.is_verified(signed_card.identity.did) is True
        # Second call uses cache
        assert discovery.is_verified(signed_card.identity.did) is True

    def test_is_verified_unknown_did(self):
        discovery = AICardDiscovery()
        assert discovery.is_verified("did:mesh:unknown") is False

    def test_clear_cache(self, signed_card):
        discovery = AICardDiscovery()
        discovery.register(signed_card)
        discovery.is_verified(signed_card.identity.did)
        discovery.clear_cache()
        # Still works after cache clear (re-verifies)
        assert discovery.is_verified(signed_card.identity.did) is True
