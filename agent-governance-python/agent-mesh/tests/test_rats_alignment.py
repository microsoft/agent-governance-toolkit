# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for RFC 9334 (RATS Architecture) alignment features.

Covers:
- EndorsementRegistry: creation, storage, expiry, revocation, querying
- Freshness nonce: round-trip in handshake, cache bypass, mismatch rejection
- Backward compatibility: no freshness_nonce = existing behavior unchanged
"""

from datetime import UTC, datetime, timedelta

import pytest

from agentmesh.trust.endorsement import (
    Endorsement,
    EndorsementRegistry,
    EndorsementType,
)
from agentmesh.trust.handshake import (
    HandshakeChallenge,
    HandshakeResponse,
    TrustHandshake,
)
from agentmesh.trust.bridge import TrustBridge


# ---------------------------------------------------------------------------
# Endorsement tests
# ---------------------------------------------------------------------------


class TestEndorsement:
    """Unit tests for Endorsement dataclass."""

    def test_create_endorsement(self):
        e = Endorsement(
            endorser_did="did:mesh:endorser-1",
            target_did="did:mesh:agent-a",
            endorsement_type=EndorsementType.COMPLIANCE,
            claims={"framework": "EU AI Act", "risk_level": "limited"},
        )
        assert e.endorser_did == "did:mesh:endorser-1"
        assert e.target_did == "did:mesh:agent-a"
        assert e.endorsement_type == EndorsementType.COMPLIANCE
        assert e.claims["framework"] == "EU AI Act"
        assert not e.is_expired()

    def test_endorsement_not_expired_when_no_expiry(self):
        e = Endorsement(
            endorser_did="did:mesh:e",
            target_did="did:mesh:a",
            endorsement_type=EndorsementType.CAPABILITY,
        )
        assert not e.is_expired()

    def test_endorsement_expired(self):
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        e = Endorsement(
            endorser_did="did:mesh:e",
            target_did="did:mesh:a",
            endorsement_type=EndorsementType.INTEGRITY,
            expires_at=past,
        )
        assert e.is_expired()

    def test_endorsement_not_expired_future(self):
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        e = Endorsement(
            endorser_did="did:mesh:e",
            target_did="did:mesh:a",
            endorsement_type=EndorsementType.INTEGRITY,
            expires_at=future,
        )
        assert not e.is_expired()

    def test_endorsement_invalid_expiry_treated_as_expired(self):
        e = Endorsement(
            endorser_did="did:mesh:e",
            target_did="did:mesh:a",
            endorsement_type=EndorsementType.IDENTITY,
            expires_at="not-a-date",
        )
        assert e.is_expired()

    def test_to_dict_roundtrip(self):
        e = Endorsement(
            endorser_did="did:mesh:endorser-1",
            target_did="did:mesh:agent-a",
            endorsement_type=EndorsementType.REFERENCE_VALUE,
            claims={"hash": "sha256:abc123"},
            metadata={"source": "ci-pipeline"},
        )
        d = e.to_dict()
        e2 = Endorsement.from_dict(d)
        assert e2.endorser_did == e.endorser_did
        assert e2.target_did == e.target_did
        assert e2.endorsement_type == e.endorsement_type
        assert e2.claims == e.claims

    def test_all_endorsement_types_valid(self):
        for et in EndorsementType:
            e = Endorsement(
                endorser_did="did:mesh:e",
                target_did="did:mesh:a",
                endorsement_type=et,
            )
            assert e.endorsement_type == et


class TestEndorsementRegistry:
    """Unit tests for EndorsementRegistry."""

    def test_add_and_retrieve(self):
        reg = EndorsementRegistry()
        e = Endorsement(
            endorser_did="did:mesh:endorser-1",
            target_did="did:mesh:agent-a",
            endorsement_type=EndorsementType.COMPLIANCE,
            claims={"standard": "ISO 42001"},
        )
        reg.add(e)
        results = reg.get_endorsements("did:mesh:agent-a")
        assert len(results) == 1
        assert results[0].claims["standard"] == "ISO 42001"

    def test_expired_endorsement_rejected_on_add(self):
        reg = EndorsementRegistry()
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        e = Endorsement(
            endorser_did="did:mesh:e",
            target_did="did:mesh:a",
            endorsement_type=EndorsementType.CAPABILITY,
            expires_at=past,
        )
        reg.add(e)
        assert reg.total_count == 0

    def test_filter_by_type(self):
        reg = EndorsementRegistry()
        target = "did:mesh:agent-a"
        reg.add(Endorsement(
            endorser_did="did:mesh:e1",
            target_did=target,
            endorsement_type=EndorsementType.COMPLIANCE,
        ))
        reg.add(Endorsement(
            endorser_did="did:mesh:e2",
            target_did=target,
            endorsement_type=EndorsementType.INTEGRITY,
        ))
        compliance_only = reg.get_endorsements(target, EndorsementType.COMPLIANCE)
        assert len(compliance_only) == 1
        assert compliance_only[0].endorsement_type == EndorsementType.COMPLIANCE

    def test_get_endorsers(self):
        reg = EndorsementRegistry()
        target = "did:mesh:agent-a"
        reg.add(Endorsement(
            endorser_did="did:mesh:e1",
            target_did=target,
            endorsement_type=EndorsementType.CAPABILITY,
        ))
        reg.add(Endorsement(
            endorser_did="did:mesh:e2",
            target_did=target,
            endorsement_type=EndorsementType.COMPLIANCE,
        ))
        reg.add(Endorsement(
            endorser_did="did:mesh:e1",
            target_did=target,
            endorsement_type=EndorsementType.INTEGRITY,
        ))
        endorsers = reg.get_endorsers(target)
        assert len(endorsers) == 2
        assert "did:mesh:e1" in endorsers
        assert "did:mesh:e2" in endorsers

    def test_has_endorsement(self):
        reg = EndorsementRegistry()
        target = "did:mesh:agent-a"
        reg.add(Endorsement(
            endorser_did="did:mesh:e1",
            target_did=target,
            endorsement_type=EndorsementType.COMPLIANCE,
        ))
        assert reg.has_endorsement(target, EndorsementType.COMPLIANCE)
        assert not reg.has_endorsement(target, EndorsementType.INTEGRITY)
        assert reg.has_endorsement(
            target, EndorsementType.COMPLIANCE, endorser_did="did:mesh:e1"
        )
        assert not reg.has_endorsement(
            target, EndorsementType.COMPLIANCE, endorser_did="did:mesh:e2"
        )

    def test_revoke(self):
        reg = EndorsementRegistry()
        target = "did:mesh:agent-a"
        reg.add(Endorsement(
            endorser_did="did:mesh:e1",
            target_did=target,
            endorsement_type=EndorsementType.CAPABILITY,
        ))
        reg.add(Endorsement(
            endorser_did="did:mesh:e2",
            target_did=target,
            endorsement_type=EndorsementType.COMPLIANCE,
        ))
        removed = reg.revoke(target, "did:mesh:e1")
        assert removed == 1
        assert len(reg.get_endorsements(target)) == 1
        assert reg.get_endorsements(target)[0].endorser_did == "did:mesh:e2"

    def test_revoke_nonexistent(self):
        reg = EndorsementRegistry()
        assert reg.revoke("did:mesh:unknown", "did:mesh:e1") == 0

    def test_clear_all(self):
        reg = EndorsementRegistry()
        for i in range(3):
            reg.add(Endorsement(
                endorser_did=f"did:mesh:e{i}",
                target_did=f"did:mesh:a{i}",
                endorsement_type=EndorsementType.CAPABILITY,
            ))
        assert reg.total_count == 3
        reg.clear()
        assert reg.total_count == 0

    def test_clear_specific_target(self):
        reg = EndorsementRegistry()
        reg.add(Endorsement(
            endorser_did="did:mesh:e1",
            target_did="did:mesh:agent-a",
            endorsement_type=EndorsementType.CAPABILITY,
        ))
        reg.add(Endorsement(
            endorser_did="did:mesh:e1",
            target_did="did:mesh:agent-b",
            endorsement_type=EndorsementType.CAPABILITY,
        ))
        reg.clear("did:mesh:agent-a")
        assert len(reg.get_endorsements("did:mesh:agent-a")) == 0
        assert len(reg.get_endorsements("did:mesh:agent-b")) == 1

    def test_empty_registry_returns_empty(self):
        reg = EndorsementRegistry()
        assert reg.get_endorsements("did:mesh:nonexistent") == []
        assert reg.get_endorsers("did:mesh:nonexistent") == []
        assert not reg.has_endorsement("did:mesh:nonexistent", EndorsementType.CAPABILITY)


# ---------------------------------------------------------------------------
# Freshness nonce tests
# ---------------------------------------------------------------------------


class TestFreshnessNonce:
    """Tests for RFC 9334 freshness nonce in handshake challenge/response."""

    def test_challenge_without_freshness(self):
        """Default challenge has no freshness nonce (backward compatible)."""
        challenge = HandshakeChallenge.generate()
        assert challenge.freshness_nonce is None
        assert challenge.nonce is not None

    def test_challenge_with_freshness(self):
        """Freshness-required challenge includes a freshness_nonce."""
        challenge = HandshakeChallenge.generate(require_freshness=True)
        assert challenge.freshness_nonce is not None
        assert len(challenge.freshness_nonce) == 32  # 16 bytes hex = 32 chars
        assert challenge.nonce is not None
        assert challenge.nonce != challenge.freshness_nonce

    def test_create_challenge_with_freshness(self):
        """TrustHandshake.create_challenge passes freshness through."""
        hs = TrustHandshake(agent_did="did:mesh:test-agent")
        challenge = hs.create_challenge(require_freshness=True)
        assert challenge.freshness_nonce is not None
        assert hs.validate_challenge(challenge.challenge_id)

    def test_create_challenge_without_freshness(self):
        """TrustHandshake.create_challenge defaults to no freshness."""
        hs = TrustHandshake(agent_did="did:mesh:test-agent")
        challenge = hs.create_challenge()
        assert challenge.freshness_nonce is None


# ---------------------------------------------------------------------------
# TrustBridge endorsement integration tests
# ---------------------------------------------------------------------------


class TestTrustBridgeEndorsements:
    """Tests for endorsement integration in TrustBridge."""

    def test_bridge_without_endorsement_registry(self):
        """TrustBridge works without endorsement registry (backward compat)."""
        bridge = TrustBridge(agent_did="did:mesh:test-agent")
        endorsements = bridge.get_endorsements("did:mesh:peer-1")
        assert endorsements == []

    def test_bridge_with_endorsement_registry(self):
        """TrustBridge delegates to endorsement registry when configured."""
        reg = EndorsementRegistry()
        reg.add(Endorsement(
            endorser_did="did:mesh:authority",
            target_did="did:mesh:peer-1",
            endorsement_type=EndorsementType.COMPLIANCE,
            claims={"standard": "SOC2"},
        ))
        bridge = TrustBridge(
            agent_did="did:mesh:test-agent",
            endorsement_registry=reg,
        )
        endorsements = bridge.get_endorsements("did:mesh:peer-1")
        assert len(endorsements) == 1
        assert endorsements[0].claims["standard"] == "SOC2"

    def test_bridge_endorsement_type_filter(self):
        """TrustBridge.get_endorsements filters by type."""
        reg = EndorsementRegistry()
        target = "did:mesh:peer-1"
        reg.add(Endorsement(
            endorser_did="did:mesh:e1",
            target_did=target,
            endorsement_type=EndorsementType.COMPLIANCE,
        ))
        reg.add(Endorsement(
            endorser_did="did:mesh:e2",
            target_did=target,
            endorsement_type=EndorsementType.INTEGRITY,
        ))
        bridge = TrustBridge(
            agent_did="did:mesh:test-agent",
            endorsement_registry=reg,
        )
        compliance = bridge.get_endorsements(target, EndorsementType.COMPLIANCE)
        assert len(compliance) == 1
        integrity = bridge.get_endorsements(target, EndorsementType.INTEGRITY)
        assert len(integrity) == 1


# ---------------------------------------------------------------------------
# Freshness nonce E2E handshake tests
# ---------------------------------------------------------------------------


class TestFreshnessNonceE2E:
    """End-to-end tests for freshness nonce in full handshake flow."""

    @pytest.mark.asyncio
    async def test_handshake_with_freshness_bypasses_cache(self):
        """require_freshness=True must bypass the handshake result cache."""
        from agentmesh.identity import AgentIdentity
        from agentmesh.identity.agent_id import IdentityRegistry

        agent_a = AgentIdentity.create(
            name="fresh-a",
            sponsor="test@test.example.com",
            capabilities=["read"],
        )
        agent_b = AgentIdentity.create(
            name="fresh-b",
            sponsor="test@test.example.com",
            capabilities=["read"],
        )
        registry = IdentityRegistry()
        registry.register(agent_a)
        registry.register(agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did),
            identity=agent_a,
            registry=registry,
        )

        # First handshake: populates cache
        result1 = await hs.initiate(
            peer_did=str(agent_b.did),
            required_trust_score=0,
        )
        assert result1.verified

        # Second handshake with freshness: must NOT return cached result
        result2 = await hs.initiate(
            peer_did=str(agent_b.did),
            required_trust_score=0,
            require_freshness=True,
        )
        assert result2.verified
        # Results should have different completion timestamps (fresh verification)
        assert result2.handshake_completed != result1.handshake_completed
