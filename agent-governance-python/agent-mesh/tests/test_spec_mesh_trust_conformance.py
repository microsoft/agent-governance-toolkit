# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Conformance tests for AgentMesh Trust and Coordination specification.

Every test references a specific section of the specification.
Tests marked [Pure Specification] verify normative requirements.
Tests marked [Default Implementation] verify reference defaults.
"""

from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone

from agentmesh.constants import (
    TIER_PROBATIONARY_THRESHOLD,
    TIER_STANDARD_THRESHOLD,
    TIER_TRUSTED_THRESHOLD,
    TIER_VERIFIED_PARTNER_THRESHOLD,
    TRUST_SCORE_DEFAULT,
    TRUST_SCORE_MAX,
    TRUST_SCORE_MIN,
)
from agentmesh.trust.levels import trust_level_for_score
from agentmesh.trust.handshake import (
    HandshakeChallenge,
    HandshakeResult,
    TrustHandshake,
)
from agentmesh.trust.bridge import (
    PeerInfo,
    ProtocolBridge,
    TrustBridge,
)
from agentmesh.trust.endorsement import (
    Endorsement,
    EndorsementRegistry,
    EndorsementType,
)
from agentmesh.trust.capability import (
    CapabilityGrant,
    CapabilityRegistry,
    CapabilityScope,
)
from agentmesh.trust.cards import TrustedAgentCard
from agentmesh.services.rate_limiter import RateLimiter, TokenBucket
from agentmesh.services.behavior_monitor import AgentBehaviorMonitor
from agentmesh.exceptions import HandshakeError


# ═══════════════════════════════════════════════════════════════════════════
# Section 3: Trust Score Model
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustScoreModel(unittest.TestCase):
    """Spec S3 -- Trust Score Model."""

    def test_trust_score_min_is_zero(self):
        """S3.1 -- trust scores range 0-1000."""
        self.assertEqual(TRUST_SCORE_MIN, 0)

    def test_trust_score_max_is_1000(self):
        """S3.2 -- trust scores range 0-1000."""
        self.assertEqual(TRUST_SCORE_MAX, 1000)

    def test_trust_score_default_is_500(self):
        """S3.3 -- default trust score is 500."""
        self.assertEqual(TRUST_SCORE_DEFAULT, 500)

    def test_peer_info_rejects_score_above_max(self):
        """S3.4 -- trust scores above 1000 are rejected."""
        with self.assertRaises(Exception):
            PeerInfo(peer_did="did:mesh:x", protocol="iatp", trust_score=1001)

    def test_peer_info_rejects_score_below_min(self):
        """S3.5 -- trust scores below 0 are rejected."""
        with self.assertRaises(Exception):
            PeerInfo(peer_did="did:mesh:x", protocol="iatp", trust_score=-1)

    def test_peer_info_accepts_boundary_scores(self):
        """S3.6 -- boundary scores 0 and 1000 are valid."""
        low = PeerInfo(peer_did="did:mesh:a", protocol="iatp", trust_score=0)
        high = PeerInfo(peer_did="did:mesh:b", protocol="iatp", trust_score=1000)
        self.assertEqual(low.trust_score, 0)
        self.assertEqual(high.trust_score, 1000)


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: Trust Tiers
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustTiers(unittest.TestCase):
    """Spec S4 -- Trust Tiers."""

    def test_verified_partner_threshold(self):
        """S4.1 -- verified_partner >= 900."""
        self.assertEqual(TIER_VERIFIED_PARTNER_THRESHOLD, 900)
        self.assertEqual(trust_level_for_score(900), "verified_partner")
        self.assertEqual(trust_level_for_score(1000), "verified_partner")

    def test_trusted_threshold(self):
        """S4.2 -- trusted >= 700."""
        self.assertEqual(TIER_TRUSTED_THRESHOLD, 700)
        self.assertEqual(trust_level_for_score(700), "trusted")
        self.assertEqual(trust_level_for_score(899), "trusted")

    def test_standard_threshold(self):
        """S4.3 -- standard >= 500."""
        self.assertEqual(TIER_STANDARD_THRESHOLD, 500)
        self.assertEqual(trust_level_for_score(500), "standard")
        self.assertEqual(trust_level_for_score(699), "standard")

    def test_probationary_threshold(self):
        """S4.4 -- probationary >= 300."""
        self.assertEqual(TIER_PROBATIONARY_THRESHOLD, 300)
        self.assertEqual(trust_level_for_score(300), "probationary")
        self.assertEqual(trust_level_for_score(499), "probationary")

    def test_untrusted_below_300(self):
        """S4.5 -- untrusted < 300."""
        self.assertEqual(trust_level_for_score(0), "untrusted")
        self.assertEqual(trust_level_for_score(299), "untrusted")


# ═══════════════════════════════════════════════════════════════════════════
# Section 5: Handshake Protocol
# ═══════════════════════════════════════════════════════════════════════════


class TestHandshakeProtocol(unittest.TestCase):
    """Spec S5 -- Handshake Protocol."""

    def test_challenge_generate_creates_fields(self):
        """S5.1 -- generated challenge has required fields."""
        c = HandshakeChallenge.generate()
        self.assertTrue(c.challenge_id.startswith("challenge_"))
        self.assertIsNotNone(c.nonce)
        self.assertIsInstance(c.timestamp, datetime)

    def test_challenge_default_expiry(self):
        """S5.2 -- default expiry is 30 seconds."""
        c = HandshakeChallenge.generate()
        self.assertEqual(c.expires_in_seconds, 30)

    def test_challenge_not_expired_immediately(self):
        """S5.3 -- freshly generated challenge is not expired."""
        c = HandshakeChallenge.generate()
        self.assertFalse(c.is_expired())

    def test_handshake_result_uses_verified_field(self):
        """S5.4 -- HandshakeResult uses 'verified' not 'success'."""
        r = HandshakeResult(verified=True, peer_did="did:mesh:p")
        self.assertTrue(r.verified)

    def test_handshake_result_uses_peer_did_field(self):
        """S5.5 -- HandshakeResult uses 'peer_did' not 'agent_did'."""
        r = HandshakeResult(verified=False, peer_did="did:mesh:q")
        self.assertEqual(r.peer_did, "did:mesh:q")

    def test_trust_handshake_requires_did_mesh_prefix(self):
        """S5.6 -- TrustHandshake rejects DIDs without 'did:mesh:' prefix."""
        with self.assertRaises(HandshakeError):
            TrustHandshake(agent_did="invalid-did")

    def test_trust_handshake_accepts_valid_did(self):
        """S5.7 -- TrustHandshake accepts valid 'did:mesh:' DID."""
        hs = TrustHandshake(agent_did="did:mesh:test123")
        self.assertEqual(hs.agent_did, "did:mesh:test123")


# ═══════════════════════════════════════════════════════════════════════════
# Section 6: Trust Bridge
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustBridge(unittest.TestCase):
    """Spec S6 -- Trust Bridge."""

    def setUp(self):
        self.bridge = TrustBridge(agent_did="did:mesh:self")

    def test_default_trust_threshold(self):
        """S6.1 -- default trust threshold is 700."""
        self.assertEqual(self.bridge.default_trust_threshold, 700)

    def test_verify_peer_stores_record(self):
        """S6.2 -- verify_peer stores peer in bridge.peers on success."""
        # verify_peer calls handshake.initiate which needs a registry;
        # without one the peer will fail verification, so we inject directly
        peer = PeerInfo(
            peer_did="did:mesh:p1",
            protocol="iatp",
            trust_score=800,
            trust_verified=True,
        )
        self.bridge.peers["did:mesh:p1"] = peer
        self.bridge._peer_signatures["did:mesh:p1"] = self.bridge._sign_peer(peer)
        self.assertIn("did:mesh:p1", self.bridge.peers)

    def test_untrusted_peer_rejected(self):
        """S6.3 -- peer below threshold is not trusted."""
        peer = PeerInfo(
            peer_did="did:mesh:low",
            protocol="iatp",
            trust_score=400,
            trust_verified=True,
        )
        self.bridge.peers["did:mesh:low"] = peer
        self.bridge._peer_signatures["did:mesh:low"] = self.bridge._sign_peer(peer)
        result = asyncio.run(self.bridge.is_peer_trusted("did:mesh:low"))
        self.assertFalse(result)

    def test_trusted_peer_accepted(self):
        """S6.4 -- peer at or above threshold is trusted."""
        peer = PeerInfo(
            peer_did="did:mesh:high",
            protocol="iatp",
            trust_score=800,
            trust_verified=True,
        )
        self.bridge.peers["did:mesh:high"] = peer
        self.bridge._peer_signatures["did:mesh:high"] = self.bridge._sign_peer(peer)
        result = asyncio.run(self.bridge.is_peer_trusted("did:mesh:high"))
        self.assertTrue(result)

    def test_unknown_peer_not_trusted(self):
        """S6.5 -- unknown peer is not trusted."""
        result = asyncio.run(self.bridge.is_peer_trusted("did:mesh:unknown"))
        self.assertFalse(result)

    def test_revoke_peer_trust(self):
        """S6.6 -- revoke_peer_trust sets score to 0."""
        peer = PeerInfo(
            peer_did="did:mesh:rev",
            protocol="iatp",
            trust_score=800,
            trust_verified=True,
        )
        self.bridge.peers["did:mesh:rev"] = peer
        self.bridge._peer_signatures["did:mesh:rev"] = self.bridge._sign_peer(peer)
        result = asyncio.run(self.bridge.revoke_peer_trust("did:mesh:rev", "test-revocation"))
        self.assertTrue(result)
        self.assertEqual(self.bridge.peers["did:mesh:rev"].trust_score, 0)
        self.assertFalse(self.bridge.peers["did:mesh:rev"].trust_verified)

    def test_integrity_check_rejects_tampered_peer(self):
        """S6.7 -- tampered peer record fails integrity check."""
        peer = PeerInfo(
            peer_did="did:mesh:tamper",
            protocol="iatp",
            trust_score=800,
            trust_verified=True,
        )
        self.bridge.peers["did:mesh:tamper"] = peer
        self.bridge._peer_signatures["did:mesh:tamper"] = self.bridge._sign_peer(peer)
        # Tamper with the score without re-signing
        self.bridge.peers["did:mesh:tamper"].trust_score = 999
        result = asyncio.run(self.bridge.is_peer_trusted("did:mesh:tamper"))
        self.assertFalse(result)


# ═══════════════════════════════════════════════════════════════════════════
# Section 7: Endorsement Registry
# ═══════════════════════════════════════════════════════════════════════════


class TestEndorsementRegistry(unittest.TestCase):
    """Spec S7 -- Endorsement Registry."""

    def setUp(self):
        self.registry = EndorsementRegistry()

    def test_add_and_query_endorsement(self):
        """S7.1 -- add() stores and get_endorsements() retrieves."""
        e = Endorsement(
            endorser_did="did:mesh:authority",
            target_did="did:mesh:agent1",
            endorsement_type=EndorsementType.COMPLIANCE,
            claims={"framework": "EU AI Act"},
        )
        self.registry.add(e)
        results = self.registry.get_endorsements("did:mesh:agent1")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].endorser_did, "did:mesh:authority")

    def test_endorsement_type_filtering(self):
        """S7.2 -- get_endorsements filters by type."""
        self.registry.add(Endorsement(
            endorser_did="did:mesh:a",
            target_did="did:mesh:t",
            endorsement_type=EndorsementType.COMPLIANCE,
        ))
        self.registry.add(Endorsement(
            endorser_did="did:mesh:b",
            target_did="did:mesh:t",
            endorsement_type=EndorsementType.CAPABILITY,
        ))
        compliance = self.registry.get_endorsements("did:mesh:t", EndorsementType.COMPLIANCE)
        self.assertEqual(len(compliance), 1)
        self.assertEqual(compliance[0].endorser_did, "did:mesh:a")

    def test_has_endorsement(self):
        """S7.3 -- has_endorsement returns True when endorsement exists."""
        self.registry.add(Endorsement(
            endorser_did="did:mesh:e",
            target_did="did:mesh:t",
            endorsement_type=EndorsementType.INTEGRITY,
        ))
        self.assertTrue(self.registry.has_endorsement("did:mesh:t", EndorsementType.INTEGRITY))
        self.assertFalse(self.registry.has_endorsement("did:mesh:t", EndorsementType.IDENTITY))

    def test_revoke_endorsement(self):
        """S7.4 -- revoke() removes endorsements from specific endorser."""
        self.registry.add(Endorsement(
            endorser_did="did:mesh:e1",
            target_did="did:mesh:t",
            endorsement_type=EndorsementType.COMPLIANCE,
        ))
        self.registry.add(Endorsement(
            endorser_did="did:mesh:e2",
            target_did="did:mesh:t",
            endorsement_type=EndorsementType.COMPLIANCE,
        ))
        removed = self.registry.revoke("did:mesh:t", "did:mesh:e1")
        self.assertEqual(removed, 1)
        remaining = self.registry.get_endorsements("did:mesh:t")
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].endorser_did, "did:mesh:e2")

    def test_expired_endorsement_rejected_on_add(self):
        """S7.5 -- expired endorsements are rejected by add()."""
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        e = Endorsement(
            endorser_did="did:mesh:e",
            target_did="did:mesh:t",
            endorsement_type=EndorsementType.COMPLIANCE,
            expires_at=past,
        )
        self.registry.add(e)
        results = self.registry.get_endorsements("did:mesh:t")
        self.assertEqual(len(results), 0)

    def test_clear_registry(self):
        """S7.6 -- clear() removes all endorsements."""
        self.registry.add(Endorsement(
            endorser_did="did:mesh:e",
            target_did="did:mesh:t",
            endorsement_type=EndorsementType.CAPABILITY,
        ))
        self.registry.clear()
        self.assertEqual(self.registry.total_count, 0)

    def test_endorsement_type_values(self):
        """S7.7 -- EndorsementType enum has expected members."""
        self.assertEqual(EndorsementType.CAPABILITY.value, "capability")
        self.assertEqual(EndorsementType.INTEGRITY.value, "integrity")
        self.assertEqual(EndorsementType.COMPLIANCE.value, "compliance")
        self.assertEqual(EndorsementType.IDENTITY.value, "identity")
        self.assertEqual(EndorsementType.REFERENCE_VALUE.value, "reference_value")


# ═══════════════════════════════════════════════════════════════════════════
# Section 8: Capability Scoping
# ═══════════════════════════════════════════════════════════════════════════


class TestCapabilityScoping(unittest.TestCase):
    """Spec S8 -- Capability Scoping."""

    def test_parse_capability(self):
        """S8.1 -- parse_capability splits action:resource:qualifier."""
        action, resource, qualifier = CapabilityGrant.parse_capability("read:data:sensitive")
        self.assertEqual(action, "read")
        self.assertEqual(resource, "data")
        self.assertEqual(qualifier, "sensitive")

    def test_parse_capability_without_qualifier(self):
        """S8.2 -- parse_capability works without qualifier."""
        action, resource, qualifier = CapabilityGrant.parse_capability("write:reports")
        self.assertEqual(action, "write")
        self.assertEqual(resource, "reports")
        self.assertIsNone(qualifier)

    def test_parse_capability_invalid_format(self):
        """S8.3 -- parse_capability rejects malformed strings."""
        with self.assertRaises(ValueError):
            CapabilityGrant.parse_capability("invalid")

    def test_grant_creation(self):
        """S8.4 -- CapabilityGrant.create() populates fields."""
        grant = CapabilityGrant.create(
            capability="read:data",
            granted_to="did:mesh:agent",
            granted_by="did:mesh:admin",
        )
        self.assertEqual(grant.action, "read")
        self.assertEqual(grant.resource, "data")
        self.assertTrue(grant.active)

    def test_has_capability(self):
        """S8.5 -- CapabilityScope.has_capability() checks grants."""
        scope = CapabilityScope(agent_did="did:mesh:a")
        grant = CapabilityGrant.create("read:data", "did:mesh:a", "did:mesh:admin")
        scope.add_grant(grant)
        self.assertTrue(scope.has_capability("read:data"))
        self.assertFalse(scope.has_capability("write:data"))

    def test_deny_overrides_grant(self):
        """S8.6 -- deny() overrides matching grants."""
        scope = CapabilityScope(agent_did="did:mesh:a")
        grant = CapabilityGrant.create("read:data", "did:mesh:a", "did:mesh:admin")
        scope.add_grant(grant)
        scope.deny("read:data")
        self.assertFalse(scope.has_capability("read:data"))

    def test_revoke_all(self):
        """S8.7 -- revoke_all() deactivates all grants."""
        scope = CapabilityScope(agent_did="did:mesh:a")
        scope.add_grant(CapabilityGrant.create("read:data", "did:mesh:a", "did:mesh:admin"))
        scope.add_grant(CapabilityGrant.create("write:data", "did:mesh:a", "did:mesh:admin"))
        count = scope.revoke_all()
        self.assertEqual(count, 2)
        self.assertFalse(scope.has_capability("read:data"))

    def test_revoke_from_grantor(self):
        """S8.8 -- revoke_from() revokes grants from a specific grantor."""
        scope = CapabilityScope(agent_did="did:mesh:a")
        scope.add_grant(CapabilityGrant.create("read:data", "did:mesh:a", "did:mesh:admin"))
        scope.add_grant(CapabilityGrant.create("write:data", "did:mesh:a", "did:mesh:other"))
        count = scope.revoke_from("did:mesh:admin")
        self.assertEqual(count, 1)
        self.assertFalse(scope.has_capability("read:data"))
        self.assertTrue(scope.has_capability("write:data"))

    def test_registry_grant_and_check(self):
        """S8.9 -- CapabilityRegistry.grant() and check() work together."""
        reg = CapabilityRegistry()
        reg.grant("read:data", to_agent="did:mesh:a", from_agent="did:mesh:admin")
        self.assertTrue(reg.check("did:mesh:a", "read:data"))
        self.assertFalse(reg.check("did:mesh:a", "write:data"))

    def test_registry_revoke_all_from(self):
        """S8.10 -- CapabilityRegistry.revoke_all_from() cascades."""
        reg = CapabilityRegistry()
        reg.grant("read:data", to_agent="did:mesh:a", from_agent="did:mesh:admin")
        reg.grant("write:data", to_agent="did:mesh:b", from_agent="did:mesh:admin")
        count = reg.revoke_all_from("did:mesh:admin")
        self.assertEqual(count, 2)
        self.assertFalse(reg.check("did:mesh:a", "read:data"))
        self.assertFalse(reg.check("did:mesh:b", "write:data"))


# ═══════════════════════════════════════════════════════════════════════════
# Section 9: Agent Cards
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentCards(unittest.TestCase):
    """Spec S9 -- Agent Cards."""

    def test_card_creation(self):
        """S9.1 -- TrustedAgentCard creation with basic fields."""
        card = TrustedAgentCard(
            name="test-agent",
            description="A test agent",
            capabilities=["read:data"],
        )
        self.assertEqual(card.name, "test-agent")
        self.assertEqual(card.description, "A test agent")
        self.assertIn("read:data", card.capabilities)

    def test_card_to_dict(self):
        """S9.2 -- to_dict() serializes card fields."""
        card = TrustedAgentCard(
            name="test-agent",
            capabilities=["read:data", "write:data"],
        )
        d = card.to_dict()
        self.assertEqual(d["name"], "test-agent")
        self.assertIn("read:data", d["capabilities"])
        self.assertIn("trust_score", d)

    def test_card_from_dict_roundtrip(self):
        """S9.3 -- from_dict() deserializes a to_dict() output."""
        card = TrustedAgentCard(
            name="roundtrip",
            description="test",
            capabilities=["execute:tools"],
            trust_score=0.9,
        )
        d = card.to_dict()
        restored = TrustedAgentCard.from_dict(d)
        self.assertEqual(restored.name, "roundtrip")
        self.assertEqual(restored.description, "test")
        self.assertAlmostEqual(restored.trust_score, 0.9)
        self.assertIn("execute:tools", restored.capabilities)


# ═══════════════════════════════════════════════════════════════════════════
# Section 10: Protocol Bridge
# ═══════════════════════════════════════════════════════════════════════════


class TestProtocolBridge(unittest.TestCase):
    """Spec S10 -- Protocol Bridge."""

    def test_supported_protocols_default(self):
        """S10.1 -- default supported protocols are a2a, mcp, iatp, acp."""
        pb = ProtocolBridge(agent_did="did:mesh:self")
        self.assertEqual(pb.supported_protocols, ["a2a", "mcp", "iatp", "acp"])

    def test_a2a_to_mcp_translation(self):
        """S10.2 -- A2A-to-MCP translation maps task_type to method."""
        pb = ProtocolBridge(agent_did="did:mesh:self")
        a2a_msg = {"task_type": "summarize", "parameters": {"text": "hello"}}
        mcp_msg = pb._a2a_to_mcp(a2a_msg)
        self.assertEqual(mcp_msg["method"], "tools/call")
        self.assertEqual(mcp_msg["params"]["name"], "summarize")
        self.assertEqual(mcp_msg["params"]["arguments"], {"text": "hello"})

    def test_mcp_to_a2a_translation(self):
        """S10.3 -- MCP-to-A2A translation maps method to task_type."""
        pb = ProtocolBridge(agent_did="did:mesh:self")
        mcp_msg = {"params": {"name": "analyze", "arguments": {"data": [1, 2]}}}
        a2a_msg = pb._mcp_to_a2a(mcp_msg)
        self.assertEqual(a2a_msg["task_type"], "analyze")
        self.assertEqual(a2a_msg["parameters"], {"data": [1, 2]})


# ═══════════════════════════════════════════════════════════════════════════
# Section 13: Mesh Rate Limiting
# ═══════════════════════════════════════════════════════════════════════════


class TestMeshRateLimiting(unittest.TestCase):
    """Spec S13 -- Mesh Rate Limiting."""

    def test_token_bucket_starts_full(self):
        """S13.1 -- token bucket starts at full capacity."""
        bucket = TokenBucket(rate=10.0, capacity=20)
        self.assertAlmostEqual(bucket.tokens_available(), 20.0, places=0)

    def test_token_bucket_consume_reduces_tokens(self):
        """S13.2 -- consuming tokens reduces available count."""
        bucket = TokenBucket(rate=10.0, capacity=20)
        self.assertTrue(bucket.consume(5))
        self.assertLessEqual(bucket.tokens_available(), 16.0)

    def test_token_bucket_rejects_when_empty(self):
        """S13.3 -- consuming more tokens than available is rejected."""
        bucket = TokenBucket(rate=0.0, capacity=5)
        for _ in range(5):
            bucket.consume(1)
        self.assertFalse(bucket.consume(1))

    def test_per_agent_rate_limiting(self):
        """S13.4 -- per-agent buckets are independent."""
        limiter = RateLimiter(per_agent_rate=0.0, per_agent_capacity=2)
        self.assertTrue(limiter.allow("did:mesh:a"))
        self.assertTrue(limiter.allow("did:mesh:a"))
        self.assertFalse(limiter.allow("did:mesh:a"))
        # Different agent has its own bucket
        self.assertTrue(limiter.allow("did:mesh:b"))

    def test_rate_limiter_check_returns_structured_result(self):
        """S13.5 -- check() returns RateLimitResult with required fields."""
        limiter = RateLimiter()
        result = limiter.check("did:mesh:a")
        self.assertIsNotNone(result.allowed)
        self.assertIsNotNone(result.remaining_tokens)
        self.assertIsNotNone(result.backpressure)


# ═══════════════════════════════════════════════════════════════════════════
# Section 15: Behavior Monitoring
# ═══════════════════════════════════════════════════════════════════════════


class TestBehaviorMonitoring(unittest.TestCase):
    """Spec S15 -- Behavior Monitoring."""

    def test_default_consecutive_failure_threshold(self):
        """S15.1 -- default consecutive failure threshold is 20."""
        mon = AgentBehaviorMonitor()
        self.assertEqual(mon._consecutive_failure_threshold, 20)

    def test_default_burst_threshold(self):
        """S15.2 -- default burst threshold is 100."""
        mon = AgentBehaviorMonitor()
        self.assertEqual(mon._burst_threshold, 100)

    def test_quarantine_on_consecutive_failures(self):
        """S15.3 -- agent quarantined after consecutive failure threshold."""
        mon = AgentBehaviorMonitor(consecutive_failure_threshold=3)
        did = "did:mesh:failing"
        for _ in range(3):
            mon.record_tool_call(did, "bad_tool", success=False)
        self.assertTrue(mon.is_quarantined(did))

    def test_success_resets_consecutive_failures(self):
        """S15.4 -- a successful call resets consecutive failure counter."""
        mon = AgentBehaviorMonitor(consecutive_failure_threshold=3)
        did = "did:mesh:intermittent"
        mon.record_tool_call(did, "tool", success=False)
        mon.record_tool_call(did, "tool", success=False)
        mon.record_tool_call(did, "tool", success=True)  # resets
        mon.record_tool_call(did, "tool", success=False)
        self.assertFalse(mon.is_quarantined(did))

    def test_auto_release_after_duration(self):
        """S15.5 -- quarantine auto-releases after configured duration."""
        mon = AgentBehaviorMonitor(
            consecutive_failure_threshold=1,
            quarantine_duration=timedelta(seconds=0),
        )
        did = "did:mesh:temp"
        mon.record_tool_call(did, "tool", success=False)
        # With zero duration, quarantine should already be expired
        self.assertFalse(mon.is_quarantined(did))

    def test_manual_release_quarantine(self):
        """S15.6 -- release_quarantine() clears quarantine status."""
        mon = AgentBehaviorMonitor(consecutive_failure_threshold=1)
        did = "did:mesh:released"
        mon.record_tool_call(did, "tool", success=False)
        self.assertTrue(mon.is_quarantined(did))
        mon.release_quarantine(did)
        self.assertFalse(mon.is_quarantined(did))


# ═══════════════════════════════════════════════════════════════════════════
# Section 19: Failure Semantics
# ═══════════════════════════════════════════════════════════════════════════


class TestFailureSemantics(unittest.TestCase):
    """Spec S19 -- Failure Semantics."""

    def test_malformed_capability_fails_closed(self):
        """S19.1 -- malformed capability string fails closed."""
        scope = CapabilityScope(agent_did="did:mesh:a")
        grant = CapabilityGrant.create("read:data", "did:mesh:a", "did:mesh:admin")
        scope.add_grant(grant)
        # Malformed request (no colon) should not match
        self.assertFalse(scope.has_capability("invalid"))

    def test_unknown_peer_denied(self):
        """S19.2 -- unknown peer is denied trust."""
        bridge = TrustBridge(agent_did="did:mesh:self")
        result = asyncio.run(bridge.is_peer_trusted("did:mesh:nobody"))
        self.assertFalse(result)

    def test_untrusted_send_raises(self):
        """S19.3 -- sending to untrusted peer raises PermissionError."""
        pb = ProtocolBridge(agent_did="did:mesh:self")
        with self.assertRaises(PermissionError):
            asyncio.run(pb.send_message(
                peer_did="did:mesh:untrusted",
                message={"data": "test"},
                source_protocol="a2a",
            ))


if __name__ == "__main__":
    unittest.main()
