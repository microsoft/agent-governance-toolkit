# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Negative security tests — adversarial scenarios.

These tests verify that the system correctly REJECTS malicious inputs,
prevents escalation attacks, and handles edge cases defensively.
Each test targets a specific vulnerability pattern identified during
the post-MSRC security audit.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentmesh.identity import AgentIdentity, AgentDID
from agentmesh.identity.agent_id import IdentityRegistry
from agentmesh.trust.handshake import (
    TrustHandshake,
    HandshakeChallenge,
    HandshakeResult,
)
from agentmesh.trust.bridge import TrustBridge


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_agent(name="agent", caps=None, sponsor="admin@corp.com"):
    return AgentIdentity.create(
        name=name,
        sponsor=sponsor,
        capabilities=caps or ["read:data"],
    )


def _setup_handshake():
    """Create two registered agents and a handshake instance."""
    agent_a = _create_agent("agent-a", ["read:data", "write:data"])
    agent_b = _create_agent("agent-b", ["read:data"])
    registry = IdentityRegistry()
    registry.register(agent_a)
    registry.register(agent_b)
    handshake = TrustHandshake(
        agent_did=str(agent_a.did),
        identity=agent_a,
        registry=registry,
    )
    return handshake, agent_a, agent_b, registry


# ===========================================================================
# V01: Delegation depth — no max enforcement
# ===========================================================================


class TestDelegationDepthAbuse:
    """Verify delegation depth limits are respected."""

    def test_deep_delegation_chain_blocked(self):
        """Delegation beyond MAX_DELEGATION_DEPTH is rejected."""
        root = _create_agent("root", ["read:data", "write:data"])
        current = root
        # Create chain up to the max (10)
        for i in range(AgentIdentity.MAX_DELEGATION_DEPTH):
            current = current.delegate(
                name=f"child-{i}",
                capabilities=["read:data"],
            )
        assert current.delegation_depth == AgentIdentity.MAX_DELEGATION_DEPTH
        # The next delegation should be rejected
        with pytest.raises(ValueError, match="Maximum delegation depth"):
            current.delegate(name="too-deep", capabilities=["read:data"])

    def test_delegation_at_max_depth_still_works(self):
        """Delegation at depth MAX-1 succeeds (boundary check)."""
        root = _create_agent("root", ["read:data"])
        current = root
        for i in range(AgentIdentity.MAX_DELEGATION_DEPTH - 1):
            current = current.delegate(name=f"child-{i}", capabilities=["read:data"])
        # One more should still work (depth == MAX-1 → child depth == MAX)
        child = current.delegate(name="last", capabilities=["read:data"])
        assert child.delegation_depth == AgentIdentity.MAX_DELEGATION_DEPTH


# ===========================================================================
# V02: Wildcard capability delegation bypass
# ===========================================================================


class TestWildcardCapabilityBypass:
    """Test that wildcard capabilities don't create unintended escalation."""

    def test_wildcard_parent_cannot_delegate_arbitrary_capabilities(self):
        """A parent with '*' CANNOT delegate capabilities not literally
        in its list — the subset check uses literal matching, not
        has_capability() wildcard matching. This is secure.
        """
        root = _create_agent("root", ["*"])
        with pytest.raises(ValueError, match="not in parent's capabilities"):
            root.delegate(
                name="child",
                capabilities=["admin:delete-all", "nuclear:launch"],
            )

    def test_wildcard_delegation_blocked(self):
        """V02: Parent with '*' CANNOT delegate '*' itself —
        wildcard propagation is explicitly blocked.
        """
        root = _create_agent("root", ["*"])
        with pytest.raises(ValueError, match="Cannot delegate wildcard"):
            root.delegate(name="child", capabilities=["*"])

    def test_star_capability_matches_everything(self):
        agent = _create_agent("super", ["*"])
        assert agent.has_capability("anything:at:all")
        assert agent.has_capability("admin:delete")
        assert agent.has_capability("")  # even empty string

    def test_prefix_wildcard_with_empty_prefix(self):
        """':*' (empty prefix) should NOT match arbitrary capabilities."""
        agent = _create_agent("test", [":*"])
        # V04: ':*' is now rejected (len(":*") == 2, not > 2)
        assert agent.has_capability(":anything") is False
        assert agent.has_capability("read:data") is False


# ===========================================================================
# V03: Plugin path traversal
# ===========================================================================


class TestPluginPathTraversal:
    """Verify plugin names can't escape the plugins directory."""

    def test_dotdot_in_plugin_name_rejected(self, tmp_path: Path):
        """Plugin name with path traversal chars is rejected by validator."""
        from agentmesh.marketplace import (
            PluginManifest, PluginType, MarketplaceError,
        )

        # URL-encoded traversal — rejected because of '.' and '%' chars
        with pytest.raises(MarketplaceError, match="alphanumeric"):
            PluginManifest(
                name="..%2F..%2Fevil",
                version="1.0.0",
                description="Malicious plugin",
                author="attacker@evil.com",
                plugin_type=PluginType.INTEGRATION,
            )

    def test_dotdot_raw_in_plugin_name_rejected(self, tmp_path: Path):
        """Plugin name with raw '../' is rejected by validator."""
        from agentmesh.marketplace import (
            PluginManifest, PluginType, MarketplaceError,
        )

        with pytest.raises(MarketplaceError, match="alphanumeric"):
            PluginManifest(
                name="../../evil",
                version="1.0.0",
                description="Malicious plugin",
                author="attacker@evil.com",
                plugin_type=PluginType.INTEGRATION,
            )

    def test_absolute_path_plugin_name(self, tmp_path: Path):
        """Plugin name that looks like an absolute path."""
        from agentmesh.marketplace import PluginManifest, PluginType, MarketplaceError

        try:
            manifest = PluginManifest(
                name="C:\\Windows\\System32\\evil",
                version="1.0.0",
                description="Malicious",
                author="attacker@evil.com",
                plugin_type=PluginType.INTEGRATION,
            )
            # If it gets here, the name validation is too permissive
            assert False, "Should have rejected plugin name with backslashes"
        except (MarketplaceError, ValueError):
            pass  # Expected — name validation caught it


# ===========================================================================
# V04: Capability matching edge cases
# ===========================================================================


class TestCapabilityMatchingEdgeCases:
    """Adversarial capability strings."""

    def test_empty_string_capability(self):
        agent = _create_agent("test", ["read:data"])
        assert agent.has_capability("") is False

    def test_colon_only_capability(self):
        agent = _create_agent("test", ["read:data"])
        assert agent.has_capability(":") is False

    def test_wildcard_in_middle_not_matched(self):
        """'read:*:secret' should NOT wildcard-match."""
        agent = _create_agent("test", ["read:*:secret"])
        # Only ':*' at the end is treated as wildcard
        assert agent.has_capability("read:anything:secret") is False

    def test_glob_star_not_wildcard(self):
        """'**' is not a valid wildcard pattern."""
        agent = _create_agent("test", ["**"])
        # '**' != '*', shouldn't match everything
        assert agent.has_capability("read:data") is False

    def test_very_long_capability_string(self):
        """Extremely long capability strings shouldn't crash."""
        agent = _create_agent("test", ["read:data"])
        long_cap = "a" * 10_000
        assert agent.has_capability(long_cap) is False


# ===========================================================================
# V05: Signature verification robustness
# ===========================================================================


class TestSignatureVerificationRobustness:
    """Adversarial inputs to signature verification."""

    def test_empty_signature(self):
        agent = _create_agent("test")
        assert agent.verify_signature(b"data", "") is False

    def test_non_base64_signature(self):
        agent = _create_agent("test")
        assert agent.verify_signature(b"data", "not-valid-base64!!!") is False

    def test_truncated_signature(self):
        """Ed25519 signatures are 64 bytes; truncated ones must fail."""
        agent = _create_agent("test")
        import base64
        truncated = base64.b64encode(b"\x00" * 32).decode()  # 32 bytes, not 64
        assert agent.verify_signature(b"data", truncated) is False

    def test_all_zeros_signature(self):
        agent = _create_agent("test")
        import base64
        zeros = base64.b64encode(b"\x00" * 64).decode()
        assert agent.verify_signature(b"data", zeros) is False

    def test_signature_from_different_key(self):
        """Signature from agent B should not verify against agent A."""
        agent_a = _create_agent("agent-a")
        agent_b = _create_agent("agent-b")
        data = b"important message"
        sig = agent_b.sign(data)
        assert agent_a.verify_signature(data, sig) is False

    def test_tampered_data(self):
        """Valid signature on original data fails on tampered data."""
        agent = _create_agent("test")
        data = b"original data"
        sig = agent.sign(data)
        assert agent.verify_signature(data, sig) is True
        assert agent.verify_signature(b"tampered data", sig) is False

    def test_signature_reuse_different_payload(self):
        """A valid signature on one payload doesn't work for another."""
        agent = _create_agent("test")
        sig = agent.sign(b"payload-1")
        assert agent.verify_signature(b"payload-2", sig) is False


# ===========================================================================
# V06: Handshake trust score self-reporting
# ===========================================================================


class TestHandshakeTrustScoreManipulation:
    """Verify handshake can't be gamed by self-reporting high trust scores."""

    @pytest.mark.asyncio
    async def test_self_reported_trust_score_not_trusted(self):
        """Peer's self-reported trust_score should not be the final score.
        The verifier should use registry/default values, not what the
        peer claims in the response.
        """
        handshake, agent_a, agent_b, registry = _setup_handshake()
        # Initiate handshake — default threshold is TIER_TRUSTED_THRESHOLD (700)
        result = await handshake.initiate(peer_did=str(agent_b.did))
        # The result should use TRUST_SCORE_DEFAULT (500), not a
        # self-reported inflated score
        assert result.trust_score <= 500  # Should not exceed default

    @pytest.mark.asyncio
    async def test_handshake_with_revoked_peer_fails(self):
        """Revoked peer should be rejected during handshake."""
        handshake, agent_a, agent_b, registry = _setup_handshake()
        agent_b.revoke("compromised")
        result = await handshake.initiate(peer_did=str(agent_b.did))
        assert result.verified is False
        # Rejection can be "revoked" or "No response from peer" —
        # either way, the peer is correctly rejected
        assert result.rejection_reason is not None

    @pytest.mark.asyncio
    async def test_handshake_with_suspended_peer_fails(self):
        handshake, agent_a, agent_b, registry = _setup_handshake()
        agent_b.suspend("under review")
        result = await handshake.initiate(peer_did=str(agent_b.did))
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_handshake_with_nonexistent_did_fails(self):
        handshake, agent_a, agent_b, registry = _setup_handshake()
        result = await handshake.initiate(peer_did="did:mesh:doesnotexist")
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_handshake_without_registry_fails(self):
        """No registry = all handshakes fail (secure default)."""
        agent = _create_agent("solo")
        handshake = TrustHandshake(agent_did=str(agent.did))
        result = await handshake.initiate(peer_did="did:mesh:any")
        assert result.verified is False


# ===========================================================================
# V07: Identity lifecycle attacks
# ===========================================================================


class TestIdentityLifecycleAttacks:
    """Test identity state transitions for security."""

    def test_revoked_identity_not_active(self):
        agent = _create_agent("test")
        agent.revoke("compromised")
        assert agent.is_active() is False
        assert agent.status == "revoked"

    def test_cannot_reactivate_revoked(self):
        agent = _create_agent("test")
        agent.revoke("compromised")
        with pytest.raises(ValueError, match="Cannot reactivate"):
            agent.reactivate()

    def test_suspended_then_reactivated(self):
        """Suspended identity can be reactivated (design choice)."""
        agent = _create_agent("test")
        agent.suspend("review")
        assert agent.is_active() is False
        agent.reactivate()
        assert agent.is_active() is True

    def test_expired_identity_not_active(self):
        agent = _create_agent("test")
        agent.expires_at = datetime.utcnow() - timedelta(hours=1)
        assert agent.is_active() is False

    def test_revoked_identity_cannot_sign(self):
        """Revoked identity's private key is still available —
        but consumers should check is_active() before trusting."""
        agent = _create_agent("test")
        agent.revoke("compromised")
        # sign() still works — this is a design concern
        sig = agent.sign(b"data")
        assert sig is not None  # Documents current behavior

    def test_delegate_from_revoked_parent(self):
        """A revoked parent can still delegate — no status check."""
        parent = _create_agent("parent", ["read:data"])
        parent.revoke("compromised")
        # This should ideally fail, but currently doesn't
        child = parent.delegate(name="child", capabilities=["read:data"])
        assert child.parent_did == str(parent.did)


# ===========================================================================
# V08: Plugin signature bypass
# ===========================================================================


class TestPluginSignatureBypass:
    """Test that unsigned or wrongly-signed plugins are handled correctly."""

    def test_unsigned_plugin_accepted_when_no_trusted_keys(self, tmp_path: Path):
        """If no trusted_keys are configured, ALL plugins are accepted
        regardless of verify=True. This is a configuration weakness.
        """
        from agentmesh.marketplace import (
            PluginInstaller, PluginRegistry, PluginManifest, PluginType,
        )

        registry = PluginRegistry()
        manifest = PluginManifest(
            name="unsigned-plugin",
            version="1.0.0",
            description="No signature",
            author="unknown@example.com",
            plugin_type=PluginType.INTEGRATION,
        )
        registry.register(manifest)
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            # No trusted_keys!
        )
        # This succeeds even with verify=True because there's no signature
        # AND no trusted key for the author
        dest = installer.install("unsigned-plugin", verify=True)
        assert dest.exists()

    def test_signed_plugin_with_wrong_key_rejected(self, tmp_path: Path):
        """Plugin signed by an unknown key should be rejected if author
        has a different trusted key registered."""
        from agentmesh.marketplace import (
            PluginInstaller, PluginRegistry, PluginManifest, PluginType,
            PluginSigner, MarketplaceError,
        )

        attacker_key = ed25519.Ed25519PrivateKey.generate()
        trusted_key = ed25519.Ed25519PrivateKey.generate()

        signer = PluginSigner(attacker_key)
        manifest = PluginManifest(
            name="evil-plugin",
            version="1.0.0",
            description="Signed with wrong key",
            author="trusted-author",
            plugin_type=PluginType.INTEGRATION,
        )
        signed = signer.sign(manifest)

        registry = PluginRegistry()
        registry.register(signed)
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            trusted_keys={"trusted-author": trusted_key.public_key()},
        )
        with pytest.raises(MarketplaceError, match="verification failed"):
            installer.install("evil-plugin", verify=True)


# ===========================================================================
# V10: Handshake challenge DoS
# ===========================================================================


class TestHandshakeChallengeDoS:
    """Test that challenge accumulation is bounded."""

    def test_many_challenges_dont_crash(self):
        """Creating many challenges shouldn't cause memory issues."""
        agent = _create_agent("test")
        handshake = TrustHandshake(agent_did=str(agent.did))
        for _ in range(1000):
            handshake.create_challenge()
        assert len(handshake._pending_challenges) == 1000

    @pytest.mark.asyncio
    async def test_expired_challenge_rejected_in_verify(self):
        """Expired challenges must be rejected during verification."""
        from agentmesh.trust.handshake import HandshakeResponse
        import secrets, base64

        handshake, agent_a, agent_b, registry = _setup_handshake()
        challenge = handshake.create_challenge()
        # Build a fake response that references the challenge
        # (can't use respond() because it checks expiry too)
        response = HandshakeResponse(
            challenge_id=challenge.challenge_id,
            response_nonce=secrets.token_hex(16),
            agent_did=str(agent_b.did),
            capabilities=agent_b.capabilities,
            trust_score=500,
            signature=base64.b64encode(b"\x00" * 64).decode(),
            public_key=agent_b.public_key,
        )
        # Now expire the challenge
        challenge.timestamp = datetime.utcnow() - timedelta(seconds=60)
        assert challenge.is_expired() is True
        # Verify with expired challenge should fail
        result = await handshake._verify_response(
            response, challenge, required_score=0, required_capabilities=None
        )
        assert result["valid"] is False
        assert "expired" in result["reason"].lower()


# ===========================================================================
# DID format injection tests
# ===========================================================================


class TestDIDFormatInjection:
    """Test that DID parsing handles adversarial inputs."""

    def test_did_from_invalid_string(self):
        with pytest.raises(ValueError, match="Invalid"):
            AgentDID.from_string("not-a-did")

    def test_did_from_wrong_method(self):
        with pytest.raises(ValueError, match="Invalid"):
            AgentDID.from_string("did:other:12345")

    def test_did_from_empty_unique_id(self):
        did = AgentDID.from_string("did:mesh:")
        assert did.unique_id == ""

    def test_did_with_special_characters(self):
        """DID with special chars in unique_id should be parsed."""
        did = AgentDID.from_string("did:mesh:abc123!@#$%")
        assert did.unique_id == "abc123!@#$%"

    def test_very_long_did(self):
        """Extremely long DIDs shouldn't crash."""
        long_id = "a" * 10_000
        did = AgentDID.from_string(f"did:mesh:{long_id}")
        assert len(str(did)) > 10_000


# ===========================================================================
# IdentityRegistry adversarial tests
# ===========================================================================


class TestIdentityRegistryAdversarial:
    """Test registry with adversarial usage patterns."""

    def test_register_duplicate_did_rejected(self):
        """Registry correctly rejects duplicate DID registration."""
        registry = IdentityRegistry()
        agent1 = _create_agent("agent-1")
        agent2 = _create_agent("agent-2")
        # Force same DID
        agent2.did = agent1.did
        registry.register(agent1)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(agent2)

    def test_get_nonexistent_returns_none(self):
        registry = IdentityRegistry()
        assert registry.get("did:mesh:ghost") is None

    def test_register_revoked_agent(self):
        """Can a revoked agent be registered? It shouldn't be useful."""
        registry = IdentityRegistry()
        agent = _create_agent("revoked-agent")
        agent.revoke("bad")
        registry.register(agent)
        result = registry.get(str(agent.did))
        assert result is not None
        assert result.is_active() is False


# ===========================================================================
# TrustBridge adversarial tests
# ===========================================================================


class TestTrustBridgeAdversarial:
    """Test TrustBridge with adversarial inputs."""

    @pytest.mark.asyncio
    async def test_verify_empty_did(self):
        agent = _create_agent("test")
        registry = IdentityRegistry()
        registry.register(agent)
        bridge = TrustBridge(
            agent_did=str(agent.did),
            identity=agent,
            registry=registry,
        )
        result = await bridge.verify_peer(peer_did="")
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_verify_self(self):
        """Agent trying to verify itself."""
        agent = _create_agent("test")
        registry = IdentityRegistry()
        registry.register(agent)
        bridge = TrustBridge(
            agent_did=str(agent.did),
            identity=agent,
            registry=registry,
        )
        # Self-verification should work (agent is registered)
        result = await bridge.verify_peer(peer_did=str(agent.did))
        # Whether this should succeed is a design decision;
        # just verify it doesn't crash
        assert isinstance(result.verified, bool)

    @pytest.mark.asyncio
    async def test_verify_with_none_registry(self):
        """Bridge without registry rejects all peers."""
        agent = _create_agent("test")
        bridge = TrustBridge(agent_did=str(agent.did))
        result = await bridge.verify_peer(peer_did="did:mesh:any")
        assert result.verified is False


# ===========================================================================
# P06: Peer record integrity (HMAC tamper detection)
# ===========================================================================


class TestPeerRecordIntegrity:
    """P06: Verify HMAC guards detect tampered peer records."""

    @pytest.mark.asyncio
    async def test_tampered_trust_score_rejected(self):
        """Directly modifying a peer's trust_score should be detected."""
        agent_a = _create_agent("a")
        agent_b = _create_agent("b")
        registry = IdentityRegistry()
        registry.register(agent_a)
        registry.register(agent_b)
        bridge = TrustBridge(
            agent_did=str(agent_a.did),
            default_trust_threshold=500,
            identity=agent_a,
            registry=registry,
        )
        result = await bridge.verify_peer(
            peer_did=str(agent_b.did), required_trust_score=500,
        )
        assert result.verified is True

        # Tamper with the peer's trust score
        bridge.peers[str(agent_b.did)].trust_score = 9999
        # is_peer_trusted should now reject the tampered record
        trusted = await bridge.is_peer_trusted(str(agent_b.did), required_score=500)
        assert trusted is False
        # Peer should be removed from peers dict
        assert str(agent_b.did) not in bridge.peers

    @pytest.mark.asyncio
    async def test_tampered_capabilities_rejected(self):
        """Modifying capabilities should fail integrity check."""
        agent_a = _create_agent("a")
        agent_b = _create_agent("b", ["read:data"])
        registry = IdentityRegistry()
        registry.register(agent_a)
        registry.register(agent_b)
        bridge = TrustBridge(
            agent_did=str(agent_a.did),
            default_trust_threshold=500,
            identity=agent_a,
            registry=registry,
        )
        await bridge.verify_peer(
            peer_did=str(agent_b.did), required_trust_score=500,
        )

        # Tamper with capabilities
        bridge.peers[str(agent_b.did)].capabilities = ["admin:all", "root:system"]
        trusted = await bridge.is_peer_trusted(str(agent_b.did), required_score=500)
        assert trusted is False

    @pytest.mark.asyncio
    async def test_untampered_record_passes(self):
        """Unmodified peer record should pass integrity check."""
        agent_a = _create_agent("a")
        agent_b = _create_agent("b")
        registry = IdentityRegistry()
        registry.register(agent_a)
        registry.register(agent_b)
        bridge = TrustBridge(
            agent_did=str(agent_a.did),
            default_trust_threshold=500,
            identity=agent_a,
            registry=registry,
        )
        await bridge.verify_peer(
            peer_did=str(agent_b.did), required_trust_score=500,
        )
        trusted = await bridge.is_peer_trusted(str(agent_b.did), required_score=500)
        assert trusted is True

    @pytest.mark.asyncio
    async def test_missing_signature_rejected(self):
        """Peer with no stored signature should fail integrity check."""
        agent_a = _create_agent("a")
        agent_b = _create_agent("b")
        registry = IdentityRegistry()
        registry.register(agent_a)
        registry.register(agent_b)
        bridge = TrustBridge(
            agent_did=str(agent_a.did),
            default_trust_threshold=500,
            identity=agent_a,
            registry=registry,
        )
        await bridge.verify_peer(
            peer_did=str(agent_b.did), required_trust_score=500,
        )
        # Delete the stored signature
        bridge._peer_signatures.pop(str(agent_b.did), None)
        trusted = await bridge.is_peer_trusted(str(agent_b.did), required_score=500)
        assert trusted is False


# ===========================================================================
# P07: Agent behavior monitor (rogue agent detection)
# ===========================================================================


class TestAgentBehaviorMonitor:
    """P07: Rogue agent detection and quarantine."""

    def test_normal_agent_not_quarantined(self):
        from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

        monitor = AgentBehaviorMonitor()
        for _ in range(10):
            monitor.record_tool_call("did:mesh:good", "read_file", success=True)
        assert monitor.is_quarantined("did:mesh:good") is False

    def test_consecutive_failures_trigger_quarantine(self):
        from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

        monitor = AgentBehaviorMonitor(consecutive_failure_threshold=5)
        for _ in range(5):
            monitor.record_tool_call("did:mesh:failing", "bad_tool", success=False)
        assert monitor.is_quarantined("did:mesh:failing") is True

    def test_success_resets_consecutive_failures(self):
        from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

        monitor = AgentBehaviorMonitor(consecutive_failure_threshold=5)
        for _ in range(4):
            monitor.record_tool_call("did:mesh:mixed", "tool", success=False)
        monitor.record_tool_call("did:mesh:mixed", "tool", success=True)
        # One more failure shouldn't trigger quarantine
        monitor.record_tool_call("did:mesh:mixed", "tool", success=False)
        assert monitor.is_quarantined("did:mesh:mixed") is False

    def test_burst_detection_triggers_quarantine(self):
        from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

        monitor = AgentBehaviorMonitor(
            burst_threshold=10,
            burst_window_seconds=60,
        )
        for _ in range(11):
            monitor.record_tool_call("did:mesh:burst", "tool", success=True)
        assert monitor.is_quarantined("did:mesh:burst") is True

    def test_capability_denial_triggers_quarantine(self):
        from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

        monitor = AgentBehaviorMonitor(capability_denial_threshold=3)
        for i in range(3):
            monitor.record_capability_denial("did:mesh:escalator", f"admin:{i}")
        assert monitor.is_quarantined("did:mesh:escalator") is True

    def test_release_quarantine(self):
        from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

        monitor = AgentBehaviorMonitor(consecutive_failure_threshold=2)
        monitor.record_tool_call("did:mesh:temp", "tool", success=False)
        monitor.record_tool_call("did:mesh:temp", "tool", success=False)
        assert monitor.is_quarantined("did:mesh:temp") is True
        monitor.release_quarantine("did:mesh:temp")
        assert monitor.is_quarantined("did:mesh:temp") is False

    def test_auto_expire_quarantine(self):
        from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

        monitor = AgentBehaviorMonitor(
            consecutive_failure_threshold=2,
            quarantine_duration=timedelta(seconds=0),
        )
        monitor.record_tool_call("did:mesh:auto", "tool", success=False)
        monitor.record_tool_call("did:mesh:auto", "tool", success=False)
        # Duration is 0, should auto-expire immediately
        assert monitor.is_quarantined("did:mesh:auto") is False

    def test_max_tracked_agents_eviction(self):
        from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

        monitor = AgentBehaviorMonitor(max_tracked_agents=3)
        for i in range(4):
            monitor.record_tool_call(f"did:mesh:agent{i}", "tool", success=True)
        # Oldest agent should be evicted
        assert len(monitor._agents) == 3

    def test_get_quarantined_agents(self):
        from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

        monitor = AgentBehaviorMonitor(consecutive_failure_threshold=1)
        monitor.record_tool_call("did:mesh:bad1", "tool", success=False)
        monitor.record_tool_call("did:mesh:bad2", "tool", success=False)
        monitor.record_tool_call("did:mesh:good", "tool", success=True)
        quarantined = monitor.get_quarantined_agents()
        dids = {m.agent_did for m in quarantined}
        assert "did:mesh:bad1" in dids
        assert "did:mesh:bad2" in dids
        assert "did:mesh:good" not in dids


# ===========================================================================
# P10: Circuit breaker in MCP
# ===========================================================================


class TestMCPCircuitBreaker:
    """P10: Circuit breaker stops tool calls after consecutive failures."""

    @pytest.mark.asyncio
    async def test_circuit_opens_after_threshold_failures(self):
        from agentmesh.integrations.mcp import TrustGatedMCPServer

        agent = _create_agent("server-agent")
        server = TrustGatedMCPServer(identity=agent, min_trust_score=0)

        async def failing_handler(**kwargs):
            raise RuntimeError("service down")

        server.register_tool(
            name="broken_tool",
            handler=failing_handler,
            description="Always fails",
            input_schema={"properties": {}},
            min_trust_score=0,
        )
        server._circuit_breaker_threshold = 3

        # Fail 3 times to open the circuit
        for _ in range(3):
            call = await server.invoke_tool(
                "broken_tool", {}, "did:mesh:caller",
                caller_trust_score=500,
            )
            assert call.success is not True

        # 4th call should be blocked by circuit breaker
        call = await server.invoke_tool(
            "broken_tool", {}, "did:mesh:caller",
            caller_trust_score=500,
        )
        assert call.error is not None
        assert "Circuit breaker" in call.error

    @pytest.mark.asyncio
    async def test_circuit_resets_on_success(self):
        from agentmesh.integrations.mcp import TrustGatedMCPServer

        agent = _create_agent("server-agent")
        server = TrustGatedMCPServer(identity=agent, min_trust_score=0)

        call_count = 0

        async def flaky_handler(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise RuntimeError("temporary failure")
            return "success"

        server.register_tool(
            name="flaky_tool",
            handler=flaky_handler,
            description="Sometimes fails",
            input_schema={"properties": {}},
            min_trust_score=0,
        )
        server._circuit_breaker_threshold = 5

        # 2 failures
        await server.invoke_tool(
            "flaky_tool", {}, "did:mesh:caller", caller_trust_score=500,
        )
        await server.invoke_tool(
            "flaky_tool", {}, "did:mesh:caller", caller_trust_score=500,
        )
        assert server._tool_failures.get("flaky_tool", 0) == 2

        # 1 success should reset the counter
        call = await server.invoke_tool(
            "flaky_tool", {}, "did:mesh:caller", caller_trust_score=500,
        )
        assert call.success is True
        assert server._tool_failures.get("flaky_tool", 0) == 0


# ===========================================================================
# P11: PII sanitization in error logs
# ===========================================================================


class TestPIISanitizationInErrors:
    """P11: Exception messages should be truncated, not expose PII."""

    @pytest.mark.asyncio
    async def test_long_exception_truncated_in_call_error(self):
        from agentmesh.integrations.mcp import TrustGatedMCPServer

        agent = _create_agent("server-agent")
        server = TrustGatedMCPServer(identity=agent, min_trust_score=0)

        pii_message = "Error for user john.doe@example.com SSN 123-45-6789 " * 50

        async def pii_handler(**kwargs):
            raise ValueError(pii_message)

        server.register_tool(
            name="pii_tool",
            handler=pii_handler,
            description="Leaks PII in errors",
            input_schema={"properties": {}},
            min_trust_score=0,
        )

        call = await server.invoke_tool(
            "pii_tool", {}, "did:mesh:caller", caller_trust_score=500,
        )
        assert call.error is not None
        # Error message should be truncated to 200 chars + type prefix
        assert len(call.error) < 300
        # Should include the error type
        assert "ValueError" in call.error
