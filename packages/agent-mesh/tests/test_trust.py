# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh Trust module."""

import pytest
from datetime import datetime

from agentmesh.trust import (
    TrustBridge,
    ProtocolBridge,
    TrustHandshake,
    HandshakeResult,
    CapabilityScope,
    CapabilityGrant,
    CapabilityRegistry,
)


class TestTrustBridge:
    """Tests for TrustBridge."""
    
    def test_create_bridge(self):
        """Test creating a trust bridge."""
        bridge = TrustBridge(agent_did="did:mesh:test")
        
        assert bridge is not None
        assert bridge.agent_did == "did:mesh:test"
    
    def test_default_trust_threshold(self):
        """Test default trust threshold is 700."""
        bridge = TrustBridge(agent_did="did:mesh:test")
        
        assert bridge.default_trust_threshold == 700
    
    def test_get_trusted_peers_empty(self):
        """Test getting trusted peers when none exist."""
        bridge = TrustBridge(agent_did="did:mesh:test")
        
        peers = bridge.get_trusted_peers()
        assert len(peers) == 0
    
    @pytest.mark.asyncio
    async def test_verify_peer(self):
        """Test verifying a peer."""
        bridge = TrustBridge(agent_did="did:mesh:agent-a")
        
        # Verification requires network, so this tests the flow
        result = await bridge.verify_peer(
            peer_did="did:mesh:agent-b",
            protocol="iatp",
        )
        
        assert isinstance(result, HandshakeResult)


class TestProtocolBridge:
    """Tests for ProtocolBridge."""
    
    def test_create_protocol_bridge(self):
        """Test creating a protocol bridge."""
        bridge = ProtocolBridge(agent_did="did:mesh:test")
        
        assert bridge is not None
        assert "a2a" in bridge.supported_protocols
        assert "mcp" in bridge.supported_protocols
        assert "iatp" in bridge.supported_protocols
    
    def test_a2a_to_mcp_translation(self):
        """Protocol translation is available."""
        bridge = ProtocolBridge(agent_did="did:mesh:test")
        
        # Bridge has _a2a_to_mcp for protocol translation
        assert hasattr(bridge, '_a2a_to_mcp')
        result = bridge._a2a_to_mcp({"task_type": "run", "parameters": {"x": 1}})
        assert result["method"] == "tools/call"
    
    def test_mcp_to_a2a_translation(self):
        """Protocol translation is available."""
        bridge = ProtocolBridge(agent_did="did:mesh:test")
        
        assert hasattr(bridge, '_mcp_to_a2a')
        result = bridge._mcp_to_a2a({"params": {"name": "run", "arguments": {"x": 1}}})
        assert result["task_type"] == "run"


class TestTrustHandshake:
    """Tests for TrustHandshake."""
    
    def test_create_handshake(self):
        """Test creating a trust handshake."""
        handshake = TrustHandshake(agent_did="did:mesh:agent-a")
        
        assert handshake is not None
        assert handshake.agent_did == "did:mesh:agent-a"
    
    def test_create_challenge(self):
        """Test challenge creation."""
        handshake = TrustHandshake(agent_did="did:mesh:agent-a")
        
        challenge = handshake.create_challenge()
        
        assert challenge.nonce is not None
        assert challenge.timestamp is not None
        assert len(challenge.nonce) > 0
    
    @pytest.mark.asyncio
    async def test_handshake_initiate(self):
        """Test initiating a handshake."""
        handshake = TrustHandshake(
            agent_did="did:mesh:agent-a",
        )
        
        result = await handshake.initiate(
            peer_did="did:mesh:agent-b",
            required_trust_score=500,
        )
        
        assert isinstance(result, HandshakeResult)


class TestHandshakeResult:
    """Tests for HandshakeResult."""
    
    def test_successful_result(self):
        """Test creating a successful result."""
        result = HandshakeResult(
            verified=True,
            peer_did="did:mesh:peer",
            trust_score=750,
            capabilities=["read", "write"],
        )
        
        assert result.verified
        assert result.trust_score == 750
        assert result.rejection_reason is None
    
    def test_failed_result(self):
        """Test creating a failed result."""
        result = HandshakeResult(
            verified=False,
            peer_did="did:mesh:peer",
            trust_score=0,
            rejection_reason="Peer not found",
        )
        
        assert not result.verified
        assert result.rejection_reason == "Peer not found"


class TestCapabilities:
    """Tests for CapabilityScope and CapabilityRegistry."""
    
    def test_capability_scope_creation(self):
        """Test creating a capability scope."""
        scope = CapabilityScope(
            agent_did="did:mesh:test",
        )
        
        # Add a grant
        from agentmesh.trust import CapabilityGrant
        grant = CapabilityGrant.create(
            capability="read:file",
            granted_to="did:mesh:test",
            granted_by="did:mesh:admin",
        )
        scope.add_grant(grant)
        
        assert scope.agent_did == "did:mesh:test"
        assert len(scope.grants) == 1
    
    def test_capability_scope_allows(self):
        """Test checking if action is allowed."""
        scope = CapabilityScope(
            agent_did="did:mesh:test",
        )
        
        from agentmesh.trust import CapabilityGrant
        grant = CapabilityGrant.create(
            capability="read:api",
            granted_to="did:mesh:test",
            granted_by="did:mesh:admin",
        )
        scope.add_grant(grant)
        
        assert scope.has_capability("read:api")
        assert not scope.has_capability("write:api")
        assert not scope.has_capability("delete:api")
    
    def test_capability_registry_register(self):
        """Test registering capabilities."""
        registry = CapabilityRegistry()
        
        # Grant capabilities
        grant = registry.grant(
            capability="get:api",
            to_agent="did:mesh:test",
            from_agent="did:mesh:admin",
        )
        
        scope = registry.get_scope("did:mesh:test")
        assert len(scope.grants) == 1
        assert grant.capability == "get:api"
    
    def test_capability_registry_is_allowed(self):
        """Test checking if action is allowed for agent."""
        registry = CapabilityRegistry()
        
        registry.grant(
            capability="read:resource",
            to_agent="did:mesh:test",
            from_agent="did:mesh:admin",
        )
        
        # Should be allowed
        assert registry.check(
            agent_did="did:mesh:test",
            capability="read:resource",
        )
        
        # Should be denied - wrong capability
        assert not registry.check(
            agent_did="did:mesh:test",
            capability="write:resource",
        )
    
    def test_capability_grant(self):
        """Test capability grant."""
        grant = CapabilityGrant.create(
            capability="read:test",
            granted_to="did:mesh:test",
            granted_by="did:mesh:admin",
        )
        
        assert grant.is_valid()
        assert grant.active


# Note: A2AAdapter and MCPAdapter tests removed as they're not exported from the trust module
# These adapters are internal implementation details of the protocol bridges
