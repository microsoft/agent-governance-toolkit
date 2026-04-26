# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for langchain-agentmesh."""

import pytest
from langchain_agentmesh import (
    CMVKIdentity,
    CMVKSignature,
    TrustHandshake,
    TrustVerificationResult,
    TrustGatedTool,
    TrustedToolExecutor,
    TrustCallbackHandler,
)


class TestCMVKIdentity:
    """Tests for CMVKIdentity."""
    
    def test_generate_identity(self):
        """Test identity generation."""
        identity = CMVKIdentity.generate(
            agent_name="test-agent",
            capabilities=["read", "write"]
        )
        
        assert identity.did.startswith("did:cmvk:")
        assert identity.agent_name == "test-agent"
        assert identity.public_key
        assert identity.private_key
        assert identity.capabilities == ["read", "write"]
    
    def test_sign_and_verify(self):
        """Test signing and verification."""
        identity = CMVKIdentity.generate("test-agent")
        
        data = "test data to sign"
        signature = identity.sign(data)
        
        assert signature.public_key == identity.public_key
        assert signature.signature
        
        # Verify signature
        assert identity.verify_signature(data, signature)
    
    def test_has_capability(self):
        """Test capability checking."""
        identity = CMVKIdentity.generate(
            agent_name="test-agent",
            capabilities=["read", "search"]
        )
        
        assert identity.has_capability("read")
        assert identity.has_capability("search")
        assert not identity.has_capability("write")
    
    def test_wildcard_capability(self):
        """Test wildcard capability."""
        identity = CMVKIdentity.generate(
            agent_name="admin-agent",
            capabilities=["*"]
        )
        
        assert identity.has_capability("anything")
        assert identity.has_capability("read")
        assert identity.has_capability("delete")
    
    def test_to_dict_excludes_private_key(self):
        """Test that to_dict excludes private key."""
        identity = CMVKIdentity.generate("test-agent")
        data = identity.to_dict()
        
        assert "private_key" not in data
        assert data["did"] == identity.did
        assert data["public_key"] == identity.public_key


class TestTrustHandshake:
    """Tests for TrustHandshake."""
    
    def test_verify_peer_success(self):
        """Test successful peer verification."""
        identity = CMVKIdentity.generate("my-agent")
        handshake = TrustHandshake(identity=identity)
        
        peer_card = {
            "did": "did:cmvk:peer123",
            "public_key": "test-key",
            "capabilities": ["analyze", "summarize"],
        }
        
        result = handshake.verify_peer(
            peer_card,
            required_capabilities=["analyze"],
            min_trust_score=0.5
        )
        
        assert result.verified
        assert result.trust_score >= 0.5
    
    def test_verify_peer_missing_capability(self):
        """Test peer verification with missing capability."""
        identity = CMVKIdentity.generate("my-agent")
        handshake = TrustHandshake(identity=identity)
        
        peer_card = {
            "did": "did:cmvk:peer123",
            "public_key": "test-key",
            "capabilities": ["analyze"],
        }
        
        result = handshake.verify_peer(
            peer_card,
            required_capabilities=["analyze", "delete"],
        )
        
        assert not result.verified
        assert "Missing capabilities" in result.reason
    
    def test_verify_peer_caching(self):
        """Test that verification results are cached."""
        identity = CMVKIdentity.generate("my-agent")
        handshake = TrustHandshake(identity=identity, cache_ttl_seconds=300)
        
        peer_card = {
            "did": "did:cmvk:peer123",
            "public_key": "test-key",
            "capabilities": ["read"],
        }
        
        # First verification
        result1 = handshake.verify_peer(peer_card)
        
        # Second verification should be cached
        result2 = handshake.verify_peer(peer_card)
        
        assert result1.verified == result2.verified
        assert result1.trust_score == result2.trust_score


class TestTrustGatedTool:
    """Tests for TrustGatedTool."""
    
    def test_check_trust_success(self):
        """Test successful trust check."""
        from langchain_core.tools import tool
        
        @tool
        def dummy_tool(query: str) -> str:
            """Dummy tool."""
            return f"Result: {query}"
        
        gated = TrustGatedTool(
            tool=dummy_tool,
            required_capabilities=["search"],
            min_trust_score=0.5,
        )
        
        identity = CMVKIdentity.generate("agent", ["search", "read"])
        
        assert gated.check_trust(identity, trust_score=0.7)
    
    def test_check_trust_missing_capability(self):
        """Test trust check with missing capability."""
        from langchain_core.tools import tool
        
        @tool
        def dummy_tool(query: str) -> str:
            """Dummy tool."""
            return f"Result: {query}"
        
        gated = TrustGatedTool(
            tool=dummy_tool,
            required_capabilities=["admin"],
        )
        
        identity = CMVKIdentity.generate("agent", ["search"])
        
        assert not gated.check_trust(identity)


class TestTrustCallbackHandler:
    """Tests for TrustCallbackHandler."""
    
    def test_metrics_tracking(self):
        """Test that metrics are tracked."""
        identity = CMVKIdentity.generate("test-agent", ["llm"])
        handler = TrustCallbackHandler(identity=identity)
        
        metrics = handler.get_metrics()
        
        assert metrics["agent_did"] == identity.did
        assert metrics["total_calls"] == 0
        assert metrics["trust_score"] >= 0.5
    
    def test_audit_log(self):
        """Test audit log functionality."""
        identity = CMVKIdentity.generate("test-agent")
        handler = TrustCallbackHandler(identity=identity)
        
        # Initially empty
        assert len(handler.get_audit_log()) == 0
        
        # After clearing
        handler.clear_audit_log()
        assert len(handler.get_audit_log()) == 0
