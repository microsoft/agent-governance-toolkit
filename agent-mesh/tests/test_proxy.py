# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh MCP Proxy."""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from agentmesh.cli.proxy import MCPProxy


class TestMCPProxy:
    """Tests for MCP proxy functionality."""
    
    def test_proxy_initialization(self):
        """Test proxy initializes with correct settings."""
        proxy = MCPProxy(
            target_command=["echo", "test"],
            policy="strict",
            identity_name="test-proxy",
            enable_footer=True,
        )
        
        assert proxy.target_command == ["echo", "test"]
        assert proxy.policy_level == "strict"
        assert proxy.enable_footer is True
        assert proxy.trust_score == 800
    
    def test_proxy_policy_levels(self):
        """Test different policy levels are loaded."""
        strict_proxy = MCPProxy(
            target_command=["test"],
            policy="strict",
        )
        assert strict_proxy.policy_level == "strict"
        
        moderate_proxy = MCPProxy(
            target_command=["test"],
            policy="moderate",
        )
        assert moderate_proxy.policy_level == "moderate"
        
        permissive_proxy = MCPProxy(
            target_command=["test"],
            policy="permissive",
        )
        assert permissive_proxy.policy_level == "permissive"
    
    def test_add_verification_footer(self):
        """Test verification footer is added correctly."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="strict",
            enable_footer=True,
        )
        
        # Create a mock MCP result message
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {"type": "text", "text": "Original content"}
                ]
            }
        }
        
        modified = proxy._add_verification_footer(message)
        
        assert "result" in modified
        assert "content" in modified["result"]
        
        # Check footer was added
        content_list = modified["result"]["content"]
        assert len(content_list) > 1
        
        footer_item = content_list[-1]
        assert "AgentMesh" in footer_item["text"]
        assert str(proxy.trust_score) in footer_item["text"]
    
    def test_policy_check_blocked_operation(self):
        """Test policy blocks dangerous operations."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="strict",
        )
        
        # Test blocking filesystem write
        context = {
            "action": {
                "tool": "filesystem_write",
                "path": "/home/user/test.txt",
            }
        }
        
        decision = proxy.policy_engine.evaluate(proxy.identity.did, context)
        
        # Strict policy should block writes
        assert not decision.allowed
    
    def test_policy_check_allowed_operation(self):
        """Test policy allows safe operations."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="strict",
        )
        
        # Test allowing filesystem read
        context = {
            "action": {
                "tool": "filesystem_read",
                "path": "/home/user/test.txt",
            }
        }
        
        decision = proxy.policy_engine.evaluate(proxy.identity.did, context)
        
        # Strict policy should allow reads
        assert decision.allowed
    
    def test_policy_check_sensitive_paths(self):
        """Test policy blocks access to sensitive paths."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="strict",
        )
        
        # Test blocking access to /etc
        sensitive_paths = ["/etc/passwd", "/root/.ssh", "/etc/shadow"]
        
        for path in sensitive_paths:
            context = {
                "action": {
                    "tool": "filesystem_read",
                    "path": path,
                }
            }
            
            decision = proxy.policy_engine.evaluate(proxy.identity.did, context)
            
            # Should block sensitive paths
            assert not decision.allowed, f"Should block {path}"
    
    def test_trust_score_increases_on_success(self):
        """Test trust score increases on successful operations."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="permissive",
        )
        
        initial_score = proxy.trust_score
        
        # Simulate successful operation
        proxy._update_trust_score("test_tool", allowed=True)
        
        assert proxy.trust_score > initial_score
    
    def test_trust_score_decreases_on_block(self):
        """Test trust score decreases when operations are blocked."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="strict",
        )
        
        initial_score = proxy.trust_score
        
        # Simulate blocked operation
        proxy._update_trust_score("dangerous_tool", allowed=False)
        
        assert proxy.trust_score < initial_score
    
    def test_trust_score_bounds(self):
        """Test trust score stays within bounds."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="permissive",
        )
        
        # Try to increase beyond max
        for _ in range(300):
            proxy._update_trust_score("tool", allowed=True)
        
        assert proxy.trust_score <= 1000
        
        # Try to decrease below min
        for _ in range(300):
            proxy._update_trust_score("tool", allowed=False)
        
        assert proxy.trust_score >= 0
    
    def test_audit_logging(self):
        """Test audit logging captures tool calls."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="moderate",
        )
        
        # Mock policy decision
        from agentmesh.governance import PolicyDecision
        decision = PolicyDecision(
            allowed=True,
            action="allow",
            policy_name="test-policy",
            matched_rule="test-rule",
        )
        
        # Should not raise exception
        proxy._audit_log_tool_call(
            tool_name="test_tool",
            arguments={"param": "value"},
            decision=decision
        )


class TestProxyPolicyEngine:
    """Tests for proxy policy engine integration."""
    
    def test_strict_policy_rules(self):
        """Test strict policy has appropriate rules."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="strict",
        )
        
        policies = proxy.policy_engine.list_policies()
        assert len(policies) > 0
        assert "strict-mcp-policy" in policies
    
    def test_moderate_policy_rules(self):
        """Test moderate policy has appropriate rules."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="moderate",
        )
        
        policies = proxy.policy_engine.list_policies()
        assert "moderate-mcp-policy" in policies
    
    def test_permissive_policy_rules(self):
        """Test permissive policy has appropriate rules."""
        proxy = MCPProxy(
            target_command=["test"],
            policy="permissive",
        )
        
        policies = proxy.policy_engine.list_policies()
        assert "permissive-mcp-policy" in policies
