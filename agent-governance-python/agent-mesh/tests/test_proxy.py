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


class TestMCPProxyWireProtocolContext:
    """Verify _handle_tool_call populates sql.* and k8s.* context for policy evaluation."""

    def _make_proxy(self):
        return MCPProxy(target_command=["test"], policy="permissive")

    def _make_tool_call_message(self, tool_name: str, arguments: dict) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }

    def test_sql_query_argument_populates_sql_context(self):
        """Tool call with 'query' argument injects sql.query into policy context."""
        proxy = self._make_proxy()
        captured = {}

        original_evaluate = proxy.policy_engine.evaluate

        def capture_evaluate(agent_did, context, stage="pre_tool"):
            captured["context"] = context
            return original_evaluate(agent_did, context, stage)

        proxy.policy_engine.evaluate = capture_evaluate

        import asyncio
        message = self._make_tool_call_message(
            "db_query", {"query": "SELECT * FROM users"}
        )
        asyncio.run(proxy._handle_tool_call(message))

        assert "sql" in captured["context"]
        assert captured["context"]["sql"]["query"] == "SELECT * FROM users"

    def test_sql_sql_argument_also_works(self):
        """Tool call with 'sql' argument (alternate key) injects sql.query."""
        proxy = self._make_proxy()
        captured = {}

        original_evaluate = proxy.policy_engine.evaluate

        def capture_evaluate(agent_did, context, stage="pre_tool"):
            captured["context"] = context
            return original_evaluate(agent_did, context, stage)

        proxy.policy_engine.evaluate = capture_evaluate

        import asyncio
        message = self._make_tool_call_message(
            "execute_sql", {"sql": "DROP TABLE users"}
        )
        asyncio.run(proxy._handle_tool_call(message))

        assert "sql" in captured["context"]
        assert captured["context"]["sql"]["query"] == "DROP TABLE users"

    def test_no_sql_argument_no_sql_context(self):
        """Tool call without query argument does not inject sql context."""
        proxy = self._make_proxy()
        captured = {}

        original_evaluate = proxy.policy_engine.evaluate

        def capture_evaluate(agent_did, context, stage="pre_tool"):
            captured["context"] = context
            return original_evaluate(agent_did, context, stage)

        proxy.policy_engine.evaluate = capture_evaluate

        import asyncio
        message = self._make_tool_call_message(
            "filesystem_read", {"path": "/tmp/test.txt"}
        )
        asyncio.run(proxy._handle_tool_call(message))

        assert "sql" not in captured["context"]

    def test_k8s_api_path_populates_k8s_context(self):
        """Tool call with method + /api/ path injects k8s context."""
        proxy = self._make_proxy()
        captured = {}

        original_evaluate = proxy.policy_engine.evaluate

        def capture_evaluate(agent_did, context, stage="pre_tool"):
            captured["context"] = context
            return original_evaluate(agent_did, context, stage)

        proxy.policy_engine.evaluate = capture_evaluate

        import asyncio
        message = self._make_tool_call_message(
            "kubectl_api",
            {"method": "DELETE", "path": "/api/v1/namespaces/production/pods/mypod"},
        )
        asyncio.run(proxy._handle_tool_call(message))

        assert "k8s" in captured["context"]
        assert captured["context"]["k8s"]["method"] == "DELETE"
        assert captured["context"]["k8s"]["path"] == "/api/v1/namespaces/production/pods/mypod"

    def test_non_k8s_path_does_not_inject_k8s_context(self):
        """Tool call with method + non-K8s path does not inject k8s context."""
        proxy = self._make_proxy()
        captured = {}

        original_evaluate = proxy.policy_engine.evaluate

        def capture_evaluate(agent_did, context, stage="pre_tool"):
            captured["context"] = context
            return original_evaluate(agent_did, context, stage)

        proxy.policy_engine.evaluate = capture_evaluate

        import asyncio
        message = self._make_tool_call_message(
            "http_request",
            {"method": "GET", "path": "/health"},
        )
        asyncio.run(proxy._handle_tool_call(message))

        assert "k8s" not in captured["context"]
