"""
Tests for MCP Trust Proxy.
"""

import pytest

from mcp_trust_proxy import AuthResult, ToolPolicy, TrustProxy


def _auth(proxy, did="did:mesh:a1", score=500, tool="search", caps=None):
    return proxy.authorize(
        agent_did=did,
        agent_trust_score=score,
        tool_name=tool,
        agent_capabilities=caps or [],
    )


class TestToolPolicy:
    def test_defaults(self):
        p = ToolPolicy()
        assert p.min_trust == 0
        assert not p.blocked
        assert p.max_calls_per_minute == 0

    def test_to_dict(self):
        p = ToolPolicy(min_trust=500, blocked=True)
        d = p.to_dict()
        assert d["min_trust"] == 500
        assert d["blocked"] is True


class TestAuthResult:
    def test_to_dict(self):
        r = AuthResult(allowed=True, tool_name="search", agent_did="d1", reason="ok")
        d = r.to_dict()
        assert d["allowed"] is True
        assert d["tool"] == "search"


class TestTrustProxyBasic:
    def test_allow_default(self):
        proxy = TrustProxy(default_min_trust=100)
        assert _auth(proxy, score=200).allowed

    def test_deny_low_trust(self):
        proxy = TrustProxy(default_min_trust=500)
        r = _auth(proxy, score=200)
        assert not r.allowed
        assert "Trust score" in r.reason

    def test_deny_missing_did(self):
        proxy = TrustProxy(require_did=True)
        r = _auth(proxy, did="")
        assert not r.allowed
        assert "DID is required" in r.reason

    def test_allow_no_did_required(self):
        proxy = TrustProxy(require_did=False, default_min_trust=0)
        assert _auth(proxy, did="", score=0).allowed

    def test_deny_blocked_did(self):
        proxy = TrustProxy(blocked_dids=["did:mesh:evil"])
        r = _auth(proxy, did="did:mesh:evil")
        assert not r.allowed
        assert "blocked" in r.reason

    def test_block_unblock(self):
        proxy = TrustProxy()
        proxy.block_agent("did:mesh:bad")
        assert not _auth(proxy, did="did:mesh:bad").allowed
        proxy.unblock_agent("did:mesh:bad")
        assert _auth(proxy, did="did:mesh:bad").allowed


class TestToolPolicies:
    def test_tool_blocked(self):
        proxy = TrustProxy()
        proxy.set_tool_policy("shell", ToolPolicy(blocked=True))
        r = _auth(proxy, tool="shell")
        assert not r.allowed
        assert "blocked" in r.reason

    def test_tool_min_trust(self):
        proxy = TrustProxy(default_min_trust=100)
        proxy.set_tool_policy("admin", ToolPolicy(min_trust=800))
        # Default tool: allowed at 500
        assert _auth(proxy, tool="search", score=500).allowed
        # Admin tool: denied at 500
        assert not _auth(proxy, tool="admin", score=500).allowed
        # Admin tool: allowed at 900
        assert _auth(proxy, tool="admin", score=900).allowed

    def test_tool_capabilities(self):
        proxy = TrustProxy()
        proxy.set_tool_policy("file_write", ToolPolicy(required_capabilities=["fs_write"]))
        # No caps
        r = _auth(proxy, tool="file_write", caps=[])
        assert not r.allowed
        assert "Missing" in r.reason
        # Has cap
        assert _auth(proxy, tool="file_write", caps=["fs_write"]).allowed

    def test_tool_rate_limit(self):
        proxy = TrustProxy()
        proxy.set_tool_policy("api", ToolPolicy(max_calls_per_minute=3))
        for _ in range(3):
            assert _auth(proxy, tool="api").allowed
        r = _auth(proxy, tool="api")
        assert not r.allowed
        assert "Rate limit" in r.reason

    def test_rate_limit_per_agent(self):
        proxy = TrustProxy()
        proxy.set_tool_policy("api", ToolPolicy(max_calls_per_minute=2))
        assert _auth(proxy, tool="api", did="d1").allowed
        assert _auth(proxy, tool="api", did="d1").allowed
        assert not _auth(proxy, tool="api", did="d1").allowed
        # Different agent still allowed
        assert _auth(proxy, tool="api", did="d2").allowed

    def test_rate_limit_per_tool(self):
        proxy = TrustProxy()
        proxy.set_tool_policy("api", ToolPolicy(max_calls_per_minute=1))
        assert _auth(proxy, tool="api").allowed
        assert not _auth(proxy, tool="api").allowed
        # Different tool: no limit
        assert _auth(proxy, tool="search").allowed

    def test_clear_rate_limits(self):
        proxy = TrustProxy()
        proxy.set_tool_policy("api", ToolPolicy(max_calls_per_minute=1))
        assert _auth(proxy, tool="api").allowed
        assert not _auth(proxy, tool="api").allowed
        proxy.clear_rate_limits()
        assert _auth(proxy, tool="api").allowed


class TestAuditAndStats:
    def test_audit_log(self):
        proxy = TrustProxy()
        _auth(proxy)
        _auth(proxy, tool="other")
        assert len(proxy.get_audit_log()) == 2

    def test_stats(self):
        proxy = TrustProxy(default_min_trust=500)
        proxy.set_tool_policy("admin", ToolPolicy(blocked=True))
        _auth(proxy, score=600)  # allowed
        _auth(proxy, score=200)  # denied (trust)
        _auth(proxy, tool="admin", score=900)  # denied (blocked)
        stats = proxy.get_stats()
        assert stats["total_requests"] == 3
        assert stats["allowed"] == 1
        assert stats["denied"] == 2
        assert stats["configured_tools"] == 1

    def test_get_tool_policies(self):
        proxy = TrustProxy()
        proxy.set_tool_policy("a", ToolPolicy(min_trust=100))
        proxy.set_tool_policy("b", ToolPolicy(blocked=True))
        assert len(proxy.get_tool_policies()) == 2


class TestIntegration:
    def test_full_mcp_proxy_lifecycle(self):
        """Simulate a full MCP proxy session with multiple agents and tools."""
        proxy = TrustProxy(
            default_min_trust=300,
            tool_policies={
                "file_write": ToolPolicy(min_trust=700, required_capabilities=["fs_write"]),
                "shell_exec": ToolPolicy(blocked=True),
                "web_search": ToolPolicy(max_calls_per_minute=5),
            },
            blocked_dids=["did:mesh:malicious"],
        )

        # Agent 1: high trust, good caps
        assert _auth(proxy, did="d1", score=800, tool="file_write", caps=["fs_write"]).allowed
        assert _auth(proxy, did="d1", score=800, tool="web_search").allowed

        # Agent 2: low trust
        assert not _auth(proxy, did="d2", score=200, tool="file_write").allowed

        # Shell blocked for everyone
        assert not _auth(proxy, did="d1", score=1000, tool="shell_exec").allowed

        # Malicious agent blocked
        assert not _auth(proxy, did="did:mesh:malicious", score=1000, tool="web_search").allowed

        stats = proxy.get_stats()
        assert stats["total_requests"] == 5
        assert stats["allowed"] == 2
        assert stats["denied"] == 3

    def test_imports(self):
        from mcp_trust_proxy import TrustProxy, ToolPolicy, AuthResult
        assert all(cls is not None for cls in [TrustProxy, ToolPolicy, AuthResult])
