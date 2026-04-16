# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP (Model Context Protocol) trust-gated integration.

Covers TrustGatedMCPServer (tool registration, trust verification,
capability checks, audit) and TrustGatedMCPClient (connect, invoke,
credentials).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentmesh.identity import AgentIdentity
from agentmesh.integrations.mcp import (
    MCPTool,
    MCPToolCall,
    TrustGatedMCPClient,
    TrustGatedMCPServer,
)


# ---------------------------------------------------------------------------
# Helpers & Fixtures
# ---------------------------------------------------------------------------


def _make_identity(
    name: str = "test-agent",
    sponsor: str = "admin@test.com",
    capabilities: Optional[List[str]] = None,
) -> AgentIdentity:
    """Create a test AgentIdentity via the real factory."""
    return AgentIdentity.create(
        name=name,
        sponsor=sponsor,
        capabilities=capabilities or [],
    )


async def _echo_handler(**kwargs: Any) -> Dict[str, Any]:
    """Simple async handler that echoes its arguments."""
    return {"echo": kwargs}


async def _failing_handler(**kwargs: Any) -> None:
    """Handler that always raises."""
    raise RuntimeError("handler exploded")


async def _sql_handler(query: str = "") -> Dict[str, Any]:
    """Simulated SQL tool handler."""
    return {"rows": [], "query": query}


@pytest.fixture()
def server_identity() -> AgentIdentity:
    return _make_identity(name="tool-server", capabilities=["provide:sql", "provide:fs"])


@pytest.fixture()
def server(server_identity: AgentIdentity) -> TrustGatedMCPServer:
    return TrustGatedMCPServer(server_identity, min_trust_score=300)


@pytest.fixture()
def client_identity() -> AgentIdentity:
    return _make_identity(name="tool-client", capabilities=["use:sql", "use:fs"])


# ---------------------------------------------------------------------------
# MCPTool / MCPToolCall dataclass tests
# ---------------------------------------------------------------------------


class TestMCPToolDataclass:
    """Tests for the MCPTool dataclass defaults and overrides."""

    def test_defaults(self) -> None:
        tool = MCPTool(name="t", description="d", handler=_echo_handler)
        assert tool.name == "t"
        assert tool.description == "d"
        assert tool.input_schema == {}
        assert tool.required_capability is None
        assert tool.min_trust_score == 300
        assert tool.require_human_sponsor is False
        assert tool.total_calls == 0
        assert tool.failed_calls == 0
        assert tool.last_called is None

    def test_custom_values(self) -> None:
        tool = MCPTool(
            name="sql",
            description="run sql",
            handler=_sql_handler,
            input_schema={"type": "object"},
            required_capability="use:sql",
            min_trust_score=700,
            require_human_sponsor=True,
        )
        assert tool.min_trust_score == 700
        assert tool.required_capability == "use:sql"
        assert tool.require_human_sponsor is True


class TestMCPToolCallDataclass:
    """Tests for the MCPToolCall dataclass defaults."""

    def test_defaults(self) -> None:
        call = MCPToolCall(
            call_id="c1",
            tool_name="sql",
            caller_did="did:mesh:abc",
            arguments={"q": "SELECT 1"},
        )
        assert call.trust_verified is False
        assert call.trust_score == 0
        assert call.capabilities_checked == []
        assert call.success is False
        assert call.result is None
        assert call.error is None
        assert call.completed_at is None
        assert isinstance(call.started_at, datetime)


# ---------------------------------------------------------------------------
# TrustGatedMCPServer — register_tool
# ---------------------------------------------------------------------------


class TestRegisterTool:
    """Tests for TrustGatedMCPServer.register_tool."""

    def test_register_basic_tool(self, server: TrustGatedMCPServer) -> None:
        server.register_tool("echo", _echo_handler, description="Echo tool")
        tools = server.list_tools()
        assert len(tools) == 1
        assert tools[0]["name"] == "echo"
        assert tools[0]["description"] == "Echo tool"

    def test_register_tool_with_capability(self, server: TrustGatedMCPServer) -> None:
        server.register_tool(
            "sql_query",
            _sql_handler,
            description="Run SQL",
            required_capability="use:sql",
        )
        tools = server.list_tools()
        assert tools[0]["x-agentmesh"]["requiredCapability"] == "use:sql"

    def test_register_tool_with_custom_trust(self, server: TrustGatedMCPServer) -> None:
        server.register_tool("high_sec", _echo_handler, min_trust_score=800)
        tools = server.list_tools()
        assert tools[0]["x-agentmesh"]["minTrustScore"] == 800

    def test_register_tool_inherits_server_trust(self, server: TrustGatedMCPServer) -> None:
        """When min_trust_score is not given, tool inherits the server default (300)."""
        server.register_tool("default_trust", _echo_handler)
        tools = server.list_tools()
        assert tools[0]["x-agentmesh"]["minTrustScore"] == 300

    def test_register_tool_with_schema(self, server: TrustGatedMCPServer) -> None:
        schema = {"type": "object", "properties": {"query": {"type": "string"}}}
        server.register_tool("sql_query", _sql_handler, input_schema=schema)
        tools = server.list_tools()
        assert tools[0]["inputSchema"] == schema

    def test_register_tool_with_human_sponsor(self, server: TrustGatedMCPServer) -> None:
        server.register_tool("admin_tool", _echo_handler, require_human_sponsor=True)
        tools = server.list_tools()
        assert tools[0]["x-agentmesh"]["requireHumanSponsor"] is True

    def test_register_multiple_tools(self, server: TrustGatedMCPServer) -> None:
        server.register_tool("a", _echo_handler)
        server.register_tool("b", _sql_handler)
        server.register_tool("c", _echo_handler)
        assert len(server.list_tools()) == 3

    def test_register_overwrites_existing_tool(self, server: TrustGatedMCPServer) -> None:
        """Re-registering a tool with the same name overwrites it."""
        server.register_tool("echo", _echo_handler, description="v1")
        server.register_tool("echo", _sql_handler, description="v2")
        tools = server.list_tools()
        assert len(tools) == 1
        assert tools[0]["description"] == "v2"


# ---------------------------------------------------------------------------
# TrustGatedMCPServer — invoke_tool
# ---------------------------------------------------------------------------


class TestInvokeTool:
    """Tests for TrustGatedMCPServer.invoke_tool — happy path, rejection, errors."""

    @pytest.mark.asyncio
    async def test_successful_invocation(self, server: TrustGatedMCPServer) -> None:
        server.register_tool("echo", _echo_handler, required_capability="use:echo")
        call = await server.invoke_tool(
            tool_name="echo",
            arguments={"msg": "hello"},
            caller_did="did:mesh:caller1",
            caller_capabilities=["use:echo"],
            caller_trust_score=500,
        )
        assert call.success is True
        assert call.error is None
        assert call.trust_verified is True
        assert call.result == {"echo": {"msg": "hello"}}
        assert call.completed_at is not None

    @pytest.mark.asyncio
    async def test_reject_unknown_tool(self, server: TrustGatedMCPServer) -> None:
        call = await server.invoke_tool(
            tool_name="nonexistent",
            arguments={},
            caller_did="did:mesh:caller1",
            caller_trust_score=500,
        )
        assert call.success is False
        assert "Unknown tool" in call.error
        assert call.completed_at is not None

    @pytest.mark.asyncio
    async def test_reject_insufficient_trust_score(
        self, server: TrustGatedMCPServer
    ) -> None:
        server.register_tool("echo", _echo_handler, min_trust_score=600)
        call = await server.invoke_tool(
            tool_name="echo",
            arguments={},
            caller_did="did:mesh:lowscore",
            caller_trust_score=100,
        )
        assert call.success is False
        assert "Insufficient trust score" in call.error
        assert "100 < 600" in call.error

    @pytest.mark.asyncio
    async def test_reject_zero_trust_score(self, server: TrustGatedMCPServer) -> None:
        server.register_tool("echo", _echo_handler)  # default min = 300
        call = await server.invoke_tool(
            tool_name="echo",
            arguments={},
            caller_did="did:mesh:zero",
            caller_trust_score=0,
        )
        assert call.success is False
        assert "Insufficient trust score" in call.error

    @pytest.mark.asyncio
    async def test_reject_missing_capability(self, server: TrustGatedMCPServer) -> None:
        server.register_tool("sql", _sql_handler, required_capability="use:sql")
        call = await server.invoke_tool(
            tool_name="sql",
            arguments={"query": "SELECT 1"},
            caller_did="did:mesh:nocap",
            caller_capabilities=["use:other"],
            caller_trust_score=500,
        )
        assert call.success is False
        assert "Missing capability" in call.error
        assert "use:sql" in call.error

    @pytest.mark.asyncio
    async def test_reject_empty_capabilities(self, server: TrustGatedMCPServer) -> None:
        server.register_tool("sql", _sql_handler, required_capability="use:sql")
        call = await server.invoke_tool(
            tool_name="sql",
            arguments={},
            caller_did="did:mesh:empty",
            caller_capabilities=[],
            caller_trust_score=500,
        )
        assert call.success is False
        assert "Missing capability" in call.error

    @pytest.mark.asyncio
    async def test_reject_none_capabilities(self, server: TrustGatedMCPServer) -> None:
        """When caller_capabilities is None, it defaults to [] internally."""
        server.register_tool("sql", _sql_handler, required_capability="use:sql")
        call = await server.invoke_tool(
            tool_name="sql",
            arguments={},
            caller_did="did:mesh:nocap",
            caller_capabilities=None,
            caller_trust_score=500,
        )
        assert call.success is False
        assert "Missing capability" in call.error

    @pytest.mark.asyncio
    async def test_no_capability_required_passes(
        self, server: TrustGatedMCPServer
    ) -> None:
        """Tools with no required_capability accept any caller with sufficient trust."""
        server.register_tool("open_tool", _echo_handler)
        call = await server.invoke_tool(
            tool_name="open_tool",
            arguments={"x": 1},
            caller_did="did:mesh:any",
            caller_capabilities=[],
            caller_trust_score=300,
        )
        assert call.success is True

    @pytest.mark.asyncio
    async def test_handler_exception_recorded(
        self, server: TrustGatedMCPServer
    ) -> None:
        server.register_tool("bomb", _failing_handler)
        call = await server.invoke_tool(
            tool_name="bomb",
            arguments={},
            caller_did="did:mesh:caller1",
            caller_trust_score=500,
        )
        assert call.success is False
        assert call.trust_verified is True  # trust check passed
        assert "handler exploded" in call.error
        assert call.completed_at is not None

    @pytest.mark.asyncio
    async def test_handler_exception_increments_failed_calls(
        self, server: TrustGatedMCPServer
    ) -> None:
        server.register_tool("bomb", _failing_handler)
        await server.invoke_tool(
            tool_name="bomb",
            arguments={},
            caller_did="did:mesh:caller1",
            caller_trust_score=500,
        )
        summary = server.get_audit_summary()
        assert summary["failedCalls"] == 1
        assert summary["totalCalls"] == 0  # handler failed, so total_calls not incremented

    @pytest.mark.asyncio
    async def test_successful_call_increments_total_calls(
        self, server: TrustGatedMCPServer
    ) -> None:
        server.register_tool("echo", _echo_handler)
        await server.invoke_tool(
            tool_name="echo",
            arguments={},
            caller_did="did:mesh:caller1",
            caller_trust_score=500,
        )
        summary = server.get_audit_summary()
        assert summary["totalCalls"] == 1
        assert summary["failedCalls"] == 0

    @pytest.mark.asyncio
    async def test_trust_rejection_increments_failed_calls(
        self, server: TrustGatedMCPServer
    ) -> None:
        server.register_tool("echo", _echo_handler, min_trust_score=999)
        await server.invoke_tool(
            tool_name="echo",
            arguments={},
            caller_did="did:mesh:low",
            caller_trust_score=1,
        )
        summary = server.get_audit_summary()
        assert summary["failedCalls"] == 1

    @pytest.mark.asyncio
    async def test_capability_rejection_increments_failed_calls(
        self, server: TrustGatedMCPServer
    ) -> None:
        server.register_tool("sql", _sql_handler, required_capability="use:sql")
        await server.invoke_tool(
            tool_name="sql",
            arguments={},
            caller_did="did:mesh:nocap",
            caller_capabilities=["use:other"],
            caller_trust_score=500,
        )
        summary = server.get_audit_summary()
        assert summary["failedCalls"] == 1

    @pytest.mark.asyncio
    async def test_call_metadata_populated(self, server: TrustGatedMCPServer) -> None:
        server.register_tool("echo", _echo_handler, required_capability="use:echo")
        call = await server.invoke_tool(
            tool_name="echo",
            arguments={"k": "v"},
            caller_did="did:mesh:agent42",
            caller_capabilities=["use:echo", "read:data"],
            caller_trust_score=750,
        )
        assert call.tool_name == "echo"
        assert call.caller_did == "did:mesh:agent42"
        assert call.arguments == {"k": "v"}
        assert call.trust_score == 750
        assert call.capabilities_checked == ["use:echo", "read:data"]
        assert call.call_id.startswith("echo-")

    @pytest.mark.asyncio
    async def test_exact_boundary_trust_score(
        self, server: TrustGatedMCPServer
    ) -> None:
        """Trust score exactly equal to minimum should pass."""
        server.register_tool("echo", _echo_handler, min_trust_score=500)
        call = await server.invoke_tool(
            tool_name="echo",
            arguments={},
            caller_did="did:mesh:boundary",
            caller_trust_score=500,
        )
        assert call.success is True

    @pytest.mark.asyncio
    async def test_one_below_boundary_trust_score(
        self, server: TrustGatedMCPServer
    ) -> None:
        """Trust score one below minimum should fail."""
        server.register_tool("echo", _echo_handler, min_trust_score=500)
        call = await server.invoke_tool(
            tool_name="echo",
            arguments={},
            caller_did="did:mesh:boundary",
            caller_trust_score=499,
        )
        assert call.success is False
        assert "Insufficient trust score" in call.error

    @pytest.mark.asyncio
    async def test_tool_last_called_updated(self, server: TrustGatedMCPServer) -> None:
        """Successful invocation updates the tool's last_called timestamp."""
        server.register_tool("echo", _echo_handler)
        assert server._tools["echo"].last_called is None
        await server.invoke_tool(
            "echo", {}, caller_did="did:mesh:a", caller_trust_score=500,
        )
        assert server._tools["echo"].last_called is not None
        assert isinstance(server._tools["echo"].last_called, datetime)


# ---------------------------------------------------------------------------
# TrustGatedMCPServer — _check_capability
# ---------------------------------------------------------------------------


class TestCheckCapability:
    """Tests for wildcard and exact capability matching."""

    def test_exact_match(self, server: TrustGatedMCPServer) -> None:
        assert server._check_capability(["use:sql"], "use:sql") is True

    def test_exact_no_match(self, server: TrustGatedMCPServer) -> None:
        assert server._check_capability(["use:sql"], "use:fs") is False

    def test_wildcard_match(self, server: TrustGatedMCPServer) -> None:
        assert server._check_capability(["use:*"], "use:sql") is True

    def test_wildcard_match_different_suffix(
        self, server: TrustGatedMCPServer
    ) -> None:
        assert server._check_capability(["use:*"], "use:filesystem") is True

    def test_wildcard_different_prefix(self, server: TrustGatedMCPServer) -> None:
        """Wildcard 'use:*' should NOT match 'read:sql'."""
        assert server._check_capability(["use:*"], "read:sql") is False

    def test_wildcard_with_nested_path(self, server: TrustGatedMCPServer) -> None:
        """Wildcard 'use:*' should match 'use:sql:advanced'."""
        assert server._check_capability(["use:*"], "use:sql:advanced") is True

    def test_no_required_capability_always_passes(
        self, server: TrustGatedMCPServer
    ) -> None:
        """Empty string required_capability returns True."""
        assert server._check_capability([], "") is True

    def test_empty_client_capabilities(self, server: TrustGatedMCPServer) -> None:
        assert server._check_capability([], "use:sql") is False

    def test_multiple_capabilities_one_matches(
        self, server: TrustGatedMCPServer
    ) -> None:
        caps = ["read:data", "use:sql", "write:logs"]
        assert server._check_capability(caps, "use:sql") is True

    def test_multiple_wildcards(self, server: TrustGatedMCPServer) -> None:
        caps = ["read:*", "use:*"]
        assert server._check_capability(caps, "use:sql") is True
        assert server._check_capability(caps, "read:metrics") is True
        assert server._check_capability(caps, "write:data") is False

    def test_wildcard_exact_colon_star_literal(
        self, server: TrustGatedMCPServer
    ) -> None:
        """Capability 'use:*' itself as required — only exact match or broader wildcard."""
        assert server._check_capability(["use:*"], "use:*") is True


# ---------------------------------------------------------------------------
# TrustGatedMCPServer — verify_client
# ---------------------------------------------------------------------------


class TestVerifyClient:
    """Tests for client verification with caching, TrustBridge, and card-based."""

    @pytest.mark.asyncio
    async def test_cache_hit_within_ttl(self, server: TrustGatedMCPServer) -> None:
        """A recently verified client should be served from cache."""
        server._verified_clients["did:mesh:cached"] = datetime.utcnow()
        result = await server.verify_client("did:mesh:cached")
        assert result is True

    @pytest.mark.asyncio
    async def test_cache_miss_expired_ttl(self, server: TrustGatedMCPServer) -> None:
        """An expired cache entry should not pass without bridge or card."""
        expired_time = datetime.utcnow() - timedelta(minutes=15)
        server._verified_clients["did:mesh:old"] = expired_time
        result = await server.verify_client("did:mesh:old")
        assert result is False

    @pytest.mark.asyncio
    async def test_trust_bridge_success(
        self, server_identity: AgentIdentity
    ) -> None:
        bridge = AsyncMock()
        bridge.verify_peer = AsyncMock(return_value=True)
        server = TrustGatedMCPServer(server_identity, trust_bridge=bridge)

        result = await server.verify_client("did:mesh:bridged")
        assert result is True
        bridge.verify_peer.assert_awaited_once_with("did:mesh:bridged")
        # Should also populate the cache
        assert "did:mesh:bridged" in server._verified_clients

    @pytest.mark.asyncio
    async def test_trust_bridge_failure(
        self, server_identity: AgentIdentity
    ) -> None:
        bridge = AsyncMock()
        bridge.verify_peer = AsyncMock(return_value=False)
        server = TrustGatedMCPServer(server_identity, trust_bridge=bridge)

        result = await server.verify_client("did:mesh:untrusted")
        assert result is False
        assert "did:mesh:untrusted" not in server._verified_clients

    @pytest.mark.asyncio
    async def test_trust_bridge_exception(
        self, server_identity: AgentIdentity
    ) -> None:
        """If TrustBridge raises an exception, verification fails gracefully."""
        bridge = AsyncMock()
        bridge.verify_peer = AsyncMock(side_effect=ConnectionError("network down"))
        server = TrustGatedMCPServer(server_identity, trust_bridge=bridge)

        result = await server.verify_client("did:mesh:error")
        assert result is False

    @pytest.mark.asyncio
    async def test_card_based_verification_sufficient_score(
        self, server: TrustGatedMCPServer
    ) -> None:
        card = MagicMock()
        card.trust_score = 500  # >= server min of 300
        result = await server.verify_client("did:mesh:card", client_card=card)
        assert result is True
        assert "did:mesh:card" in server._verified_clients

    @pytest.mark.asyncio
    async def test_card_based_verification_insufficient_score(
        self, server: TrustGatedMCPServer
    ) -> None:
        card = MagicMock()
        card.trust_score = 100  # < server min of 300
        result = await server.verify_client("did:mesh:lowcard", client_card=card)
        assert result is False

    @pytest.mark.asyncio
    async def test_card_without_trust_score_attr(
        self, server: TrustGatedMCPServer
    ) -> None:
        """Card object without trust_score attribute should fail verification."""
        card = MagicMock(spec=[])  # empty spec → no attributes
        result = await server.verify_client("did:mesh:noattr", client_card=card)
        assert result is False

    @pytest.mark.asyncio
    async def test_no_bridge_no_card_fails(self, server: TrustGatedMCPServer) -> None:
        result = await server.verify_client("did:mesh:nobody")
        assert result is False

    @pytest.mark.asyncio
    async def test_cache_preferred_over_bridge(
        self, server_identity: AgentIdentity
    ) -> None:
        """If client is in cache, TrustBridge should NOT be called."""
        bridge = AsyncMock()
        bridge.verify_peer = AsyncMock(return_value=True)
        server = TrustGatedMCPServer(server_identity, trust_bridge=bridge)
        server._verified_clients["did:mesh:cached"] = datetime.utcnow()

        result = await server.verify_client("did:mesh:cached")
        assert result is True
        bridge.verify_peer.assert_not_awaited()


# ---------------------------------------------------------------------------
# TrustGatedMCPServer — list_tools
# ---------------------------------------------------------------------------


class TestListTools:
    """Tests for list_tools MCP format output."""

    def test_empty_server(self, server: TrustGatedMCPServer) -> None:
        assert server.list_tools() == []

    def test_tool_format(self, server: TrustGatedMCPServer) -> None:
        server.register_tool(
            "sql_query",
            _sql_handler,
            description="Run SQL queries",
            input_schema={"type": "object"},
            required_capability="use:sql",
            min_trust_score=600,
            require_human_sponsor=True,
        )
        tools = server.list_tools()
        assert len(tools) == 1
        tool = tools[0]
        assert tool["name"] == "sql_query"
        assert tool["description"] == "Run SQL queries"
        assert tool["inputSchema"] == {"type": "object"}
        assert tool["x-agentmesh"]["requiredCapability"] == "use:sql"
        assert tool["x-agentmesh"]["minTrustScore"] == 600
        assert tool["x-agentmesh"]["requireHumanSponsor"] is True

    def test_multiple_tools_order(self, server: TrustGatedMCPServer) -> None:
        """Tools should appear in insertion order (dict ordering)."""
        server.register_tool("alpha", _echo_handler)
        server.register_tool("beta", _echo_handler)
        server.register_tool("gamma", _echo_handler)
        names = [t["name"] for t in server.list_tools()]
        assert names == ["alpha", "beta", "gamma"]


# ---------------------------------------------------------------------------
# TrustGatedMCPServer — get_audit_summary
# ---------------------------------------------------------------------------


class TestAuditSummary:
    """Tests for get_audit_summary and _record_call."""

    def test_empty_summary(self, server: TrustGatedMCPServer) -> None:
        summary = server.get_audit_summary()
        assert summary == {
            "totalTools": 0,
            "totalCalls": 0,
            "failedCalls": 0,
            "recentCalls": 0,
            "verifiedClients": 0,
        }

    @pytest.mark.asyncio
    async def test_summary_after_mixed_calls(
        self, server: TrustGatedMCPServer
    ) -> None:
        server.register_tool("echo", _echo_handler)
        server.register_tool("bomb", _failing_handler)

        # Successful call
        await server.invoke_tool(
            "echo", {}, "did:mesh:a", caller_trust_score=500
        )
        # Handler failure
        await server.invoke_tool(
            "bomb", {}, "did:mesh:b", caller_trust_score=500
        )
        # Unknown tool
        await server.invoke_tool(
            "ghost", {}, "did:mesh:c", caller_trust_score=500
        )

        summary = server.get_audit_summary()
        assert summary["totalTools"] == 2
        assert summary["totalCalls"] == 1  # only echo succeeded
        assert summary["failedCalls"] == 1  # bomb handler failed
        assert summary["recentCalls"] == 3  # all 3 recorded in history

    @pytest.mark.asyncio
    async def test_verified_clients_count(
        self, server: TrustGatedMCPServer
    ) -> None:
        card = MagicMock()
        card.trust_score = 999
        await server.verify_client("did:mesh:a", client_card=card)
        await server.verify_client("did:mesh:b", client_card=card)
        summary = server.get_audit_summary()
        assert summary["verifiedClients"] == 2


# ---------------------------------------------------------------------------
# TrustGatedMCPServer — _record_call (audit cap)
# ---------------------------------------------------------------------------


class TestRecordCall:
    """Tests for _record_call and the 1000-call history cap."""

    def test_record_call_appends(self, server: TrustGatedMCPServer) -> None:
        call = MCPToolCall(
            call_id="test-1",
            tool_name="t",
            caller_did="did:mesh:x",
            arguments={},
        )
        server._record_call(call)
        assert len(server._call_history) == 1
        assert server._call_history[0].call_id == "test-1"

    def test_record_call_respects_audit_flag(
        self, server_identity: AgentIdentity
    ) -> None:
        """When audit_all_calls=False, nothing is recorded."""
        server = TrustGatedMCPServer(server_identity, audit_all_calls=False)
        call = MCPToolCall(
            call_id="ignored",
            tool_name="t",
            caller_did="did:mesh:x",
            arguments={},
        )
        server._record_call(call)
        assert len(server._call_history) == 0

    def test_record_call_caps_at_1000(self, server: TrustGatedMCPServer) -> None:
        """History should never exceed 1000 entries; oldest entries are dropped."""
        for i in range(1050):
            call = MCPToolCall(
                call_id=f"call-{i}",
                tool_name="t",
                caller_did="did:mesh:x",
                arguments={},
            )
            server._record_call(call)

        assert len(server._call_history) == 1000
        # Oldest entries (0-49) should have been evicted
        assert server._call_history[0].call_id == "call-50"
        assert server._call_history[-1].call_id == "call-1049"

    def test_record_call_exactly_1000(self, server: TrustGatedMCPServer) -> None:
        """Exactly 1000 calls should all be retained."""
        for i in range(1000):
            call = MCPToolCall(
                call_id=f"call-{i}",
                tool_name="t",
                caller_did="did:mesh:x",
                arguments={},
            )
            server._record_call(call)

        assert len(server._call_history) == 1000
        assert server._call_history[0].call_id == "call-0"

    def test_record_call_1001_trims(self, server: TrustGatedMCPServer) -> None:
        """The 1001st call triggers trimming to 1000."""
        for i in range(1001):
            call = MCPToolCall(
                call_id=f"call-{i}",
                tool_name="t",
                caller_did="did:mesh:x",
                arguments={},
            )
            server._record_call(call)

        assert len(server._call_history) == 1000
        assert server._call_history[0].call_id == "call-1"


# ---------------------------------------------------------------------------
# TrustGatedMCPClient — connect
# ---------------------------------------------------------------------------


class TestMCPClientConnect:
    """Tests for TrustGatedMCPClient.connect."""

    @pytest.mark.asyncio
    async def test_connect_without_bridge(
        self, client_identity: AgentIdentity
    ) -> None:
        client = TrustGatedMCPClient(client_identity)
        result = await client.connect("https://mcp.example.com:8080")
        assert result is True
        assert client._connected_servers == {"https://mcp.example.com:8080"}

    @pytest.mark.asyncio
    async def test_connect_with_bridge_no_server_did(
        self, client_identity: AgentIdentity
    ) -> None:
        """When _discover_server_did returns None, bridge is skipped."""
        bridge = AsyncMock()
        bridge.verify_peer = AsyncMock(return_value=False)
        client = TrustGatedMCPClient(client_identity, trust_bridge=bridge)
        result = await client.connect("https://mcp.example.com:8080")
        assert result is True
        bridge.verify_peer.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_connect_with_bridge_server_did_verified(
        self, client_identity: AgentIdentity
    ) -> None:
        bridge = AsyncMock()
        bridge.verify_peer = AsyncMock(return_value=True)
        client = TrustGatedMCPClient(client_identity, trust_bridge=bridge)

        with patch.object(
            client, "_discover_server_did", return_value="did:mesh:server1"
        ):
            result = await client.connect("http://trusted-server:8080")
        assert result is True
        bridge.verify_peer.assert_awaited_once_with("did:mesh:server1")

    @pytest.mark.asyncio
    async def test_connect_with_bridge_server_rejected(
        self, client_identity: AgentIdentity
    ) -> None:
        bridge = AsyncMock()
        bridge.verify_peer = AsyncMock(return_value=False)
        client = TrustGatedMCPClient(client_identity, trust_bridge=bridge)

        with patch.object(
            client, "_discover_server_did", return_value="did:mesh:evil"
        ):
            result = await client.connect("http://evil-server:8080")
        assert result is False
        assert "http://evil-server:8080" not in client._connected_servers

    @pytest.mark.asyncio
    async def test_connect_multiple_servers(
        self, client_identity: AgentIdentity
    ) -> None:
        client = TrustGatedMCPClient(client_identity)
        await client.connect("http://server-a:8080")
        await client.connect("http://server-b:9090")
        assert len(client._connected_servers) == 2


# ---------------------------------------------------------------------------
# TrustGatedMCPClient — invoke
# ---------------------------------------------------------------------------


class TestMCPClientInvoke:
    """Tests for TrustGatedMCPClient.invoke — now raises NotImplementedError."""

    @pytest.mark.asyncio
    async def test_invoke_raises_not_implemented(
        self, client_identity: AgentIdentity
    ) -> None:
        client = TrustGatedMCPClient(client_identity)
        await client.connect("https://mcp.example.com:8080")

        with pytest.raises(NotImplementedError, match="MCP HTTP transport"):
            await client.invoke(
                "https://mcp.example.com:8080",
                "sql_query",
                {"query": "SELECT 1"},
            )

    @pytest.mark.asyncio
    async def test_invoke_mentions_server_and_tool(
        self, client_identity: AgentIdentity
    ) -> None:
        """Error message should include the server URL and tool name."""
        client = TrustGatedMCPClient(client_identity)
        await client.connect("http://my-server:9090")

        with pytest.raises(NotImplementedError) as exc_info:
            await client.invoke(
                "http://my-server:9090",
                "my_tool",
                {},
            )
        assert "http://my-server:9090" in str(exc_info.value)
        assert "my_tool" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_invoke_auto_connects_then_raises(
        self, client_identity: AgentIdentity
    ) -> None:
        """Invoking on an unconnected server auto-connects, then raises."""
        client = TrustGatedMCPClient(client_identity)
        with pytest.raises(NotImplementedError):
            await client.invoke("http://auto:8080", "tool", {})
        # Should have auto-connected
        assert "http://auto:8080" in client._connected_servers

    @pytest.mark.asyncio
    async def test_invoke_auto_connect_failure(
        self, client_identity: AgentIdentity
    ) -> None:
        """If auto-connect fails (bridge rejects), return error dict instead of raise."""
        bridge = AsyncMock()
        bridge.verify_peer = AsyncMock(return_value=False)
        client = TrustGatedMCPClient(client_identity, trust_bridge=bridge)

        with patch.object(
            client, "_discover_server_did", return_value="did:mesh:bad"
        ):
            result = await client.invoke("http://bad-server:8080", "tool", {})
        assert result == {"error": "Failed to connect to server"}


# ---------------------------------------------------------------------------
# TrustGatedMCPClient — get_credentials
# ---------------------------------------------------------------------------


class TestMCPClientGetCredentials:
    """Tests for TrustGatedMCPClient.get_credentials."""

    def test_credentials_shape(self, client_identity: AgentIdentity) -> None:
        client = TrustGatedMCPClient(client_identity)
        creds = client.get_credentials()
        assert creds["type"] == "cmvk"
        assert "did" in creds
        assert "trustScore" in creds
        assert "capabilities" in creds

    def test_credentials_did_is_string(self, client_identity: AgentIdentity) -> None:
        client = TrustGatedMCPClient(client_identity)
        creds = client.get_credentials()
        assert isinstance(creds["did"], str)
        assert creds["did"].startswith("did:mesh:")

    def test_credentials_capabilities_from_identity(self) -> None:
        identity = _make_identity(capabilities=["use:sql", "read:data"])
        client = TrustGatedMCPClient(identity)
        creds = client.get_credentials()
        assert set(creds["capabilities"]) == {"use:sql", "read:data"}

    def test_credentials_empty_capabilities(self) -> None:
        identity = _make_identity(capabilities=[])
        client = TrustGatedMCPClient(identity)
        creds = client.get_credentials()
        assert creds["capabilities"] == []

    def test_credentials_trust_score_default(
        self, client_identity: AgentIdentity
    ) -> None:
        """AgentIdentity has no trust_score attr → falls back to 500."""
        client = TrustGatedMCPClient(client_identity)
        creds = client.get_credentials()
        assert creds["trustScore"] == 500

    def test_credentials_with_trust_score_attr(self) -> None:
        """If identity has a trust_score attribute, it should be used."""
        from unittest.mock import MagicMock

        identity = MagicMock()
        identity.did = "did:mesh:scored"
        identity.trust_score = 850
        identity.capabilities = ["read:data"]
        client = TrustGatedMCPClient(identity)
        creds = client.get_credentials()
        assert creds["trustScore"] == 850


# ---------------------------------------------------------------------------
# TrustGatedMCPClient — _discover_server_did
# ---------------------------------------------------------------------------


class TestDiscoverServerDID:
    """Tests for the placeholder _discover_server_did."""

    @pytest.mark.asyncio
    async def test_returns_none(self, client_identity: AgentIdentity) -> None:
        client = TrustGatedMCPClient(client_identity)
        result = await client._discover_server_did("http://any-server:8080")
        assert result is None


# ---------------------------------------------------------------------------
# Integration: end-to-end server workflow
# ---------------------------------------------------------------------------


class TestEndToEndServerWorkflow:
    """Integration tests exercising a full register → verify → invoke flow."""

    @pytest.mark.asyncio
    async def test_full_happy_path(self, server: TrustGatedMCPServer) -> None:
        """Register tool, verify client, invoke tool — all succeed."""
        server.register_tool(
            "sql_query",
            _sql_handler,
            description="Run SQL",
            required_capability="use:sql",
            min_trust_score=400,
        )

        # Verify client via card
        card = MagicMock()
        card.trust_score = 500
        verified = await server.verify_client("did:mesh:agent-a", client_card=card)
        assert verified is True

        # Invoke
        call = await server.invoke_tool(
            tool_name="sql_query",
            arguments={"query": "SELECT 1"},
            caller_did="did:mesh:agent-a",
            caller_capabilities=["use:sql"],
            caller_trust_score=500,
        )
        assert call.success is True
        assert call.result == {"rows": [], "query": "SELECT 1"}

        # Audit
        summary = server.get_audit_summary()
        assert summary["totalTools"] == 1
        assert summary["totalCalls"] == 1
        assert summary["verifiedClients"] == 1
        assert summary["recentCalls"] == 1

    @pytest.mark.asyncio
    async def test_multiple_tools_multiple_callers(
        self, server: TrustGatedMCPServer
    ) -> None:
        server.register_tool("echo", _echo_handler)
        server.register_tool("sql", _sql_handler, required_capability="use:sql")

        # Caller with use:sql → accepted
        call1 = await server.invoke_tool(
            "sql", {"query": "SELECT 1"}, "did:mesh:a",
            caller_capabilities=["use:sql"], caller_trust_score=500,
        )
        assert call1.success is True

        # Caller without use:sql → rejected
        call2 = await server.invoke_tool(
            "sql", {"query": "DROP TABLE"}, "did:mesh:b",
            caller_capabilities=["use:echo"], caller_trust_score=500,
        )
        assert call2.success is False

        # Caller with enough trust for echo (no capability required)
        call3 = await server.invoke_tool(
            "echo", {"msg": "hi"}, "did:mesh:b",
            caller_capabilities=[], caller_trust_score=300,
        )
        assert call3.success is True

        summary = server.get_audit_summary()
        assert summary["totalCalls"] == 2  # echo + sql by "a"
        assert summary["failedCalls"] == 1  # sql by "b"
        assert summary["recentCalls"] == 3

    @pytest.mark.asyncio
    async def test_wildcard_capability_e2e(
        self, server: TrustGatedMCPServer
    ) -> None:
        """Agent with 'use:*' wildcard can invoke any 'use:' tool."""
        server.register_tool("sql", _sql_handler, required_capability="use:sql")
        server.register_tool("fs", _echo_handler, required_capability="use:fs")

        for tool in ("sql", "fs"):
            call = await server.invoke_tool(
                tool_name=tool,
                arguments={},
                caller_did="did:mesh:admin",
                caller_capabilities=["use:*"],
                caller_trust_score=999,
            )
            assert call.success is True, f"{tool} should have succeeded with use:*"
