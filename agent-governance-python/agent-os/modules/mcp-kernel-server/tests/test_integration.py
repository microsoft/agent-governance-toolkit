# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Integration tests for MCP Kernel Server."""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_kernel_server.server import KernelMCPServer, ServerConfig
from mcp_kernel_server.tools import GetAuditLogTool


class TestEndToEnd:
    def setup_method(self):
        self.server = KernelMCPServer(ServerConfig())
        GetAuditLogTool._audit_log.clear()

    @pytest.mark.asyncio
    async def test_init_then_list_tools(self):
        init_result = await self.server.handle_initialize({})
        assert init_result["serverInfo"]["name"] == "agent-os-kernel"
        tools_result = await self.server.handle_list_tools()
        assert len(tools_result["tools"]) == 8

    @pytest.mark.asyncio
    async def test_call_tool_and_check_result(self):
        result = await self.server.handle_call_tool(
            "verify_code_safety",
            {"code": "x = 1 + 2", "language": "python"},
        )
        assert result["isError"] is False
        data = json.loads(result["content"][0]["text"])
        assert data["safe"] is True

    @pytest.mark.asyncio
    async def test_sign_then_verify_flow(self):
        # Sign content
        sign_result = await self.server.handle_call_tool(
            "iatp_sign",
            {"content": "important data", "agent_id": "agent-a", "capabilities": ["reversible"]},
        )
        assert sign_result["isError"] is False
        sign_data = json.loads(sign_result["content"][0]["text"])
        assert "signature" in sign_data

        # Verify the remote agent
        verify_result = await self.server.handle_call_tool(
            "iatp_verify",
            {"remote_agent_id": "agent-b", "required_trust_level": "standard"},
        )
        assert verify_result["isError"] is False
        verify_data = json.loads(verify_result["content"][0]["text"])
        assert verify_data["verified"] is True

    @pytest.mark.asyncio
    async def test_kernel_execute_blocked_then_audit(self):
        # Execute a blocked action
        exec_result = await self.server.handle_call_tool(
            "kernel_execute",
            {
                "action": "file_write",
                "params": {},
                "agent_id": "test-agent",
                "policies": ["read_only"],
            },
        )
        assert exec_result["isError"] is True

        # Log the blocked action to audit
        GetAuditLogTool.log_entry({
            "type": "blocked",
            "agent_id": "test-agent",
            "action": "file_write",
        })

        # Retrieve audit log
        audit_result = await self.server.handle_call_tool(
            "get_audit_log",
            {"limit": 10, "filter": {"type": "blocked"}},
        )
        audit_data = json.loads(audit_result["content"][0]["text"])
        assert audit_data["returned"] >= 1

    @pytest.mark.asyncio
    async def test_cmvk_verify_and_review(self):
        # Verify a claim
        verify_result = await self.server.handle_call_tool(
            "cmvk_verify", {"claim": "2+2=4"},
        )
        assert verify_result["isError"] is False

        # Review code
        review_result = await self.server.handle_call_tool(
            "cmvk_review",
            {"code": "eval(input())", "language": "python", "focus": ["security"]},
        )
        assert review_result["isError"] is False
        review_data = json.loads(review_result["content"][0]["text"])
        assert any("eval" in i.get("issue", "").lower() for i in review_data.get("issues", []))

    @pytest.mark.asyncio
    async def test_vfs_write_read_via_server(self):
        # Write via VFS
        await self.server.vfs.write("vfs://integration-agent/mem/working/test", {"value": 42})
        # Read via server
        result = await self.server.handle_read_resource("vfs://integration-agent/mem/working/test")
        content = json.loads(result["contents"][0]["text"])
        assert content["value"] == 42

    @pytest.mark.asyncio
    async def test_reputation_slash_and_query(self):
        # Slash reputation
        slash_result = await self.server.handle_call_tool(
            "iatp_reputation",
            {"action": "slash", "agent_id": "bad-actor", "slash_reason": "misinfo", "slash_severity": "high"},
        )
        assert slash_result["isError"] is False

        # Query reputation
        query_result = await self.server.handle_call_tool(
            "iatp_reputation",
            {"action": "query", "agent_id": "bad-actor"},
        )
        query_data = json.loads(query_result["content"][0]["text"])
        assert query_data["reputation_score"] < 5.0

    @pytest.mark.asyncio
    async def test_jsonrpc_handler(self):
        response = await self.server._handle_jsonrpc({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {},
            "id": 1,
        })
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert "result" in response
        assert response["result"]["serverInfo"]["name"] == "agent-os-kernel"
