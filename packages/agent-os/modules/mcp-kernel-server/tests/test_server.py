# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP Kernel Server."""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_kernel_server.server import KernelMCPServer, ServerConfig, stateless_execute


class TestServerConfig:
    def test_defaults(self):
        config = ServerConfig()
        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.policy_mode == "strict"
        assert config.cmvk_threshold == 0.85
        assert config.vfs_backend == "memory"

    def test_custom_config(self):
        config = ServerConfig(port=9090, policy_mode="permissive")
        assert config.port == 9090
        assert config.policy_mode == "permissive"


class TestKernelMCPServer:
    def setup_method(self):
        self.server = KernelMCPServer(ServerConfig())

    def test_init_has_8_tools(self):
        assert len(self.server.tools) == 8

    def test_tool_names(self):
        expected = {
            "verify_code_safety", "cmvk_verify", "cmvk_review",
            "kernel_execute", "iatp_sign", "iatp_verify",
            "iatp_reputation", "get_audit_log",
        }
        assert set(self.server.tools.keys()) == expected

    @pytest.mark.asyncio
    async def test_handle_initialize(self):
        result = await self.server.handle_initialize({})
        assert result["protocolVersion"] == "2024-11-05"
        assert "tools" in result["capabilities"]
        assert "resources" in result["capabilities"]
        assert "prompts" in result["capabilities"]
        assert result["serverInfo"]["name"] == "agent-os-kernel"
        assert result["serverInfo"]["version"] == "1.2.0"

    @pytest.mark.asyncio
    async def test_handle_list_tools(self):
        result = await self.server.handle_list_tools()
        assert "tools" in result
        assert len(result["tools"]) == 8
        tool_names = {t["name"] for t in result["tools"]}
        assert "verify_code_safety" in tool_names
        assert "cmvk_verify" in tool_names

    @pytest.mark.asyncio
    async def test_handle_call_tool_code_safety(self):
        result = await self.server.handle_call_tool(
            "verify_code_safety",
            {"code": "print('hi')", "language": "python"},
        )
        assert result["isError"] is False
        data = json.loads(result["content"][0]["text"])
        assert data["safe"] is True

    @pytest.mark.asyncio
    async def test_handle_call_tool_unknown(self):
        result = await self.server.handle_call_tool("nonexistent", {})
        assert result["isError"] is True
        assert "Unknown tool" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_handle_list_resources(self):
        result = await self.server.handle_list_resources()
        assert "resources" in result
        assert len(result["resources"]) == 2
        uris = {r["uri"] for r in result["resources"]}
        assert "vfs://" in uris
        assert "audit://" in uris

    @pytest.mark.asyncio
    async def test_handle_list_prompts(self):
        result = await self.server.handle_list_prompts()
        assert "prompts" in result
        assert len(result["prompts"]) == 3
        names = {p["name"] for p in result["prompts"]}
        assert "governed_agent" in names
        assert "verify_claim" in names
        assert "safe_execution" in names

    @pytest.mark.asyncio
    async def test_handle_get_prompt_governed_agent(self):
        result = await self.server.handle_get_prompt(
            "governed_agent", {"agent_id": "test-agent", "policies": "strict"},
        )
        assert "messages" in result
        assert result["messages"][0]["role"] == "user"
        text = result["messages"][0]["content"]["text"]
        assert "test-agent" in text
        assert "strict" in text

    @pytest.mark.asyncio
    async def test_handle_get_prompt_unknown(self):
        result = await self.server.handle_get_prompt("unknown_prompt", {})
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_handle_list_resource_templates(self):
        result = await self.server.handle_list_resource_templates()
        assert "resourceTemplates" in result
        # 3 from VFS + 1 audit
        assert len(result["resourceTemplates"]) == 4

    @pytest.mark.asyncio
    async def test_handle_read_resource_audit(self):
        result = await self.server.handle_read_resource("audit://agent-1/log")
        assert "contents" in result
        content = json.loads(result["contents"][0]["text"])
        assert content["agent_id"] == "agent-1"

    @pytest.mark.asyncio
    async def test_handle_call_tool_error_result(self):
        result = await self.server.handle_call_tool(
            "kernel_execute",
            {"action": "file_write", "params": {}, "agent_id": "test", "policies": ["read_only"]},
        )
        assert result["isError"] is True


class TestStatelessExecute:
    @pytest.mark.asyncio
    async def test_basic_execute(self):
        result = await stateless_execute(
            "database_query",
            {"query": "SELECT 1"},
            {"agent_id": "test"},
        )
        assert result["success"] is True
        assert result["data"]["action"] == "database_query"

    @pytest.mark.asyncio
    async def test_execute_with_policy_violation(self):
        result = await stateless_execute(
            "file_write",
            {"path": "/tmp/test"},
            {"agent_id": "test", "policies": ["read_only"]},
        )
        assert result["success"] is False
        assert "SIGKILL" in result["error"]
