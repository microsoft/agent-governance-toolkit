# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Server Integration Tests.

Tests MCP protocol compliance: initialize, list_tools, call_tool,
resources, prompts, and error handling at the server handler level.
"""

import pytest
import json


pytestmark = pytest.mark.asyncio


def _get_server():
    """Create a KernelMCPServer, skip if not installed."""
    try:
        from mcp_kernel_server.server import KernelMCPServer
        return KernelMCPServer()
    except ImportError:
        pytest.skip("mcp_kernel_server not installed")


class TestMCPInitialize:
    """Test MCP initialize handshake."""

    async def test_initialize_returns_protocol_version(self):
        server = _get_server()
        result = await server.handle_initialize({"protocolVersion": "2024-11-05"})
        assert "protocolVersion" in result
        assert isinstance(result["protocolVersion"], str)

    async def test_initialize_returns_capabilities(self):
        server = _get_server()
        result = await server.handle_initialize({})
        assert "capabilities" in result
        caps = result["capabilities"]
        assert "tools" in caps
        assert "resources" in caps
        assert "prompts" in caps

    async def test_initialize_returns_server_info(self):
        server = _get_server()
        result = await server.handle_initialize({})
        assert "serverInfo" in result
        info = result["serverInfo"]
        assert "name" in info
        assert "version" in info


class TestMCPListTools:
    """Test MCP tools/list."""

    async def test_list_tools_returns_all_tools(self):
        server = _get_server()
        result = await server.handle_list_tools()
        tools = result["tools"]
        assert len(tools) == 8
        names = {t["name"] for t in tools}
        assert "cmvk_verify" in names
        assert "kernel_execute" in names
        assert "iatp_sign" in names
        assert "get_audit_log" in names

    async def test_each_tool_has_required_fields(self):
        server = _get_server()
        result = await server.handle_list_tools()
        for tool in result["tools"]:
            assert "name" in tool, f"Tool missing 'name'"
            assert "description" in tool, f"Tool {tool.get('name')} missing 'description'"
            assert "inputSchema" in tool, f"Tool {tool.get('name')} missing 'inputSchema'"
            assert isinstance(tool["inputSchema"], dict)

    async def test_input_schemas_have_properties(self):
        server = _get_server()
        result = await server.handle_list_tools()
        for tool in result["tools"]:
            schema = tool["inputSchema"]
            assert "properties" in schema, f"Tool {tool['name']} schema missing 'properties'"


class TestMCPCallTool:
    """Test MCP tools/call with various tools."""

    async def test_call_unknown_tool_returns_error(self):
        server = _get_server()
        result = await server.handle_call_tool("nonexistent_tool", {})
        assert result["isError"] is True
        assert any("Unknown tool" in c["text"] for c in result["content"])

    async def test_call_cmvk_verify(self):
        server = _get_server()
        result = await server.handle_call_tool("cmvk_verify", {
            "claim": "The sky is blue",
            "models": ["mock-1", "mock-2"],
        })
        assert "content" in result
        assert len(result["content"]) > 0
        assert result["content"][0]["type"] == "text"

    async def test_call_kernel_execute_allowed(self):
        server = _get_server()
        result = await server.handle_call_tool("kernel_execute", {
            "agent_id": "test-agent",
            "action": "read_data",
            "params": {"key": "value"},
            "context": {"policies": []},
        })
        assert "content" in result
        assert result.get("isError", False) is False

    async def test_call_kernel_execute_blocked(self):
        server = _get_server()
        result = await server.handle_call_tool("kernel_execute", {
            "agent_id": "test-agent",
            "action": "file_write",
            "params": {"path": "/etc/passwd"},
            "context": {"policies": ["read_only"]},
        })
        assert result["isError"] is True

    async def test_call_iatp_sign(self):
        server = _get_server()
        result = await server.handle_call_tool("iatp_sign", {
            "content": "trusted content",
            "agent_id": "signer-agent",
            "capabilities": ["read"],
            "metadata": {},
        })
        assert result.get("isError", False) is False
        data = json.loads(result["content"][0]["text"])
        assert "signature" in data

    async def test_call_verify_code_safety(self):
        server = _get_server()
        result = await server.handle_call_tool("verify_code_safety", {
            "code": "print('hello world')",
            "language": "python",
        })
        assert "content" in result

    async def test_call_get_audit_log(self):
        server = _get_server()
        result = await server.handle_call_tool("get_audit_log", {
            "agent_id": "test-agent",
            "limit": 10,
        })
        assert "content" in result

    async def test_call_tool_result_content_format(self):
        """All tool results should return MCP-compliant content array."""
        server = _get_server()
        result = await server.handle_call_tool("cmvk_verify", {
            "claim": "test",
            "models": ["m1"],
        })
        assert "content" in result
        assert isinstance(result["content"], list)
        for item in result["content"]:
            assert "type" in item
            assert "text" in item


class TestMCPResources:
    """Test MCP resource listing and reading."""

    async def test_list_resources_returns_list(self):
        server = _get_server()
        result = await server.handle_list_resources()
        assert "resources" in result
        assert isinstance(result["resources"], list)

    async def test_list_resource_templates(self):
        server = _get_server()
        result = await server.handle_list_resource_templates()
        assert "resourceTemplates" in result
        templates = result["resourceTemplates"]
        assert len(templates) > 0
        for tmpl in templates:
            assert "uriTemplate" in tmpl
            assert "name" in tmpl

    async def test_read_unknown_resource_handles_gracefully(self):
        server = _get_server()
        result = await server.handle_read_resource("vfs://unknown-agent/nonexistent")
        # Should return content (possibly empty) or error, but not crash
        assert result is not None


class TestMCPPrompts:
    """Test MCP prompt templates."""

    async def test_list_prompts(self):
        server = _get_server()
        result = await server.handle_list_prompts()
        assert "prompts" in result
        prompts = result["prompts"]
        assert len(prompts) >= 3
        names = {p["name"] for p in prompts}
        assert "governed_agent" in names
        assert "verify_claim" in names
        assert "safe_execution" in names

    async def test_prompt_has_required_fields(self):
        server = _get_server()
        result = await server.handle_list_prompts()
        for prompt in result["prompts"]:
            assert "name" in prompt
            assert "description" in prompt

    async def test_get_prompt_governed_agent(self):
        server = _get_server()
        result = await server.handle_get_prompt("governed_agent", {})
        assert "messages" in result
        assert len(result["messages"]) > 0
        msg = result["messages"][0]
        assert "role" in msg
        assert "content" in msg

    async def test_get_unknown_prompt_handles_gracefully(self):
        server = _get_server()
        try:
            result = await server.handle_get_prompt("nonexistent_prompt", {})
            # Should return error or empty, not crash
            assert result is not None
        except (KeyError, ValueError):
            pass  # Acceptable to raise on unknown prompt
