# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test MCP Kernel Server.
"""

import pytest
from typing import Dict, Any


class TestMCPTools:
    """Test MCP tool implementations."""
    
    def test_import_tools(self):
        """Test importing MCP tools."""
        try:
            from mcp_kernel_server.tools import (
                CMVKVerifyTool,
                KernelExecuteTool,
                IATPSignTool,
            )
            assert CMVKVerifyTool is not None
            assert KernelExecuteTool is not None
            assert IATPSignTool is not None
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    def test_cmvk_tool_schema(self):
        """Test CMVK verify tool schema."""
        try:
            from mcp_kernel_server.tools import CMVKVerifyTool
            
            tool = CMVKVerifyTool()
            
            assert tool.name == "cmvk_verify"
            assert "claim" in tool.input_schema["properties"]
            assert "models" in tool.input_schema["properties"]
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    def test_kernel_execute_tool_schema(self):
        """Test kernel execute tool schema."""
        try:
            from mcp_kernel_server.tools import KernelExecuteTool
            
            tool = KernelExecuteTool()
            
            assert tool.name == "kernel_execute"
            assert "agent_id" in tool.input_schema["properties"]
            assert "action" in tool.input_schema["properties"]
            assert "context" in tool.input_schema["properties"]
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    def test_iatp_sign_tool_schema(self):
        """Test IATP sign tool schema."""
        try:
            from mcp_kernel_server.tools import IATPSignTool
            
            tool = IATPSignTool()
            
            assert tool.name == "iatp_sign"
            assert "content" in tool.input_schema["properties"]
            assert "agent_id" in tool.input_schema["properties"]
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    @pytest.mark.asyncio
    async def test_cmvk_verify_execution(self):
        """Test CMVK verify tool execution."""
        try:
            from mcp_kernel_server.tools import CMVKVerifyTool
            
            tool = CMVKVerifyTool()
            
            result = await tool.execute({
                "claim": "2 + 2 = 4",
                "models": ["mock-model-1", "mock-model-2"]
            })
            
            assert result.data["verified"] is not None
            assert "confidence" in result.data
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    @pytest.mark.asyncio
    async def test_kernel_execute_allowed(self):
        """Test kernel execute for allowed action."""
        try:
            from mcp_kernel_server.tools import KernelExecuteTool
            
            tool = KernelExecuteTool()
            
            result = await tool.execute({
                "agent_id": "test-agent",
                "action": "database_query",
                "params": {"query": "SELECT 1"},
                "context": {"policies": []}
            })
            
            assert result.success is True
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    @pytest.mark.asyncio
    async def test_kernel_execute_blocked(self):
        """Test kernel execute for blocked action."""
        try:
            from mcp_kernel_server.tools import KernelExecuteTool
            
            tool = KernelExecuteTool()
            
            result = await tool.execute({
                "agent_id": "test-agent",
                "action": "file_write",
                "params": {"path": "/data/file.txt"},
                "context": {"policies": ["read_only"]}
            })
            
            assert result.success is False
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    @pytest.mark.asyncio
    async def test_iatp_sign_execution(self):
        """Test IATP sign tool execution."""
        try:
            from mcp_kernel_server.tools import IATPSignTool
            
            tool = IATPSignTool()
            
            result = await tool.execute({
                "content": "Hello, World!",
                "agent_id": "test-agent",
                "capabilities": [],
                "metadata": {}
            })
            
            assert "signature" in result.data
            assert "timestamp" in result.data
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")


class TestMCPServer:
    """Test MCP server implementation."""
    
    def test_import_server(self):
        """Test importing MCP server."""
        try:
            from mcp_kernel_server.server import KernelMCPServer
            assert KernelMCPServer is not None
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    def test_create_server(self):
        """Test creating MCP server."""
        try:
            from mcp_kernel_server.server import KernelMCPServer
            
            server = KernelMCPServer()
            assert server is not None
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    def test_server_has_tools(self):
        """Test server has registered tools."""
        try:
            from mcp_kernel_server.server import KernelMCPServer
            
            server = KernelMCPServer()
            
            assert isinstance(server.tools, dict)
            assert len(server.tools) == 8
            assert "cmvk_verify" in server.tools
            assert "kernel_execute" in server.tools
            assert "iatp_sign" in server.tools
            assert "verify_code_safety" in server.tools
            assert "cmvk_review" in server.tools
            assert "iatp_verify" in server.tools
            assert "iatp_reputation" in server.tools
            assert "get_audit_log" in server.tools
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    def test_server_tools_have_schemas(self):
        """Test all registered tools have required attributes."""
        try:
            from mcp_kernel_server.server import KernelMCPServer
            
            server = KernelMCPServer()
            
            for name, tool in server.tools.items():
                assert tool.name == name
                assert hasattr(tool, 'input_schema')
                assert hasattr(tool, 'execute')
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    def test_server_tool_lookup(self):
        """Test server tool lookup by name."""
        try:
            from mcp_kernel_server.server import KernelMCPServer
            
            server = KernelMCPServer()
            
            tool = server.tools["cmvk_verify"]
            assert tool is not None
            assert tool.name == "cmvk_verify"
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")


class TestMCPResources:
    """Test MCP resource handling."""
    
    def test_server_has_vfs_resources(self):
        """Test server exposes VFS resources."""
        try:
            from mcp_kernel_server.server import KernelMCPServer
            
            server = KernelMCPServer()
            resources = server.list_resources()
            
            # Should have VFS resource templates
            assert any("vfs" in str(r.get("uri", "")) for r in resources)
        except (ImportError, AttributeError):
            pytest.skip("mcp_kernel_server not installed or resources not implemented")
    
    @pytest.mark.asyncio
    async def test_read_vfs_resource(self):
        """Test reading VFS resource."""
        try:
            from mcp_kernel_server.server import KernelMCPServer
            
            server = KernelMCPServer()
            
            # Read memory resource
            content = await server.read_resource("vfs://test-agent/mem/working/data")
            
            # May be empty but shouldn't crash
            assert content is not None or content == ""
        except (ImportError, AttributeError):
            pytest.skip("mcp_kernel_server not installed or resources not implemented")


class TestMCPProtocol:
    """Test MCP protocol handling."""
    
    def test_server_has_tools_attribute(self):
        """Test server exposes tools attribute as dict."""
        try:
            from mcp_kernel_server.server import KernelMCPServer
            
            server = KernelMCPServer()
            
            assert hasattr(server, 'tools')
            assert isinstance(server.tools, dict)
            assert len(server.tools) > 0
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
    
    def test_server_all_tools_registered(self):
        """Test all expected tools are registered in server."""
        try:
            from mcp_kernel_server.server import KernelMCPServer
            
            server = KernelMCPServer()
            
            expected_tools = {
                'verify_code_safety', 'cmvk_verify', 'cmvk_review',
                'kernel_execute', 'iatp_sign', 'iatp_verify',
                'iatp_reputation', 'get_audit_log'
            }
            assert set(server.tools.keys()) == expected_tools
        except ImportError:
            pytest.skip("mcp_kernel_server not installed")
