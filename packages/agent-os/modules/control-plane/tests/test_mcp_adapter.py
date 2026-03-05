# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the MCP Adapter
"""

import unittest
import json
from agent_control_plane import (
    AgentControlPlane,
    MCPAdapter,
    MCPServer,
    create_governed_mcp_server,
    ActionType,
    PermissionLevel,
)


class TestMCPAdapter(unittest.TestCase):
    """Test suite for MCP Adapter"""
    
    def test_create_adapter(self):
        """Test creating an MCP adapter"""
        control_plane = AgentControlPlane()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("mcp-test", permissions)
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.agent_context.agent_id, "mcp-test")
    
    def test_register_tool(self):
        """Test registering an MCP tool"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("tool-test", permissions)
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        tool_info = {
            "name": "read_file",
            "description": "Read a file",
            "inputSchema": {"type": "object"}
        }
        
        adapter.register_tool("read_file", tool_info)
        
        self.assertIn("read_file", adapter.registered_tools)
    
    def test_register_resource(self):
        """Test registering an MCP resource"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("resource-test", permissions)
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        resource_info = {
            "uri": "file://",
            "name": "Files",
            "description": "File resources"
        }
        
        adapter.register_resource("file://", resource_info)
        
        self.assertIn("file://", adapter.registered_resources)
    
    def test_tools_list_message(self):
        """Test handling tools/list MCP message"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("list-test", permissions)
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        # Register a tool
        adapter.register_tool("read_file", {"name": "read_file"})
        
        # Send tools/list message
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        response = adapter.handle_message(message)
        
        self.assertEqual(response["jsonrpc"], "2.0")
        self.assertEqual(response["id"], 1)
        self.assertIn("result", response)
    
    def test_tools_call_allowed(self):
        """Test handling allowed tools/call MCP message"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("call-test", permissions)
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        # Send tools/call message
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/data/test.txt"}
            }
        }
        
        response = adapter.handle_message(message)
        
        # Should succeed (permission granted)
        self.assertEqual(response["jsonrpc"], "2.0")
        self.assertIn("result", response)
    
    def test_tools_call_blocked(self):
        """Test handling blocked tools/call MCP message"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.FILE_WRITE: PermissionLevel.NONE,  # Blocked
        }
        agent_context = control_plane.create_agent("blocked-test", permissions)
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        # Try to call a write tool (should be blocked)
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "/data/test.txt", "content": "data"}
            }
        }
        
        response = adapter.handle_message(message)
        
        # Should return error
        self.assertEqual(response["jsonrpc"], "2.0")
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], -32000)
    
    def test_resources_list_message(self):
        """Test handling resources/list MCP message"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("res-list-test", permissions)
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        # Register a resource
        adapter.register_resource("file://", {"uri": "file://"})
        
        # Send resources/list message
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {}
        }
        
        response = adapter.handle_message(message)
        
        self.assertEqual(response["jsonrpc"], "2.0")
        self.assertIn("result", response)
    
    def test_custom_tool_mapping(self):
        """Test custom tool name mappings"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("mapping-test", permissions)
        
        custom_mapping = {
            "custom_tool": ActionType.FILE_READ,
        }
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            tool_mapping=custom_mapping
        )
        
        self.assertIn("custom_tool", adapter.tool_mapping)
    
    def test_mcp_server_creation(self):
        """Test creating an MCP server"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        
        mcp_server = create_governed_mcp_server(
            control_plane=control_plane,
            agent_id="server-test",
            server_name="test-server",
            permissions=permissions,
            transport="stdio"
        )
        
        self.assertIsNotNone(mcp_server)
        self.assertEqual(mcp_server.server_name, "test-server")
    
    def test_map_tool_to_action(self):
        """Test tool name to ActionType mapping"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("map-test", permissions)
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        # Test various tool names
        self.assertEqual(
            adapter._map_tool_to_action("read_file"),
            ActionType.FILE_READ
        )
        self.assertEqual(
            adapter._map_tool_to_action("sql_query"),
            ActionType.DATABASE_QUERY
        )
        self.assertEqual(
            adapter._map_tool_to_action("api_request"),
            ActionType.API_CALL
        )
    
    def test_map_resource_to_action(self):
        """Test resource URI to ActionType mapping"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("res-map-test", permissions)
        
        adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        # Test various resource URIs
        self.assertEqual(
            adapter._map_resource_to_action("file:///data/test.txt"),
            ActionType.FILE_READ
        )
        self.assertEqual(
            adapter._map_resource_to_action("postgres://localhost/db"),
            ActionType.DATABASE_QUERY
        )
        self.assertEqual(
            adapter._map_resource_to_action("https://api.example.com"),
            ActionType.API_CALL
        )


if __name__ == "__main__":
    unittest.main()
