# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP (Model Context Protocol) Integration Demo - Agent Control Plane

This example demonstrates how to use the Agent Control Plane with MCP
to govern tool and resource calls in MCP-compliant servers.

MCP is Anthropic's open standard for connecting AI agents to external tools,
data sources, and services.
"""

import sys
import os
import json

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from agent_control_plane import (
    AgentControlPlane,
    MCPAdapter,
    MCPServer,
    create_governed_mcp_server,
    ActionType,
    PermissionLevel,
)


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_basic_mcp_server():
    """Demonstrate basic MCP server with governance"""
    print_section("Demo 1: Basic MCP Server with Governance")
    
    # Create control plane
    control_plane = AgentControlPlane()
    
    # Define permissions
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.FILE_WRITE: PermissionLevel.NONE,  # Blocked!
    }
    
    # Create governed MCP server
    mcp_server = create_governed_mcp_server(
        control_plane=control_plane,
        agent_id="mcp-file-server",
        server_name="file-server",
        permissions=permissions,
        transport="stdio"
    )
    
    print("✓ Created governed MCP server")
    print(f"✓ Server name: file-server")
    print(f"✓ Transport: stdio (standard input/output)")
    print(f"✓ Permissions: READ_ONLY for files and database")
    print(f"✓ File writes: BLOCKED\n")
    
    # Register tools
    def handle_read_file(args):
        return {"content": f"Mock file content from {args.get('path', 'unknown')}"}
    
    mcp_server.register_tool("read_file", handle_read_file, "Read a file from disk")
    
    print("✓ Registered tool: read_file")
    print("✓ All tool calls will be governed by the control plane!")


def demo_mcp_protocol_messages():
    """Demonstrate MCP protocol message handling"""
    print_section("Demo 2: MCP Protocol Message Handling")
    
    control_plane = AgentControlPlane()
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
    }
    agent_context = control_plane.create_agent("mcp-client", permissions)
    
    # Create MCP adapter
    adapter = MCPAdapter(
        control_plane=control_plane,
        agent_context=agent_context
    )
    
    # Register a tool
    adapter.register_tool("read_file", {
        "name": "read_file",
        "description": "Read a file from the filesystem",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            }
        }
    })
    
    print("✓ Created MCP adapter")
    print("✓ Registered tool: read_file\n")
    
    # Example 1: tools/list request
    print("Example 1: List available tools (tools/list)")
    list_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }
    
    response = adapter.handle_message(list_request)
    print(f"Request: {json.dumps(list_request, indent=2)}")
    print(f"Response: {json.dumps(response, indent=2)}\n")
    
    # Example 2: tools/call request (allowed)
    print("Example 2: Call tool - allowed (tools/call)")
    call_request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/data/test.txt"}
        }
    }
    
    response = adapter.handle_message(call_request)
    print(f"Request: {json.dumps(call_request, indent=2)}")
    print(f"Response: {json.dumps(response, indent=2)}\n")
    
    print("✓ MCP protocol messages are handled with governance")
    print("✓ JSON-RPC 2.0 format for requests and responses")


def demo_mcp_resources():
    """Demonstrate MCP resource handling"""
    print_section("Demo 3: MCP Resource Handling")
    
    control_plane = AgentControlPlane()
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
    }
    agent_context = control_plane.create_agent("mcp-resource-client", permissions)
    
    adapter = MCPAdapter(
        control_plane=control_plane,
        agent_context=agent_context
    )
    
    # Register resources
    adapter.register_resource("file://", {
        "uri": "file://",
        "name": "Local Files",
        "description": "Access to local filesystem",
        "mimeType": "text/plain"
    })
    
    print("✓ Created MCP adapter")
    print("✓ Registered resource: file://\n")
    
    # List resources
    print("Example 1: List available resources (resources/list)")
    list_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "resources/list",
        "params": {}
    }
    
    response = adapter.handle_message(list_request)
    print(f"Response: {json.dumps(response, indent=2)}\n")
    
    # Read a resource
    print("Example 2: Read a resource (resources/read)")
    read_request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/read",
        "params": {
            "uri": "file:///data/test.txt"
        }
    }
    
    response = adapter.handle_message(read_request)
    print(f"Request: {json.dumps(read_request, indent=2)}")
    print(f"Response: {json.dumps(response, indent=2)}\n")
    
    print("✓ MCP resources are governed just like tools")
    print("✓ URI-based resource access with permissions")


def demo_mcp_error_handling():
    """Demonstrate MCP error handling for blocked actions"""
    print_section("Demo 4: MCP Error Handling - Blocked Actions")
    
    control_plane = AgentControlPlane()
    
    # Restrictive permissions - no write access
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.FILE_WRITE: PermissionLevel.NONE,  # Blocked!
    }
    agent_context = control_plane.create_agent("restricted-mcp-client", permissions)
    
    adapter = MCPAdapter(
        control_plane=control_plane,
        agent_context=agent_context
    )
    
    # Register a write tool
    adapter.register_tool("write_file", {
        "name": "write_file",
        "description": "Write to a file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"}
            }
        }
    })
    
    print("✓ Created MCP adapter with restricted permissions")
    print("✓ File writes: BLOCKED\n")
    
    # Try to call the blocked tool
    print("Example: Attempt to write file (BLOCKED)")
    write_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "/data/output.txt",
                "content": "This should be blocked"
            }
        }
    }
    
    response = adapter.handle_message(write_request)
    print(f"Request: {json.dumps(write_request, indent=2)}")
    print(f"Response: {json.dumps(response, indent=2)}\n")
    
    print("✓ Blocked actions return JSON-RPC error responses")
    print("✓ Error code -32000 for permission errors")
    print("✓ Clear error messages for debugging")


def demo_integration_pattern():
    """Demonstrate real-world MCP integration"""
    print_section("Demo 5: Real-World MCP Integration Pattern")
    
    print("Real-world MCP server integration pattern:\n")
    
    print("1. Server Setup:")
    print("   ```python")
    print("   from agent_control_plane import create_governed_mcp_server")
    print("   ")
    print("   # Create governed MCP server")
    print("   mcp_server = create_governed_mcp_server(")
    print("       control_plane=control_plane,")
    print("       agent_id='production-mcp-server',")
    print("       server_name='company-data-server',")
    print("       permissions={")
    print("           ActionType.FILE_READ: PermissionLevel.READ_ONLY,")
    print("           ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,")
    print("       },")
    print("       transport='stdio'")
    print("   )")
    print("   ```\n")
    
    print("2. Register Tools and Resources:")
    print("   ```python")
    print("   # Register tools")
    print("   mcp_server.register_tool('read_file', handle_read_file,")
    print("                            'Read files from disk')")
    print("   mcp_server.register_tool('query_db', handle_query_db,")
    print("                            'Query the database')")
    print("   ")
    print("   # Register resources")
    print("   mcp_server.register_resource('file://', handle_file_resource,")
    print("                                'Access to local files')")
    print("   mcp_server.register_resource('db://', handle_db_resource,")
    print("                               'Database access')")
    print("   ```\n")
    
    print("3. Start Server:")
    print("   ```python")
    print("   # Start the MCP server")
    print("   mcp_server.start()")
    print("   ")
    print("   # Process incoming MCP requests")
    print("   while True:")
    print("       request = receive_mcp_request()  # From stdio, SSE, etc.")
    print("       response = mcp_server.handle_request(request)")
    print("       send_mcp_response(response)")
    print("   ```\n")
    
    print("4. Benefits:")
    print("   ✓ Standard MCP protocol compliance")
    print("   ✓ All tools and resources governed")
    print("   ✓ Works with any MCP-compatible client")
    print("   ✓ Complete audit trail")
    print("   ✓ Easy integration with Claude, IDEs, etc.")


def demo_mcp_features():
    """Demonstrate MCP protocol features"""
    print_section("Demo 6: MCP Protocol Features")
    
    print("MCP (Model Context Protocol) Features:\n")
    
    print("1. Tools (Function Calling):")
    print("   - Expose functions to AI agents")
    print("   - Input schema validation")
    print("   - Governed execution\n")
    
    print("2. Resources (Data Access):")
    print("   - URI-based resource access")
    print("   - Multiple resource types (files, databases, APIs)")
    print("   - Read operations with governance\n")
    
    print("3. Prompts (Templated Prompts):")
    print("   - Pre-defined prompt templates")
    print("   - Consistent agent behavior")
    print("   - Safe prompt management\n")
    
    print("4. JSON-RPC 2.0:")
    print("   - Standard protocol format")
    print("   - Request/response structure")
    print("   - Error handling\n")
    
    print("5. Transports:")
    print("   - stdio: Standard input/output")
    print("   - SSE: Server-Sent Events")
    print("   - HTTP: REST API\n")
    
    print("✓ Agent Control Plane governs all MCP operations")
    print("✓ Same governance approach across all transports")
    print("✓ Compatible with any MCP-compliant client")


def main():
    """Run all demos"""
    print("\n" + "=" * 80)
    print("  MCP (Model Context Protocol) Integration Demo")
    print("=" * 80)
    
    try:
        demo_basic_mcp_server()
        demo_mcp_protocol_messages()
        demo_mcp_resources()
        demo_mcp_error_handling()
        demo_integration_pattern()
        demo_mcp_features()
        
        print_section("Summary")
        print("✓ MCP adapter provides governance for MCP protocol")
        print("✓ Standard JSON-RPC 2.0 message handling")
        print("✓ Tools and resources are governed")
        print("✓ Error responses for blocked actions")
        print("✓ Compatible with any MCP client")
        print("\n✓ Use MCP to connect agents to external tools")
        print("✓ Agent Control Plane ensures safe execution!")
        print("\n" + "=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
