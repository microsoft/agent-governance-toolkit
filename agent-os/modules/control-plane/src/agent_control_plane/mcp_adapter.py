# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP (Model Context Protocol) Adapter - Agent Control Plane Integration

This adapter provides governance for MCP-compliant tool and resource servers.
MCP is Anthropic's open standard for connecting AI agents to external tools,
data sources, and services.

The MCP adapter intercepts MCP protocol messages (tools/call, resources/read, etc.)
and applies Agent Control Plane governance before allowing execution.

Usage:
    from agent_control_plane import AgentControlPlane
    from agent_control_plane.mcp_adapter import MCPAdapter, MCPServer
    
    # Setup control plane
    control_plane = AgentControlPlane()
    agent_context = control_plane.create_agent("my-agent", permissions)
    
    # Create governed MCP server
    mcp_server = MCPServer(
        server_name="file-server",
        transport="stdio",
        control_plane=control_plane,
        agent_context=agent_context
    )
    
    # Register tools
    mcp_server.register_tool("read_file", handle_read_file)
    mcp_server.register_resource("file://", handle_file_resource)
    
    # All MCP calls are now governed!
    mcp_server.start()
"""

from typing import Any, Dict, List, Optional, Callable, Union
import json
import logging
from datetime import datetime
from enum import Enum

from .agent_kernel import ActionType, AgentContext
from .control_plane import AgentControlPlane


class MCPMessageType(Enum):
    """MCP protocol message types.

    Enumerates the JSON-RPC methods defined by the Model Context Protocol
    specification. Each value corresponds to a method string sent in the
    ``"method"`` field of an MCP JSON-RPC 2.0 request.

    Attributes:
        TOOLS_LIST: List available tools on the server.
        TOOLS_CALL: Invoke a registered tool by name.
        RESOURCES_LIST: List available resources (files, databases, etc.).
        RESOURCES_READ: Read the contents of a specific resource URI.
        PROMPTS_LIST: List available prompt templates.
        PROMPTS_GET: Retrieve a specific prompt template by name.
        COMPLETION: Request a completion (reserved for future use).

    Example:
        >>> msg_type = MCPMessageType.TOOLS_CALL
        >>> msg_type.value
        'tools/call'
    """
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    PROMPTS_LIST = "prompts/list"
    PROMPTS_GET = "prompts/get"
    COMPLETION = "completion/complete"


# Mapping from MCP operations to ActionTypes
DEFAULT_MCP_MAPPING = {
    # Tool operations
    "tools/call": ActionType.CODE_EXECUTION,  # Default for tool calls
    
    # Resource operations
    "resources/read": ActionType.FILE_READ,  # Default for resource reads
    "resources/write": ActionType.FILE_WRITE,  # If write operations exist
    
    # Specific tool patterns
    "file_read": ActionType.FILE_READ,
    "file_write": ActionType.FILE_WRITE,
    "database_query": ActionType.DATABASE_QUERY,
    "database_write": ActionType.DATABASE_WRITE,
    "api_call": ActionType.API_CALL,
    "http_request": ActionType.API_CALL,
}


class MCPAdapter:
    """MCP Protocol Adapter with Agent Control Plane Governance.

    Intercepts MCP protocol messages and applies governance rules before
    forwarding to the actual MCP server or client. MCP uses JSON-RPC 2.0
    for communication, with specific methods like:

    - ``tools/list``: List available tools
    - ``tools/call``: Execute a tool
    - ``resources/list``: List available resources
    - ``resources/read``: Read a resource

    The adapter ensures all operations respect agent permissions and
    policies defined in the control plane. Unknown tools are denied by
    default (secure-by-default).

    Args:
        control_plane: The ``AgentControlPlane`` instance for governance.
        agent_context: The ``AgentContext`` for the agent using this adapter.
        mcp_handler: Optional upstream MCP message handler to delegate to
            after governance checks pass.
        tool_mapping: Optional custom mapping from tool names to
            ``ActionType`` values. Merged with ``DEFAULT_MCP_MAPPING``.
        on_block: Optional callback invoked when an action is blocked.
            Receives ``(tool_name, arguments, check_result)``.
        logger: Optional logger instance.

    Attributes:
        registered_tools: Dictionary of tool name to tool metadata.
        registered_resources: Dictionary of URI pattern to resource metadata.
        tool_mapping: Combined mapping of tool/operation names to
            ``ActionType`` values used for governance decisions.

    Example:
        >>> from agent_control_plane import AgentControlPlane
        >>> from agent_control_plane.mcp_adapter import MCPAdapter
        >>>
        >>> cp = AgentControlPlane()
        >>> ctx = cp.create_agent("my-agent")
        >>> adapter = MCPAdapter(control_plane=cp, agent_context=ctx)
        >>>
        >>> # Register a tool
        >>> adapter.register_tool("read_file", {
        ...     "name": "read_file",
        ...     "description": "Read a file from disk",
        ...     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
        ... })
        >>>
        >>> # Handle an MCP request — governance is applied automatically
        >>> response = adapter.handle_message({
        ...     "jsonrpc": "2.0",
        ...     "id": 1,
        ...     "method": "tools/call",
        ...     "params": {"name": "read_file", "arguments": {"path": "/tmp/data.txt"}}
        ... })
    """
    
    def __init__(
        self,
        control_plane: AgentControlPlane,
        agent_context: AgentContext,
        mcp_handler: Optional[Any] = None,
        tool_mapping: Optional[Dict[str, ActionType]] = None,
        on_block: Optional[Callable[[str, Dict, Dict], None]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the MCP adapter.
        
        Args:
            control_plane: The AgentControlPlane instance for governance
            agent_context: The AgentContext for the agent using this adapter
            mcp_handler: Optional MCP message handler to wrap
            tool_mapping: Optional custom mapping from tool names to ActionTypes
            on_block: Optional callback when an action is blocked
            logger: Optional logger instance
        """
        self.control_plane = control_plane
        self.agent_context = agent_context
        self.mcp_handler = mcp_handler
        self.logger = logger or logging.getLogger("MCPAdapter")
        self.on_block = on_block
        
        # Merge default mapping with custom mapping
        self.tool_mapping = DEFAULT_MCP_MAPPING.copy()
        if tool_mapping:
            self.tool_mapping.update({k.lower(): v for k, v in tool_mapping.items()})
        
        # Register available tools and resources
        self.registered_tools: Dict[str, Dict] = {}
        self.registered_resources: Dict[str, Dict] = {}
        
        self.logger.info(
            f"Initialized MCPAdapter for agent {agent_context.agent_id}"
        )
    
    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an MCP protocol message with governance.

        This is the main entry point for MCP messages. It parses the
        JSON-RPC message, applies governance checks via the control plane,
        and returns the result.

        Args:
            message: MCP JSON-RPC 2.0 message containing ``jsonrpc``,
                ``method``, ``params``, and ``id`` fields.

        Returns:
            A JSON-RPC 2.0 response dict. On success, contains a
            ``"result"`` key. On failure (governance block or error),
            contains an ``"error"`` key with ``"code"`` and ``"message"``.

        Raises:
            PermissionError: Internally raised when governance blocks an
                action; caught and converted to a JSON-RPC error response.
        """
        # Parse the JSON-RPC message
        jsonrpc = message.get("jsonrpc", "2.0")
        method = message.get("method", "")
        params = message.get("params", {})
        msg_id = message.get("id")
        
        self.logger.debug(f"Received MCP message: method={method}, id={msg_id}")
        
        try:
            # Route to appropriate handler based on method
            if method == MCPMessageType.TOOLS_LIST.value:
                result = self._handle_tools_list(params)
            elif method == MCPMessageType.TOOLS_CALL.value:
                result = self._handle_tools_call(params)
            elif method == MCPMessageType.RESOURCES_LIST.value:
                result = self._handle_resources_list(params)
            elif method == MCPMessageType.RESOURCES_READ.value:
                result = self._handle_resources_read(params)
            elif method == MCPMessageType.PROMPTS_LIST.value:
                result = self._handle_prompts_list(params)
            elif method == MCPMessageType.PROMPTS_GET.value:
                result = self._handle_prompts_get(params)
            else:
                # Unknown method
                return self._create_error_response(msg_id, -32601, f"Method not found: {method}")
            
            # Success response
            return {
                "jsonrpc": jsonrpc,
                "id": msg_id,
                "result": result
            }
        
        except PermissionError as e:
            # Governance blocked the action
            self.logger.warning(f"Permission denied: {str(e)}")
            return self._create_error_response(msg_id, -32000, str(e))
        
        except Exception as e:
            # Other errors
            self.logger.error(f"Error handling MCP message: {str(e)}")
            return self._create_error_response(msg_id, -32603, f"Internal error: {str(e)}")
    
    def _handle_tools_list(self, params: Dict) -> Dict:
        """Handle tools/list - return list of available tools."""
        # Return only tools that the agent has permission to use
        allowed_tools = []
        
        for tool_name, tool_info in self.registered_tools.items():
            action_type = self._map_tool_to_action(tool_name)
            if action_type and self._check_permission(action_type, {}):
                allowed_tools.append(tool_info)
        
        return {"tools": allowed_tools}
    
    def _handle_tools_call(self, params: Dict) -> Dict:
        """Handle tools/call — execute a tool with governance.

        Maps the tool name to an ``ActionType``, checks permissions via
        the control plane, and either delegates to the registered handler
        or returns the control plane result.

        Args:
            params: JSON-RPC params containing ``"name"`` and ``"arguments"``.

        Returns:
            Tool execution result dict with MCP ``content`` format.

        Raises:
            PermissionError: If the tool is unknown or governance denies
                the action.
        """
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        
        self.logger.info(f"Tool call request: {tool_name}")
        
        # Map to ActionType
        action_type = self._map_tool_to_action(tool_name)
        
        if action_type is None:
            # Security: Unknown tools are denied by default
            self.logger.warning(f"Unknown tool '{tool_name}', denying by default")
            raise PermissionError(f"Unknown tool: {tool_name}. Tool must be mapped to an ActionType.")
        
        # THE KERNEL CHECK - This is where governance happens
        check_result = self.control_plane.execute_action(
            self.agent_context,
            action_type,
            arguments
        )
        
        if not check_result['success']:
            # Action is BLOCKED
            error_msg = f"Tool call blocked: {check_result.get('error', 'Policy violation')}"
            self.logger.warning(f"BLOCKED: {tool_name} - {error_msg}")
            
            if self.on_block:
                self.on_block(tool_name, arguments, check_result)
            
            raise PermissionError(error_msg)
        
        self.logger.info(f"ALLOWED: {tool_name}")
        
        # If we have a handler, delegate to it
        if self.mcp_handler and hasattr(self.mcp_handler, 'call_tool'):
            return self.mcp_handler.call_tool(tool_name, arguments)
        
        # Otherwise return the result from the control plane
        return {
            "content": [{
                "type": "text",
                "text": json.dumps(check_result.get('result', {}))
            }]
        }
    
    def _handle_resources_list(self, params: Dict) -> Dict:
        """Handle resources/list - return list of available resources."""
        # Return only resources the agent can access
        allowed_resources = []
        
        for resource_uri, resource_info in self.registered_resources.items():
            # Determine appropriate action type for this resource
            action_type = self._map_resource_to_action(resource_uri)
            
            # Check permission for this resource
            if self._check_permission(action_type, {}):
                allowed_resources.append(resource_info)
        
        return {"resources": allowed_resources}
    
    def _handle_resources_read(self, params: Dict) -> Dict:
        """Handle resources/read — read a resource with governance.

        Determines the ``ActionType`` from the URI scheme and checks
        permissions before returning resource contents.

        Args:
            params: JSON-RPC params containing ``"uri"``.

        Returns:
            Resource contents dict with MCP ``contents`` format.

        Raises:
            PermissionError: If governance denies the resource read.
        """
        uri = params.get("uri", "")
        
        self.logger.info(f"Resource read request: {uri}")
        
        # Determine action type based on URI scheme
        action_type = self._map_resource_to_action(uri)
        
        # Check permission
        check_result = self.control_plane.execute_action(
            self.agent_context,
            action_type,
            {"uri": uri}
        )
        
        if not check_result['success']:
            error_msg = f"Resource read blocked: {check_result.get('error', 'Policy violation')}"
            self.logger.warning(f"BLOCKED: {uri} - {error_msg}")
            
            if self.on_block:
                self.on_block(uri, {"uri": uri}, check_result)
            
            raise PermissionError(error_msg)
        
        self.logger.info(f"ALLOWED: resource read {uri}")
        
        # If we have a handler, delegate to it
        if self.mcp_handler and hasattr(self.mcp_handler, 'read_resource'):
            return self.mcp_handler.read_resource(uri)
        
        # Otherwise return a placeholder
        return {
            "contents": [{
                "uri": uri,
                "mimeType": "text/plain",
                "text": json.dumps(check_result.get('result', {}))
            }]
        }
    
    def _handle_prompts_list(self, params: Dict) -> Dict:
        """
        Handle prompts/list - list available prompts.
        
        TODO: Implement actual prompt management when needed.
        """
        # Prompts are generally safe to list
        return {"prompts": []}
    
    def _handle_prompts_get(self, params: Dict) -> Dict:
        """
        Handle prompts/get - get a specific prompt.
        
        TODO: Implement actual prompt retrieval when needed.
        """
        # Prompts are generally safe to retrieve
        prompt_name = params.get("name", "")
        return {
            "messages": [],
            "description": f"Prompt: {prompt_name}"
        }
    
    def _map_tool_to_action(self, tool_name: str) -> Optional[ActionType]:
        """Map an MCP tool name to an ``ActionType``.

        Resolution order:
        1. Exact match in ``self.tool_mapping`` (case-insensitive).
        2. Pattern-based heuristics (e.g. names containing ``"read"``
           and ``"file"`` map to ``FILE_READ``).
        3. Returns ``None`` for unrecognized tools (deny-by-default).

        Args:
            tool_name: The MCP tool name to resolve.

        Returns:
            The corresponding ``ActionType``, or ``None`` if the tool
            cannot be mapped (triggering a denial).
        """
        tool_name_lower = tool_name.lower()
        
        # Check exact match
        if tool_name_lower in self.tool_mapping:
            return self.tool_mapping[tool_name_lower]
        
        # Pattern matching
        if any(p in tool_name_lower for p in ['read', 'get', 'fetch', 'load']) and \
           any(p in tool_name_lower for p in ['file', 'document']):
            return ActionType.FILE_READ
        
        if any(p in tool_name_lower for p in ['write', 'save', 'create', 'update']) and \
           any(p in tool_name_lower for p in ['file', 'document']):
            return ActionType.FILE_WRITE
        
        if any(p in tool_name_lower for p in ['sql', 'query', 'database', 'db']):
            if any(p in tool_name_lower for p in ['insert', 'update', 'delete', 'drop']):
                return ActionType.DATABASE_WRITE
            return ActionType.DATABASE_QUERY
        
        if any(p in tool_name_lower for p in ['api', 'http', 'request']):
            return ActionType.API_CALL
        
        if any(p in tool_name_lower for p in ['exec', 'run', 'execute', 'code', 'python', 'bash']):
            return ActionType.CODE_EXECUTION
        
        # Security: Return None for unknown tools (deny by default)
        return None
    
    def _map_resource_to_action(self, uri: str) -> ActionType:
        """Map a resource URI to an ActionType."""
        if uri.startswith("file://"):
            return ActionType.FILE_READ
        elif uri.startswith("db://") or uri.startswith("postgres://") or uri.startswith("mysql://"):
            return ActionType.DATABASE_QUERY
        elif uri.startswith("http://") or uri.startswith("https://"):
            return ActionType.API_CALL
        else:
            return ActionType.FILE_READ
    
    def _check_permission(self, action_type: ActionType, parameters: Dict) -> bool:
        """Check if the agent has permission for an action."""
        check_result = self.control_plane.execute_action(
            self.agent_context,
            action_type,
            parameters
        )
        return check_result['success']
    
    def _create_error_response(self, msg_id: Any, code: int, message: str) -> Dict:
        """Create a JSON-RPC error response."""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message
            }
        }
    
    def register_tool(self, tool_name: str, tool_info: Dict):
        """
        Register an MCP tool.
        
        Args:
            tool_name: Name of the tool
            tool_info: Tool metadata (description, input schema, etc.)
        """
        self.registered_tools[tool_name] = tool_info
        self.logger.debug(f"Registered MCP tool: {tool_name}")
    
    def register_resource(self, uri_pattern: str, resource_info: Dict):
        """
        Register an MCP resource.
        
        Args:
            uri_pattern: URI pattern (e.g., "file://", "db://")
            resource_info: Resource metadata
        """
        self.registered_resources[uri_pattern] = resource_info
        self.logger.debug(f"Registered MCP resource: {uri_pattern}")
    
    def add_tool_mapping(self, tool_name: str, action_type: ActionType):
        """Add a custom tool to ActionType mapping."""
        self.tool_mapping[tool_name.lower()] = action_type
        self.logger.debug(f"Added MCP tool mapping: {tool_name} -> {action_type.value}")


class MCPServer:
    """Simplified MCP Server with built-in governance.

    Provides a high-level API for creating an MCP-compliant server with
    Agent Control Plane governance built in. Wraps an ``MCPAdapter``
    internally and exposes convenience methods for tool and resource
    registration.

    Args:
        server_name: Human-readable name for this MCP server.
        control_plane: ``AgentControlPlane`` instance for governance.
        agent_context: ``AgentContext`` representing the server's agent.
        transport: Transport method — ``"stdio"`` (default) or ``"sse"``.
        logger: Optional logger instance.

    Attributes:
        adapter: The underlying ``MCPAdapter`` that handles governance.
        server_name: Name of this server.
        transport: Active transport method.

    Example:
        >>> from agent_control_plane import AgentControlPlane
        >>> from agent_control_plane.mcp_adapter import MCPServer
        >>>
        >>> cp = AgentControlPlane()
        >>> ctx = cp.create_agent("file-agent")
        >>> server = MCPServer("file-server", cp, ctx, transport="stdio")
        >>>
        >>> server.register_tool("read_file", handle_read, "Read a file")
        >>> server.register_resource("file://", handle_resource, "File resources")
        >>> server.start()  # All calls are now governed
    """
    
    def __init__(
        self,
        server_name: str,
        control_plane: AgentControlPlane,
        agent_context: AgentContext,
        transport: str = "stdio",
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize an MCP server.
        
        Args:
            server_name: Name of the MCP server
            control_plane: Agent Control Plane instance
            agent_context: Agent context
            transport: Transport method ("stdio" or "sse")
            logger: Optional logger
        """
        self.server_name = server_name
        self.transport = transport
        self.logger = logger or logging.getLogger(f"MCPServer.{server_name}")
        
        # Create the adapter
        self.adapter = MCPAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            logger=self.logger
        )
        
        self.logger.info(f"Initialized MCP server: {server_name}")
    
    def register_tool(self, tool_name: str, handler: Callable, description: str = ""):
        """Register a tool with the server."""
        tool_info = {
            "name": tool_name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }
        self.adapter.register_tool(tool_name, tool_info)
    
    def register_resource(self, uri_pattern: str, handler: Callable, description: str = ""):
        """Register a resource with the server."""
        resource_info = {
            "uri": uri_pattern,
            "name": uri_pattern,
            "description": description,
            "mimeType": "text/plain"
        }
        self.adapter.register_resource(uri_pattern, resource_info)
    
    def handle_request(self, request: Dict) -> Dict:
        """Handle an MCP request."""
        return self.adapter.handle_message(request)
    
    def start(self):
        """
        Start the MCP server (placeholder for actual implementation).
        
        Note: This is a simplified server implementation. For production use,
        you would need to implement:
        - Actual transport handling (stdio, SSE, HTTP)
        - Request/response queuing
        - Connection management
        - Error recovery
        """
        self.logger.info(f"MCP server '{self.server_name}' started on {self.transport}")


def create_governed_mcp_server(
    control_plane: AgentControlPlane,
    agent_id: str,
    server_name: str,
    permissions: Optional[Dict[ActionType, Any]] = None,
    transport: str = "stdio"
) -> MCPServer:
    """
    Convenience function to create a governed MCP server.
    
    Args:
        control_plane: Agent Control Plane instance
        agent_id: Agent ID
        server_name: Name for the MCP server
        permissions: Optional agent permissions
        transport: Transport method ("stdio" or "sse")
        
    Returns:
        A governed MCPServer instance
    """
    agent_context = control_plane.create_agent(agent_id, permissions)
    
    return MCPServer(
        server_name=server_name,
        control_plane=control_plane,
        agent_context=agent_context,
        transport=transport
    )
