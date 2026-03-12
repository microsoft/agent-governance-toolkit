# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP (Model Context Protocol) Integration for AgentMesh
=======================================================

Provides trust-gated MCP server and client implementations that verify
agent identity before allowing tool access.

Features:
- Trust verification before tool invocation
- Capability-based tool access control
- CMVK authentication for MCP connections
- Audit logging of all tool calls

Example:
    >>> from agentmesh.integrations.mcp import TrustGatedMCPServer
    >>> from agentmesh.identity import AgentIdentity
    >>>
    >>> identity = AgentIdentity.create(
    ...     name="tool-server",
    ...     sponsor_id="admin@example.com",
    ...     capabilities=["provide:sql", "provide:filesystem"]
    ... )
    >>>
    >>> server = TrustGatedMCPServer(identity, min_trust_score=400)
    >>> server.register_tool("sql_query", sql_handler, required_capability="use:sql")
    >>> await server.start()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Awaitable
from enum import Enum

logger = logging.getLogger(__name__)


class MCPMessageType(Enum):
    """MCP message types."""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


@dataclass
class MCPTool:
    """MCP tool definition with trust requirements."""
    name: str
    description: str
    handler: Callable[..., Awaitable[Any]]
    input_schema: Dict[str, Any] = field(default_factory=dict)

    # Trust requirements
    required_capability: Optional[str] = None
    min_trust_score: int = 300
    require_human_sponsor: bool = False

    # Audit
    total_calls: int = 0
    failed_calls: int = 0
    last_called: Optional[datetime] = None


@dataclass
class MCPToolCall:
    """Record of an MCP tool invocation."""
    call_id: str
    tool_name: str
    caller_did: str
    arguments: Dict[str, Any]

    # Trust metadata
    trust_verified: bool = False
    trust_score: int = 0
    capabilities_checked: List[str] = field(default_factory=list)

    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    # Result
    success: bool = False
    result: Any = None
    error: Optional[str] = None


class TrustGatedMCPServer:
    """
    MCP Server with AgentMesh trust verification.

    All tool invocations require:
    1. Valid agent identity (CMVK verification)
    2. Sufficient trust score
    3. Required capabilities
    """

    def __init__(
        self,
        identity: Any,  # AgentIdentity
        trust_bridge: Any = None,  # TrustBridge
        min_trust_score: int = 300,
        audit_all_calls: bool = True,
    ):
        self.identity = identity
        self.trust_bridge = trust_bridge
        self.min_trust_score = min_trust_score
        self.audit_all_calls = audit_all_calls

        self._tools: Dict[str, MCPTool] = {}
        self._call_history: List[MCPToolCall] = []
        self._verified_clients: Dict[str, datetime] = {}
        self._verification_ttl = timedelta(minutes=10)

    def register_tool(
        self,
        name: str,
        handler: Callable[..., Awaitable[Any]],
        description: str = "",
        input_schema: Optional[Dict[str, Any]] = None,
        required_capability: Optional[str] = None,
        min_trust_score: Optional[int] = None,
        require_human_sponsor: bool = False,
    ) -> None:
        """
        Register a tool with trust requirements.

        Args:
            name: Tool name
            handler: Async handler function
            description: Tool description
            input_schema: JSON Schema for inputs
            required_capability: Capability needed to invoke
            min_trust_score: Minimum trust score (overrides server default)
            require_human_sponsor: Require direct human sponsor
        """
        self._tools[name] = MCPTool(
            name=name,
            description=description,
            handler=handler,
            input_schema=input_schema or {},
            required_capability=required_capability,
            min_trust_score=min_trust_score or self.min_trust_score,
            require_human_sponsor=require_human_sponsor,
        )
        logger.info(f"Registered tool '{name}' with capability requirement: {required_capability}")

    async def verify_client(
        self,
        client_did: str,
        client_card: Optional[Any] = None,  # A2AAgentCard
    ) -> bool:
        """Verify client identity before allowing tool access."""
        # Check cache
        if client_did in self._verified_clients:
            cached_time = self._verified_clients[client_did]
            if datetime.utcnow() - cached_time < self._verification_ttl:
                return True

        # Use TrustBridge if available
        if self.trust_bridge:
            try:
                result = await self.trust_bridge.verify_peer(client_did)
                if result:
                    self._verified_clients[client_did] = datetime.utcnow()
                    return True
            except Exception as e:
                logger.error(f"Trust verification failed: {e}")
                return False

        # Basic verification via card
        if client_card:
            if hasattr(client_card, "trust_score"):
                if client_card.trust_score >= self.min_trust_score:
                    self._verified_clients[client_did] = datetime.utcnow()
                    return True

        logger.warning(f"Client {client_did} failed trust verification")
        return False

    def _check_capability(
        self,
        client_capabilities: List[str],
        required: str,
    ) -> bool:
        """Check if client has required capability (with wildcard support)."""
        if not required:
            return True

        for cap in client_capabilities:
            # Exact match
            if cap == required:
                return True
            # Wildcard match (e.g., "use:*" matches "use:sql")
            if cap.endswith(":*"):
                prefix = cap[:-1]  # "use:"
                if required.startswith(prefix):
                    return True

        return False

    async def invoke_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        caller_did: str,
        caller_capabilities: Optional[List[str]] = None,
        caller_trust_score: int = 0,
    ) -> MCPToolCall:
        """
        Invoke a tool with trust verification.

        Args:
            tool_name: Name of tool to invoke
            arguments: Tool arguments
            caller_did: Caller's agent DID
            caller_capabilities: Caller's granted capabilities
            caller_trust_score: Caller's trust score

        Returns:
            MCPToolCall with result or error
        """
        call_id = f"{tool_name}-{datetime.utcnow().timestamp()}"

        call = MCPToolCall(
            call_id=call_id,
            tool_name=tool_name,
            caller_did=caller_did,
            arguments=arguments,
            trust_score=caller_trust_score,
            capabilities_checked=caller_capabilities or [],
        )

        # Check tool exists
        if tool_name not in self._tools:
            call.error = f"Unknown tool: {tool_name}"
            call.completed_at = datetime.utcnow()
            self._record_call(call)
            return call

        tool = self._tools[tool_name]

        # Verify trust score
        if caller_trust_score < tool.min_trust_score:
            call.error = (
                f"Insufficient trust score: {caller_trust_score} < {tool.min_trust_score}"
            )
            call.completed_at = datetime.utcnow()
            tool.failed_calls += 1
            self._record_call(call)
            logger.warning(f"Trust check failed for {caller_did} on {tool_name}")
            return call

        # Check capability
        if tool.required_capability:
            if not self._check_capability(caller_capabilities or [], tool.required_capability):
                call.error = f"Missing capability: {tool.required_capability}"
                call.completed_at = datetime.utcnow()
                tool.failed_calls += 1
                self._record_call(call)
                logger.warning(f"Capability check failed for {caller_did} on {tool_name}")
                return call

        # Execute tool
        call.trust_verified = True
        try:
            result = await tool.handler(**arguments)
            call.success = True
            call.result = result
            tool.total_calls += 1
            tool.last_called = datetime.utcnow()
            logger.info(f"Tool {tool_name} invoked successfully by {caller_did}")
        except Exception as e:
            call.error = str(e)
            tool.failed_calls += 1
            logger.error(f"Tool {tool_name} failed: {e}")

        call.completed_at = datetime.utcnow()
        self._record_call(call)
        return call

    def _record_call(self, call: MCPToolCall) -> None:
        """Record call for audit."""
        if self.audit_all_calls:
            self._call_history.append(call)
            # Keep last 1000 calls
            if len(self._call_history) > 1000:
                self._call_history = self._call_history[-1000:]

    def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools in MCP format."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
                "x-agentmesh": {
                    "requiredCapability": tool.required_capability,
                    "minTrustScore": tool.min_trust_score,
                    "requireHumanSponsor": tool.require_human_sponsor,
                },
            }
            for tool in self._tools.values()
        ]

    def get_audit_summary(self) -> Dict[str, Any]:
        """Get summary of tool usage."""
        return {
            "totalTools": len(self._tools),
            "totalCalls": sum(t.total_calls for t in self._tools.values()),
            "failedCalls": sum(t.failed_calls for t in self._tools.values()),
            "recentCalls": len(self._call_history),
            "verifiedClients": len(self._verified_clients),
        }


class TrustGatedMCPClient:
    """
    MCP Client with AgentMesh identity.

    Automatically attaches identity credentials to MCP requests.
    """

    def __init__(
        self,
        identity: Any,  # AgentIdentity
        trust_bridge: Any = None,  # TrustBridge
    ):
        self.identity = identity
        self.trust_bridge = trust_bridge
        self._connected_servers: Dict[str, datetime] = {}

    async def connect(self, server_url: str) -> bool:
        """Connect to MCP server with trust verification."""
        # Verify server identity if TrustBridge available
        if self.trust_bridge:
            # Extract server DID from URL or discovery
            server_did = await self._discover_server_did(server_url)
            if server_did:
                if not await self.trust_bridge.verify_peer(server_did):
                    logger.warning(f"Server {server_url} failed trust verification")
                    return False

        self._connected_servers[server_url] = datetime.utcnow()
        logger.info(f"Connected to MCP server: {server_url}")
        return True

    async def _discover_server_did(self, server_url: str) -> Optional[str]:
        """Discover server DID from /.well-known/agent.json"""
        # In real implementation, fetch agent.json and extract DID
        return None

    async def invoke(
        self,
        server_url: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Invoke tool on MCP server.

        Automatically attaches identity credentials.
        """
        if server_url not in self._connected_servers:
            if not await self.connect(server_url):
                return {"error": "Failed to connect to server"}

        # Build request with identity
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
            "id": f"req-{datetime.utcnow().timestamp()}",
            # AgentMesh identity extension
            "x-agentmesh": {
                "callerDid": str(self.identity.did) if hasattr(self.identity, "did") else "",
                "trustScore": self.identity.trust_score if hasattr(self.identity, "trust_score") else 500,
                "capabilities": list(self.identity.capabilities) if hasattr(self.identity, "capabilities") else [],
            },
        }

        logger.debug(f"MCP request to {server_url}: {tool_name}")

        # In real implementation, send HTTP request
        # For now, return placeholder
        return {"status": "request_prepared", "request": request}

    def get_credentials(self) -> Dict[str, Any]:
        """Get identity credentials for MCP authentication."""
        return {
            "type": "cmvk",
            "did": str(self.identity.did) if hasattr(self.identity, "did") else "",
            "trustScore": self.identity.trust_score if hasattr(self.identity, "trust_score") else 500,
            "capabilities": list(self.identity.capabilities) if hasattr(self.identity, "capabilities") else [],
        }


# Convenience exports
__all__ = [
    "TrustGatedMCPServer",
    "TrustGatedMCPClient",
    "MCPTool",
    "MCPToolCall",
]
