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
import uuid
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
        self._max_verified_clients = 10_000

        # P10: Circuit breaker — track consecutive failures per tool
        self._tool_failures: Dict[str, int] = {}
        self._circuit_breaker_threshold = 5  # open circuit after 5 consecutive failures
        self._circuit_breaker_reset = timedelta(minutes=1)

    # P05: Maximum tool description length to prevent prompt injection via descriptions
    _MAX_DESCRIPTION_LENGTH = 1000
    # P12: Maximum total size of tool arguments (bytes when serialized)
    _MAX_ARGUMENTS_SIZE = 1_048_576  # 1 MB

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
            description: Tool description (max 1000 chars, stripped of control chars)
            input_schema: JSON Schema for inputs
            required_capability: Capability needed to invoke
            min_trust_score: Minimum trust score (overrides server default)
            require_human_sponsor: Require direct human sponsor
        """
        # P05: Sanitize tool description — truncate and strip control characters
        import re as _re
        clean_desc = _re.sub(r"[\x00-\x1f\x7f-\x9f]", "", description)
        if len(clean_desc) > self._MAX_DESCRIPTION_LENGTH:
            logger.warning(
                "Tool '%s' description truncated from %d to %d chars",
                name, len(clean_desc), self._MAX_DESCRIPTION_LENGTH,
            )
            clean_desc = clean_desc[:self._MAX_DESCRIPTION_LENGTH]

        self._tools[name] = MCPTool(
            name=name,
            description=clean_desc,
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
            # Expired — remove stale entry
            del self._verified_clients[client_did]

        # V22: Evict expired entries when cache grows too large
        if len(self._verified_clients) >= self._max_verified_clients:
            self._evict_expired_clients()

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

    def _evict_expired_clients(self) -> None:
        """Remove expired entries from the verified clients cache."""
        now = datetime.utcnow()
        expired = [
            did for did, ts in self._verified_clients.items()
            if now - ts >= self._verification_ttl
        ]
        for did in expired:
            del self._verified_clients[did]

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
        call_id = f"{tool_name}-{uuid.uuid4().hex}"

        call = MCPToolCall(
            call_id=call_id,
            tool_name=tool_name,
            caller_did=caller_did,
            arguments=arguments,
            trust_score=caller_trust_score,
            capabilities_checked=caller_capabilities or [],
        )

        # P12: Reject oversized arguments to prevent memory DoS
        import json as _json
        try:
            args_size = len(_json.dumps(arguments))
        except (TypeError, ValueError):
            args_size = 0
        if args_size > self._MAX_ARGUMENTS_SIZE:
            call.error = f"Arguments too large: {args_size} bytes exceeds {self._MAX_ARGUMENTS_SIZE} limit"
            call.completed_at = datetime.utcnow()
            self._record_call(call)
            return call

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

        # P10: Circuit breaker — reject if tool has too many consecutive failures
        fail_count = self._tool_failures.get(tool_name, 0)
        if fail_count >= self._circuit_breaker_threshold:
            call.error = f"Circuit breaker open: {tool_name} has {fail_count} consecutive failures"
            call.completed_at = datetime.utcnow()
            self._record_call(call)
            return call

        try:
            # V12: Validate arguments against input_schema before dispatch
            allowed_keys = set(tool.input_schema.get("properties", {}).keys())
            if allowed_keys:
                sanitized = {k: v for k, v in arguments.items() if k in allowed_keys}
                stripped = set(arguments.keys()) - allowed_keys
                if stripped:
                    logger.warning(
                        "Stripped unexpected kwargs from %s call by %s: %s",
                        tool_name, caller_did, stripped,
                    )
            else:
                sanitized = arguments
            result = await tool.handler(**sanitized)
            call.success = True
            call.result = result
            tool.total_calls += 1
            tool.last_called = datetime.utcnow()
            self._tool_failures.pop(tool_name, None)  # reset on success
            logger.info(f"Tool {tool_name} invoked successfully by {caller_did}")
        except Exception as e:
            # P11: Sanitize exception — don't log full message (may contain PII)
            error_type = type(e).__name__
            call.error = f"{error_type}: {str(e)[:200]}"
            tool.failed_calls += 1
            self._tool_failures[tool_name] = self._tool_failures.get(tool_name, 0) + 1
            logger.error("Tool %s failed with %s (caller: %s)", tool_name, error_type, caller_did)

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
        # V18: Validate server URL scheme
        from urllib.parse import urlparse
        parsed = urlparse(server_url)
        if parsed.scheme not in ("http", "https", "ws", "wss"):
            logger.warning("Rejected server URL with invalid scheme: %s", server_url)
            return False
        if not parsed.hostname:
            logger.warning("Rejected server URL with missing host: %s", server_url)
            return False
        # Block common internal/loopback targets
        _blocked_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254"}
        if parsed.hostname.lower() in _blocked_hosts:
            logger.warning("Rejected internal/loopback server URL: %s", server_url)
            return False

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

        Raises:
            NotImplementedError: HTTP transport is not yet available.
        """
        if server_url not in self._connected_servers:
            if not await self.connect(server_url):
                return {"error": "Failed to connect to server"}

        raise NotImplementedError(
            "MCP HTTP transport is not yet implemented. "
            f"Cannot send request to {server_url} for tool '{tool_name}'. "
            "Provide an HTTP transport backend via a subclass or plugin."
        )

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
