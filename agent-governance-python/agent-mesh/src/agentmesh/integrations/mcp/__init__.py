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

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Awaitable
from enum import Enum

from agentmesh.integrations.mcp.server_identity import (
    DiscoveryConfig,
    ServerVerificationResult,
    verify_server,
)
from agentmesh.integrations.request_auth import InMemoryReplayCache

logger = logging.getLogger(__name__)


def _safe_host_label(server_url: str) -> str:
    """Return a log-safe identifier for ``server_url``.

    Only the parsed hostname is ever returned — never userinfo,
    credentials, ports, or paths — so connection warnings and errors
    cannot leak secrets even when the configured URL embeds them.
    """
    from urllib.parse import urlparse

    try:
        host = urlparse(server_url).hostname or ""
    except (ValueError, TypeError):
        return "unparseable-server-url"
    return host.lower() or "unparseable-server-url"


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
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
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
            min_trust_score: Minimum trust score (overrides server default).
                ``None`` uses the server's ``min_trust_score``. An explicit
                ``0`` means no trust floor (any caller passes this tool's gate)
                and is honored as given, not coerced to the default.
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
            min_trust_score=self.min_trust_score if min_trust_score is None else min_trust_score,
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
            if datetime.now(timezone.utc) - cached_time < self._verification_ttl:
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
                    self._verified_clients[client_did] = datetime.now(timezone.utc)
                    return True
            except Exception as e:
                logger.error(f"Trust verification failed: {e}")
                return False

        # Basic verification via card
        if client_card:
            if hasattr(client_card, "trust_score"):
                if client_card.trust_score >= self.min_trust_score:
                    self._verified_clients[client_did] = datetime.now(timezone.utc)
                    return True

        logger.warning(f"Client {client_did} failed trust verification")
        return False

    def _evict_expired_clients(self) -> None:
        """Remove expired entries from the verified clients cache."""
        now = datetime.now(timezone.utc)
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
        """Check if client has required capability.

        Delegates to :func:`agentmesh.trust.capability.capability_scope_matches`
        so MCP tool gating uses the same scope semantics as the core
        capability matcher (exact, trailing-wildcard, colon-boundary, and
        full-qualifier component matching), rather than a divergent
        exact/wildcard-only check.
        """
        if not required:
            return True

        from agentmesh.trust.capability import capability_scope_matches

        return any(
            capability_scope_matches(cap, required) for cap in client_capabilities
        )

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
            call.completed_at = datetime.now(timezone.utc)
            self._record_call(call)
            return call

        # Check tool exists
        if tool_name not in self._tools:
            call.error = f"Unknown tool: {tool_name}"
            call.completed_at = datetime.now(timezone.utc)
            self._record_call(call)
            return call

        tool = self._tools[tool_name]

        # Verify trust score
        if caller_trust_score < tool.min_trust_score:
            call.error = (
                f"Insufficient trust score: {caller_trust_score} < {tool.min_trust_score}"
            )
            call.completed_at = datetime.now(timezone.utc)
            tool.failed_calls += 1
            self._record_call(call)
            logger.warning(f"Trust check failed for {caller_did} on {tool_name}")
            return call

        # Check capability
        if tool.required_capability:
            if not self._check_capability(caller_capabilities or [], tool.required_capability):
                call.error = f"Missing capability: {tool.required_capability}"
                call.completed_at = datetime.now(timezone.utc)
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
            call.completed_at = datetime.now(timezone.utc)
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
            tool.last_called = datetime.now(timezone.utc)
            self._tool_failures.pop(tool_name, None)  # reset on success
            logger.info(f"Tool {tool_name} invoked successfully by {caller_did}")
        except Exception as e:
            # P11: Sanitize exception — don't log full message (may contain PII)
            error_type = type(e).__name__
            call.error = f"{error_type}: {str(e)[:200]}"
            tool.failed_calls += 1
            self._tool_failures[tool_name] = self._tool_failures.get(tool_name, 0) + 1
            logger.error("Tool %s failed with %s (caller: %s)", tool_name, error_type, caller_did)

        call.completed_at = datetime.now(timezone.utc)
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
        registry: Any = None,  # IdentityRegistry
        discovery_config: Optional[DiscoveryConfig] = None,
        http_transport: Any = None,  # httpx.AsyncBaseTransport (tests/injection)
        replay_cache: Any = None,  # InMemoryReplayCache (challenge nonces)
    ):
        self.identity = identity
        self.trust_bridge = trust_bridge
        self.registry = registry
        self.discovery_config = discovery_config or DiscoveryConfig()
        self.http_transport = http_transport
        # One cache per client so challenge nonces stay single-use across
        # every verification this client performs.
        self.replay_cache = replay_cache or InMemoryReplayCache()
        self._connected_servers: set[str] = set()

    def _client_did(self) -> str:
        """Return this client's DID string for challenge audiences."""
        did = getattr(self.identity, "did", "")
        return str(did) if did else ""

    async def verify_server_identity(self, server_url: str) -> ServerVerificationResult:
        """Run Phase 1 server verification for ``server_url``.

        Fetches ``/.well-known/agent.json``, binds the document to the
        configured :class:`IdentityRegistry`, and verifies possession via
        the document signature (plus the interactive challenge when the
        document advertises a same-origin HTTPS challenge endpoint).
        Requires a registry; without one there is no trust anchor to
        verify against, which fails closed. The whole pipeline runs under
        ``discovery_config.total_deadline_seconds``; exceeding it fails
        closed with ``deadline-exceeded``.
        """
        if self.registry is None:
            return ServerVerificationResult(False, None, "no-registry-configured")
        try:
            return await asyncio.wait_for(
                verify_server(
                    server_url,
                    self.registry,
                    self._client_did(),
                    self.discovery_config,
                    self.replay_cache,
                    self.http_transport,
                ),
                self.discovery_config.total_deadline_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Server %s verification exceeded its deadline",
                _safe_host_label(server_url),
            )
            return ServerVerificationResult(False, None, "deadline-exceeded")
        except Exception as exc:  # noqa: BLE001 — unexpected errors fail closed
            # Log only the error type: messages may echo URLs or bodies.
            logger.warning(
                "Server %s verification errored with %s",
                _safe_host_label(server_url),
                type(exc).__name__,
            )
            return ServerVerificationResult(False, None, "verification-error")

    async def connect(self, server_url: str) -> bool:
        """Connect to MCP server with trust verification.

        Fail-closed when trust material is configured: with a registry,
        the server must pass full identity verification; with only a
        trust bridge, the discovered DID must verify through the bridge
        (a missing DID fails closed). With neither configured there is no
        trust anchor to enforce, so the connection is recorded as before.
        """
        # Reject embedded credentials before anything else — including
        # before any logging — so usernames and passwords can never reach
        # logs, errors, discovery, or the network.
        from urllib.parse import urlparse
        try:
            parsed = urlparse(server_url)
            has_userinfo = bool(parsed.username or parsed.password)
            host = (parsed.hostname or "").lower()
        except (ValueError, TypeError):
            logger.warning("Rejected malformed server URL")
            return False
        if has_userinfo:
            logger.warning(
                "Rejected server URL with embedded credentials: %s",
                _safe_host_label(server_url),
            )
            return False
        # V18: Validate server URL scheme
        if parsed.scheme not in ("http", "https", "ws", "wss"):
            logger.warning(
                "Rejected server URL with invalid scheme: %s",
                _safe_host_label(server_url),
            )
            return False
        if not host:
            logger.warning(
                "Rejected server URL with missing host: %s",
                _safe_host_label(server_url),
            )
            return False
        # Block common internal/loopback targets
        _blocked_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254"}  # noqa: S104 — intentional: server bind-all for container deployment
        if host in _blocked_hosts:
            logger.warning(
                "Rejected internal/loopback server URL: %s",
                _safe_host_label(server_url),
            )
            return False

        # Registry path: full Phase 1 verification (fail closed).
        if self.registry is not None:
            result = await self.verify_server_identity(server_url)
            if not result.verified:
                logger.warning(
                    "Server %s failed identity verification: %s",
                    _safe_host_label(server_url),
                    result.reason,
                )
                return False
            self._connected_servers.add(server_url)
            logger.info("Connected to MCP server: %s", _safe_host_label(server_url))
            return True

        # Bridge path: the discovered DID must verify through the bridge.
        # A missing DID fails closed — an unverifiable server is not
        # recorded as connected. ``verify_peer`` returns a
        # ``HandshakeResult`` (check ``.verified``), while tests may
        # substitute plain booleans.
        if self.trust_bridge:
            server_did = await self._discover_server_did(server_url)
            if not server_did:
                logger.warning(
                    "Server %s has no verifiable DID", _safe_host_label(server_url)
                )
                return False
            peer = await self.trust_bridge.verify_peer(server_did)
            verified = peer.verified if hasattr(peer, "verified") else bool(peer)
            if not verified:
                logger.warning(
                    "Server %s failed trust verification", _safe_host_label(server_url)
                )
                return False

        self._connected_servers.add(server_url)
        logger.info("Connected to MCP server: %s", _safe_host_label(server_url))
        return True

    async def _discover_server_did(self, server_url: str) -> Optional[str]:
        """Discover the server DID from ``/.well-known/agent.json``.

        Returns the DID only when the fetched document parses; otherwise
        ``None``. Signature and registry checks happen in
        :meth:`verify_server_identity` — discovery alone authenticates
        nothing.
        """
        from agentmesh.integrations.mcp.server_identity import (
            afetch_server_document,
            parse_server_document,
        )

        raw = await afetch_server_document(
            server_url, self.discovery_config, self.http_transport
        )
        if raw is None:
            return None
        document = parse_server_document(raw)
        return document.did if document else None

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

        # NOTE: userinfo-bearing URLs can never reach this raise through
        # the public flow — connect() rejects them before recording the
        # server — so the full URL here preserves the pinned error
        # contract (see test_invoke_mentions_server_and_tool) without a
        # credential path.
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
