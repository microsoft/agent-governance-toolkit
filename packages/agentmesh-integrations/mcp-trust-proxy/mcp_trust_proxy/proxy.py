"""
MCP Trust Proxy — trust-gated tool access for MCP servers.

Wraps any MCP tool endpoint with AgentMesh trust verification.
Before an agent can call a tool, it must:
1. Present a valid agent DID
2. Meet the trust score threshold (global or per-tool)
3. Have the required capabilities (if tool requires specific ones)
4. Not be blocked or rate-limited

Works without importing MCP SDK — operates on tool names and agent metadata.
Can be used as middleware in front of any MCP server.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolPolicy:
    """Access policy for a specific MCP tool."""

    min_trust: int = 0
    required_capabilities: List[str] = field(default_factory=list)
    blocked: bool = False
    max_calls_per_minute: int = 0  # 0 = unlimited
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "min_trust": self.min_trust,
            "required_capabilities": self.required_capabilities,
            "blocked": self.blocked,
            "max_calls_per_minute": self.max_calls_per_minute,
        }


@dataclass
class AuthResult:
    """Result of an authorization check."""

    allowed: bool
    tool_name: str
    agent_did: str
    reason: str = ""
    trust_score: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "tool": self.tool_name,
            "agent_did": self.agent_did,
            "reason": self.reason,
            "trust_score": self.trust_score,
        }


class TrustProxy:
    """
    MCP trust proxy — intercepts tool calls and verifies agent identity.

    Usage as middleware:
        proxy = TrustProxy(default_min_trust=300)
        proxy.set_tool_policy("shell_exec", ToolPolicy(blocked=True))

        # Before forwarding tool call to MCP server:
        result = proxy.authorize(
            agent_did="did:mesh:agent-1",
            agent_trust_score=600,
            agent_capabilities=["search"],
            tool_name="web_search",
        )
        if not result.allowed:
            return {"error": result.reason}
    """

    def __init__(
        self,
        default_min_trust: int = 100,
        tool_policies: Optional[Dict[str, ToolPolicy]] = None,
        blocked_dids: Optional[List[str]] = None,
        require_did: bool = True,
    ):
        self.default_min_trust = default_min_trust
        self._tool_policies: Dict[str, ToolPolicy] = dict(tool_policies or {})
        self._blocked_dids: set = set(blocked_dids or [])
        self.require_did = require_did
        self._rate_tracker: Dict[str, Dict[str, List[float]]] = {}  # {tool: {did: [timestamps]}}
        self._audit_log: List[AuthResult] = []

    def set_tool_policy(self, tool_name: str, policy: ToolPolicy) -> None:
        """Set or update policy for a specific tool."""
        self._tool_policies[tool_name] = policy

    def block_agent(self, did: str) -> None:
        """Block an agent by DID."""
        self._blocked_dids.add(did)

    def unblock_agent(self, did: str) -> None:
        """Unblock an agent by DID."""
        self._blocked_dids.discard(did)

    def authorize(
        self,
        agent_did: str,
        agent_trust_score: int,
        tool_name: str,
        agent_capabilities: Optional[List[str]] = None,
        tool_args: Optional[Dict[str, Any]] = None,
    ) -> AuthResult:
        """
        Authorize an MCP tool call.

        Checks (in order):
        1. Agent DID is present (if required)
        2. Agent DID is not blocked
        3. Tool is not blocked
        4. Trust score meets threshold
        5. Agent has required capabilities
        6. Rate limit not exceeded
        """
        caps = agent_capabilities or []

        def deny(reason: str) -> AuthResult:
            r = AuthResult(
                allowed=False,
                tool_name=tool_name,
                agent_did=agent_did,
                reason=reason,
                trust_score=agent_trust_score,
            )
            self._audit_log.append(r)
            return r

        # 1. DID required
        if self.require_did and not agent_did:
            return deny("Agent DID is required")

        # 2. Blocked DID
        if agent_did in self._blocked_dids:
            return deny(f"Agent {agent_did} is blocked")

        # Get tool policy
        policy = self._tool_policies.get(tool_name)

        # 3. Tool blocked
        if policy and policy.blocked:
            return deny(f"Tool '{tool_name}' is blocked by policy")

        # 4. Trust score
        min_trust = policy.min_trust if policy and policy.min_trust else self.default_min_trust
        if agent_trust_score < min_trust:
            return deny(
                f"Trust score {agent_trust_score} below minimum {min_trust} for '{tool_name}'"
            )

        # 5. Capabilities
        if policy and policy.required_capabilities:
            missing = [c for c in policy.required_capabilities if c not in caps]
            if missing:
                return deny(f"Missing capabilities for '{tool_name}': {missing}")

        # 6. Rate limit
        if policy and policy.max_calls_per_minute > 0 and agent_did:
            now = time.time()
            tool_rates = self._rate_tracker.setdefault(tool_name, {})
            timestamps = tool_rates.get(agent_did, [])
            timestamps = [t for t in timestamps if t > now - 60]
            if len(timestamps) >= policy.max_calls_per_minute:
                return deny(f"Rate limit exceeded for '{tool_name}' ({policy.max_calls_per_minute}/min)")
            timestamps.append(now)
            tool_rates[agent_did] = timestamps

        # Allowed
        r = AuthResult(
            allowed=True,
            tool_name=tool_name,
            agent_did=agent_did,
            reason="Authorized",
            trust_score=agent_trust_score,
        )
        self._audit_log.append(r)
        return r

    def get_audit_log(self) -> List[AuthResult]:
        return list(self._audit_log)

    def get_tool_policies(self) -> Dict[str, ToolPolicy]:
        return dict(self._tool_policies)

    def get_stats(self) -> Dict[str, Any]:
        total = len(self._audit_log)
        allowed = sum(1 for r in self._audit_log if r.allowed)
        return {
            "total_requests": total,
            "allowed": allowed,
            "denied": total - allowed,
            "configured_tools": len(self._tool_policies),
            "blocked_agents": len(self._blocked_dids),
        }

    def clear_rate_limits(self) -> None:
        self._rate_tracker.clear()
