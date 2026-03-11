"""
Trust layer for OpenAI Agents SDK — function call gating and handoff verification.

In OpenAI Agents SDK, agents call functions and hand off to other agents.
This module adds AgentMesh trust verification to both flows:

1. **TrustedFunctionGuard**: Before an agent calls a function, verify the
   agent's trust score meets the function's threshold.

2. **HandoffVerifier**: Before Agent A hands off to Agent B, verify both
   agents' trust scores and ensure the handoff is within delegation bounds.

3. **AgentTrustContext**: Carries trust metadata through the conversation,
   enabling "On-Behalf-Of" flows (Agent B knows it's working for User X
   via Agent A).

No OpenAI SDK dependency — works with any agent framework via duck typing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FunctionCallResult:
    """Result of a function call trust check."""

    allowed: bool
    function_name: str
    agent_did: str
    reason: str = ""
    trust_score: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "function": self.function_name,
            "agent_did": self.agent_did,
            "reason": self.reason,
            "trust_score": self.trust_score,
        }


@dataclass
class HandoffResult:
    """Result of a handoff trust verification."""

    allowed: bool
    source_did: str
    target_did: str
    reason: str = ""
    source_trust: int = 0
    target_trust: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "source_did": self.source_did,
            "target_did": self.target_did,
            "reason": self.reason,
            "source_trust": self.source_trust,
            "target_trust": self.target_trust,
        }


@dataclass
class AgentTrustContext:
    """
    Trust context propagated through agent conversations.

    Enables "On-Behalf-Of" flows: when Agent A delegates to Agent B,
    the context carries the original user identity and the scope chain.
    """

    user_id: str = ""
    originating_did: str = ""
    scope_chain: List[str] = field(default_factory=list)
    max_delegation_depth: int = 5
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_delegation(self, agent_did: str) -> bool:
        """
        Add an agent to the scope chain.

        Returns False if max depth would be exceeded.
        """
        if len(self.scope_chain) >= self.max_delegation_depth:
            return False
        self.scope_chain.append(agent_did)
        return True

    @property
    def delegation_depth(self) -> int:
        return len(self.scope_chain)

    @property
    def current_agent(self) -> str:
        if self.scope_chain:
            return self.scope_chain[-1]
        return self.originating_did

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "originating_did": self.originating_did,
            "scope_chain": self.scope_chain,
            "delegation_depth": self.delegation_depth,
        }


class TrustedFunctionGuard:
    """
    Trust-gated function calling for OpenAI Agents SDK.

    Checks agent trust score before allowing function calls.
    Supports per-function trust thresholds for sensitive operations.
    """

    def __init__(
        self,
        min_trust_score: int = 100,
        sensitive_functions: Optional[Dict[str, int]] = None,
        blocked_functions: Optional[List[str]] = None,
    ):
        self.min_trust_score = min_trust_score
        self._sensitive: Dict[str, int] = dict(sensitive_functions or {})
        self._blocked: set = set(blocked_functions or [])
        self._log: List[FunctionCallResult] = []

    def check_call(
        self,
        agent_did: str,
        agent_trust_score: int,
        function_name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> FunctionCallResult:
        """
        Check if an agent is trusted enough to call a function.

        Order of checks:
        1. Function not blocked
        2. Trust score meets function-specific threshold (or default)
        """
        def deny(reason: str) -> FunctionCallResult:
            r = FunctionCallResult(
                allowed=False,
                function_name=function_name,
                agent_did=agent_did,
                reason=reason,
                trust_score=agent_trust_score,
            )
            self._log.append(r)
            return r

        # 1. Blocked
        if function_name in self._blocked:
            return deny(f"Function '{function_name}' is blocked")

        # 2. Trust threshold
        threshold = self._sensitive.get(function_name, self.min_trust_score)
        if agent_trust_score < threshold:
            return deny(
                f"Trust score {agent_trust_score} below {threshold} for '{function_name}'"
            )

        r = FunctionCallResult(
            allowed=True,
            function_name=function_name,
            agent_did=agent_did,
            reason="Trusted",
            trust_score=agent_trust_score,
        )
        self._log.append(r)
        return r

    def set_threshold(self, function_name: str, min_trust: int) -> None:
        """Set trust threshold for a specific function."""
        self._sensitive[function_name] = min_trust

    def block_function(self, function_name: str) -> None:
        self._blocked.add(function_name)

    def unblock_function(self, function_name: str) -> None:
        self._blocked.discard(function_name)

    def get_log(self) -> List[FunctionCallResult]:
        return list(self._log)

    def get_stats(self) -> Dict[str, Any]:
        total = len(self._log)
        allowed = sum(1 for r in self._log if r.allowed)
        return {
            "total_checks": total,
            "allowed": allowed,
            "denied": total - allowed,
            "sensitive_functions": len(self._sensitive),
            "blocked_functions": len(self._blocked),
        }


class HandoffVerifier:
    """
    Trust verification for agent-to-agent handoffs.

    In OpenAI Agents SDK, agents can hand off tasks to other agents.
    HandoffVerifier ensures:
    - Both source and target agents meet trust thresholds
    - Delegation depth is within bounds
    - Trust context is properly propagated
    """

    def __init__(
        self,
        min_trust_score: int = 300,
        max_delegation_depth: int = 5,
        require_mutual_trust: bool = False,
    ):
        self.min_trust_score = min_trust_score
        self.max_delegation_depth = max_delegation_depth
        self.require_mutual_trust = require_mutual_trust
        self._log: List[HandoffResult] = []

    def verify_handoff(
        self,
        source_did: str,
        source_trust: int,
        target_did: str,
        target_trust: int,
        context: Optional[AgentTrustContext] = None,
    ) -> HandoffResult:
        """
        Verify a handoff from source agent to target agent.

        Checks:
        1. Source agent meets trust threshold
        2. Target agent meets trust threshold
        3. Delegation depth within bounds (if context provided)
        4. Source != Target (no self-delegation)
        """
        def deny(reason: str) -> HandoffResult:
            r = HandoffResult(
                allowed=False,
                source_did=source_did,
                target_did=target_did,
                reason=reason,
                source_trust=source_trust,
                target_trust=target_trust,
            )
            self._log.append(r)
            return r

        # Self-delegation
        if source_did == target_did:
            return deny("Cannot hand off to self")

        # Source trust
        if source_trust < self.min_trust_score:
            return deny(f"Source trust {source_trust} below minimum {self.min_trust_score}")

        # Target trust
        if target_trust < self.min_trust_score:
            return deny(f"Target trust {target_trust} below minimum {self.min_trust_score}")

        # Mutual trust (if required)
        if self.require_mutual_trust:
            if source_trust < self.min_trust_score or target_trust < self.min_trust_score:
                return deny("Mutual trust requirement not met")

        # Delegation depth
        if context:
            if context.delegation_depth >= self.max_delegation_depth:
                return deny(
                    f"Delegation depth {context.delegation_depth} exceeds max {self.max_delegation_depth}"
                )
            context.add_delegation(target_did)

        r = HandoffResult(
            allowed=True,
            source_did=source_did,
            target_did=target_did,
            reason="Handoff verified",
            source_trust=source_trust,
            target_trust=target_trust,
        )
        self._log.append(r)
        return r

    def get_log(self) -> List[HandoffResult]:
        return list(self._log)

    def get_stats(self) -> Dict[str, Any]:
        total = len(self._log)
        allowed = sum(1 for r in self._log if r.allowed)
        return {
            "total_handoffs": total,
            "allowed": allowed,
            "denied": total - allowed,
        }
