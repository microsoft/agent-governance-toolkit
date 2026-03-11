"""PolicyCheckpoint: Governance policy enforcement node for LangGraph."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from langgraph_trust.state import TrustState, TrustVerdict


@dataclass
class GovernancePolicy:
    """Declarative governance policy for graph execution.

    Policies define constraints that must be satisfied at a checkpoint
    before the graph continues. They can be constructed programmatically
    or loaded from a dict/YAML-like structure.
    """

    name: str = "default"
    max_tokens: int | None = None
    max_tool_calls: int | None = None
    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)
    require_human_approval: bool = False
    allowed_models: list[str] = field(default_factory=list)
    custom_rules: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GovernancePolicy:
        return cls(
            name=data.get("name", "default"),
            max_tokens=data.get("max_tokens"),
            max_tool_calls=data.get("max_tool_calls"),
            allowed_tools=data.get("allowed_tools", []),
            blocked_tools=data.get("blocked_tools", []),
            blocked_patterns=data.get("blocked_patterns", []),
            require_human_approval=data.get("require_human_approval", False),
            allowed_models=data.get("allowed_models", []),
            custom_rules=data.get("custom_rules", {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "max_tokens": self.max_tokens,
            "max_tool_calls": self.max_tool_calls,
            "allowed_tools": self.allowed_tools,
            "blocked_tools": self.blocked_tools,
            "blocked_patterns": self.blocked_patterns,
            "require_human_approval": self.require_human_approval,
            "allowed_models": self.allowed_models,
            "custom_rules": self.custom_rules,
        }


class PolicyCheckpoint:
    """A LangGraph node that validates governance policies at graph transitions.

    Checks the current graph state against a :class:`GovernancePolicy` and
    writes a :class:`TrustState` verdict into ``state["trust_result"]``.

    Example::

        policy = GovernancePolicy(
            name="prod-safety",
            max_tool_calls=5,
            blocked_tools=["shell_exec", "file_delete"],
            blocked_patterns=["password", "secret"],
        )
        checkpoint = PolicyCheckpoint(policy=policy)
        graph.add_node("policy_check", checkpoint)
    """

    def __init__(
        self,
        policy: GovernancePolicy,
        content_key: str = "messages",
        tool_calls_key: str = "tool_calls",
        tokens_key: str = "total_tokens",
    ) -> None:
        self.policy = policy
        self.content_key = content_key
        self.tool_calls_key = tool_calls_key
        self.tokens_key = tokens_key

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        violations: list[str] = []

        # Token limit
        if self.policy.max_tokens is not None:
            tokens = state.get(self.tokens_key, 0)
            if isinstance(tokens, (int, float)) and tokens > self.policy.max_tokens:
                violations.append(
                    "Token limit exceeded: %d > %d" % (tokens, self.policy.max_tokens)
                )

        # Tool call limit
        if self.policy.max_tool_calls is not None:
            calls = state.get(self.tool_calls_key)
            if isinstance(calls, list) and len(calls) > self.policy.max_tool_calls:
                violations.append(
                    "Tool call limit exceeded: %d > %d"
                    % (len(calls), self.policy.max_tool_calls)
                )

        # Blocked tools
        if self.policy.blocked_tools:
            calls = state.get(self.tool_calls_key)
            if isinstance(calls, list):
                for call in calls:
                    tool_name = call if isinstance(call, str) else call.get("name", "")
                    if tool_name in self.policy.blocked_tools:
                        violations.append("Blocked tool used: %s" % tool_name)

        # Allowed tools (allowlist mode)
        if self.policy.allowed_tools:
            calls = state.get(self.tool_calls_key)
            if isinstance(calls, list):
                for call in calls:
                    tool_name = call if isinstance(call, str) else call.get("name", "")
                    if tool_name and tool_name not in self.policy.allowed_tools:
                        violations.append("Unauthorized tool: %s" % tool_name)

        # Blocked content patterns
        if self.policy.blocked_patterns:
            content = self._extract_content(state)
            for pattern in self.policy.blocked_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    violations.append("Blocked pattern detected: %s" % pattern)

        # Human approval required
        if self.policy.require_human_approval:
            approved = state.get("human_approved", False)
            if not approved:
                violations.append("Human approval required but not granted")

        if violations:
            ts = TrustState(
                verdict=TrustVerdict.FAIL,
                score=0.0,
                threshold=0.0,
                reason="Policy violations: %s" % "; ".join(violations),
                policy_violations=violations,
            )
        else:
            ts = TrustState(
                verdict=TrustVerdict.PASS,
                score=1.0,
                threshold=0.0,
                reason="Policy '%s' satisfied" % self.policy.name,
            )

        return {"trust_result": ts.to_dict()}

    def _extract_content(self, state: dict[str, Any]) -> str:
        """Extract searchable text content from state."""
        raw = state.get(self.content_key, [])
        if isinstance(raw, str):
            return raw
        if isinstance(raw, list):
            parts = []
            for item in raw:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(str(item.get("content", "")))
                else:
                    parts.append(str(item))
            return " ".join(parts)
        return str(raw)
