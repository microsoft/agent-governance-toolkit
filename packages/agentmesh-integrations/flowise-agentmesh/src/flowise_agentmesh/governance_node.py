"""Governance policy check node for Flowise flows."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from flowise_agentmesh.policy import Policy, load_policy


@dataclass
class GovernanceResult:
    """Result of a governance policy check."""

    allowed: bool
    reason: str | None = None
    tool: str | None = None
    input_data: dict[str, Any] = field(default_factory=dict)


class GovernanceNode:
    """Evaluates agent actions against a YAML governance policy.

    Checks tool allowlist/blocklist, content patterns, and argument scanning.
    Outputs pass (to next node) or block (with reason).
    """

    def __init__(
        self,
        policy: Policy | str | dict | None = None,
        policy_path: str | None = None,
        strict_mode: bool = True,
        log_level: str = "INFO",
    ) -> None:
        self.strict_mode = strict_mode
        self.logger = logging.getLogger("flowise_agentmesh.governance")
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

        if policy_path:
            self.policy = load_policy(policy_path)
        elif isinstance(policy, Policy):
            self.policy = policy
        elif policy is not None:
            self.policy = load_policy(policy)
        else:
            # Default deny-all policy
            self.policy = Policy()

    def evaluate(
        self,
        tool_name: str | None = None,
        content: str | None = None,
        arguments: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> GovernanceResult:
        """Evaluate an action against governance policy."""
        input_data = {"tool": tool_name, "content": content, "arguments": arguments, **kwargs}

        # Tool check
        if tool_name is not None:
            if not self.policy.is_tool_allowed(tool_name):
                reason = f"Tool '{tool_name}' is not allowed by policy"
                self.logger.warning(reason)
                return GovernanceResult(allowed=False, reason=reason, tool=tool_name, input_data=input_data)

        # Content check
        if content is not None:
            allowed, reason = self.policy.check_content(content)
            if not allowed:
                self.logger.warning(reason)
                return GovernanceResult(allowed=False, reason=reason, tool=tool_name, input_data=input_data)

        # Argument scanning
        if arguments is not None:
            allowed, reason = self.policy.check_arguments(arguments)
            if not allowed:
                self.logger.warning(reason)
                return GovernanceResult(allowed=False, reason=reason, tool=tool_name, input_data=input_data)

        # In strict mode, at least one check must have been performed
        if self.strict_mode and tool_name is None and content is None and arguments is None:
            reason = "Strict mode: no tool, content, or arguments provided for evaluation"
            self.logger.warning(reason)
            return GovernanceResult(allowed=False, reason=reason, input_data=input_data)

        self.logger.info("Action allowed: tool=%s", tool_name)
        return GovernanceResult(allowed=True, tool=tool_name, input_data=input_data)

    def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Flowise-compatible run method. Accepts and returns dicts."""
        result = self.evaluate(
            tool_name=input_data.get("tool"),
            content=input_data.get("content"),
            arguments=input_data.get("arguments"),
        )
        return {
            "allowed": result.allowed,
            "reason": result.reason,
            "tool": result.tool,
            "output": input_data if result.allowed else None,
        }
