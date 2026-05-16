# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governance callbacks for ADK agent lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class DelegationScope:
    """Defines the scope of permissions delegated to a sub-agent.

    Enforces monotonic narrowing — child scope cannot exceed parent scope.
    """
    allowed_tools: list[str] = field(default_factory=list)
    max_tool_calls: int = 50
    max_depth: int = 3
    read_only: bool = False
    trust_ceiling: Optional[int] = None

    def narrow(self, **overrides) -> "DelegationScope":
        """Create a narrower scope for sub-delegation.

        If trust_ceiling is provided in overrides, it is clamped to not
        exceed the parent's ceiling (monotonic narrowing).
        """
        # Compute child ceiling: take the minimum of parent and requested
        requested_ceiling = overrides.get("trust_ceiling", self.trust_ceiling)
        if self.trust_ceiling is not None and requested_ceiling is not None:
            child_ceiling = min(requested_ceiling, self.trust_ceiling)
        elif self.trust_ceiling is not None:
            child_ceiling = self.trust_ceiling
        else:
            child_ceiling = requested_ceiling

        child = DelegationScope(
            allowed_tools=overrides.get("allowed_tools", self.allowed_tools[:]),
            max_tool_calls=min(
                overrides.get("max_tool_calls", self.max_tool_calls),
                self.max_tool_calls,
            ),
            max_depth=min(
                overrides.get("max_depth", self.max_depth - 1),
                self.max_depth - 1,
            ),
            read_only=self.read_only or overrides.get("read_only", False),
            trust_ceiling=child_ceiling,
        )
        # Monotonic narrowing: child tools must be subset of parent
        if self.allowed_tools:
            child.allowed_tools = [
                t for t in child.allowed_tools if t in self.allowed_tools
            ]
        return child


class GovernanceCallbacks:
    """Wires governance checks into ADK agent lifecycle.

    Example::

        from adk_agentmesh import ADKPolicyEvaluator, GovernanceCallbacks

        evaluator = ADKPolicyEvaluator.from_config("policies/adk-governance.yaml")
        callbacks = GovernanceCallbacks(evaluator)

        agent = LlmAgent(
            before_tool_callback=callbacks.before_tool,
            after_tool_callback=callbacks.after_tool,
            before_agent_callback=callbacks.before_agent,
            after_agent_callback=callbacks.after_agent,
        )
    """

    def __init__(self, evaluator: Any, delegation_scope: Optional[DelegationScope] = None):
        self.evaluator = evaluator
        self.scope = delegation_scope or DelegationScope()

    def before_tool(self, tool_name: str, tool_args: dict, **kwargs) -> Optional[dict]:
        """Pre-tool governance check."""
        if self.scope.read_only and tool_name.startswith(("write_", "delete_", "update_")):
            return {"error": f"Read-only scope: '{tool_name}' is blocked"}
        if self.scope.allowed_tools and tool_name not in self.scope.allowed_tools:
            return {"error": f"Tool '{tool_name}' not in delegation scope"}
        return self.evaluator.before_tool_callback(tool_name, tool_args, **kwargs)

    def after_tool(self, tool_name: str, result: Any, **kwargs) -> None:
        """Post-tool audit logging."""
        self.evaluator.after_tool_callback(tool_name, result, **kwargs)

    def before_agent(self, agent_name: str, **kwargs) -> Optional[dict]:
        """Pre-delegation governance check."""
        if self.scope.max_depth <= 0:
            return {"error": f"Maximum delegation depth reached for '{agent_name}'"}
        return None

    def after_agent(self, agent_name: str, result: Any, **kwargs) -> None:
        """Post-delegation audit."""
        self.evaluator._log_audit("agent_completed", agent_name=agent_name)
