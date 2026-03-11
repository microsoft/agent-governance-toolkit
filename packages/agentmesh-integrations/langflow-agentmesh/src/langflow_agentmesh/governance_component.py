"""Langflow custom component for governance policy enforcement.

Provides a visual node that checks agent actions against YAML-based
policy rules: tool allowlist/blocklist, argument scanning, and content
pattern matching. Actions are either passed through or blocked with
violation details.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from langflow_agentmesh.policy import (
    GovernanceEventType,
    GovernancePolicy,
    PatternType,
    PolicyCheckResult,
)


@dataclass
class GovernanceResult:
    """Output from the governance component."""

    allowed: bool
    action: str
    agent_id: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    violation_reason: Optional[str] = None
    violation_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        d: Dict[str, Any] = {
            "allowed": self.allowed,
            "action": self.action,
            "agent_id": self.agent_id,
            "parameters": self.parameters,
        }
        if not self.allowed:
            d["violation_reason"] = self.violation_reason
            d["violation_metadata"] = self.violation_metadata
        return d


class GovernanceComponent:
    """Langflow component for policy enforcement.

    Can be used as a standalone governance gate or integrated into
    a Langflow flow as a custom component. Configurable via constructor
    parameters that map to Langflow UI fields.

    Parameters
    ----------
    allowed_tools : list of str
        Tools explicitly allowed (empty = all allowed).
    blocked_tools : list of str
        Tools explicitly blocked.
    blocked_patterns : list of tuple(str, str)
        Content patterns to block. Each tuple is (pattern, type)
        where type is 'substring', 'regex', or 'glob'.
    max_calls : int
        Maximum tool calls per session.
    policy_yaml : str
        YAML policy string (overrides individual fields if provided).
    """

    display_name = "Governance Gate"
    description = "Enforces governance policies on agent actions"
    icon = "shield"

    def __init__(
        self,
        allowed_tools: Optional[List[str]] = None,
        blocked_tools: Optional[List[str]] = None,
        blocked_patterns: Optional[List[tuple]] = None,
        max_calls: int = 10,
        policy_yaml: Optional[str] = None,
    ) -> None:
        if policy_yaml:
            self.policy = GovernancePolicy.from_yaml(policy_yaml)
        else:
            parsed_patterns = []
            for p in (blocked_patterns or []):
                if isinstance(p, (list, tuple)) and len(p) == 2:
                    parsed_patterns.append((p[0], PatternType(p[1])))
                elif isinstance(p, str):
                    parsed_patterns.append((p, PatternType.SUBSTRING))

            self.policy = GovernancePolicy(
                allowed_tools=allowed_tools or [],
                blocked_tools=blocked_tools or [],
                blocked_patterns=parsed_patterns,
                max_tool_calls_per_request=max_calls,
            )
        self._call_count = 0

    def process(
        self,
        action: str,
        parameters: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
    ) -> GovernanceResult:
        """Evaluate an action against governance policy.

        Returns GovernanceResult with allowed=True (pass-through) or
        allowed=False (blocked with violation details).
        """
        params = parameters or {}
        self._call_count += 1

        # Check call count limit
        count_result = self.policy.check_call_count(self._call_count)
        if not count_result.allowed:
            return GovernanceResult(
                allowed=False,
                action=action,
                agent_id=agent_id,
                parameters=params,
                violation_reason=count_result.reason,
                violation_metadata=count_result.metadata,
            )

        # Run full policy enforcement
        result = self.policy.enforce(action, params, agent_id=agent_id)

        return GovernanceResult(
            allowed=result.allowed,
            action=action,
            agent_id=agent_id,
            parameters=params,
            violation_reason=result.reason if not result.allowed else None,
            violation_metadata=result.metadata if not result.allowed else {},
        )

    def reset(self) -> None:
        """Reset call counter for a new session."""
        self._call_count = 0

    @property
    def call_count(self) -> int:
        """Current call count."""
        return self._call_count
