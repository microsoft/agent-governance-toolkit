# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""ADK PolicyEvaluator backed by Agent Governance Toolkit.

Implements the PolicyEvaluator protocol proposed in google/adk-python#4897,
wiring ADK's before_tool_callback into our deterministic policy engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass
class PolicyDecision:
    """Result of a policy evaluation."""
    verdict: Verdict
    reason: str = ""
    matched_rule: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


class PolicyEvaluatorProtocol(Protocol):
    """The PolicyEvaluator protocol from google/adk-python#4897."""

    async def evaluate_tool_call(
        self, *, tool_name: str, tool_args: dict, agent_name: str, context: Any
    ) -> PolicyDecision: ...

    async def evaluate_agent_delegation(
        self, *, parent_agent: str, child_agent: str, scope: Any, context: Any
    ) -> PolicyDecision: ...


class ADKPolicyEvaluator:
    """PolicyEvaluator backed by Agent Governance Toolkit.

    Loads governance rules from YAML configuration and evaluates
    ADK tool calls and agent delegations against them.

    Example::

        from adk_agentmesh import ADKPolicyEvaluator

        evaluator = ADKPolicyEvaluator.from_config("policies/adk-governance.yaml")

        # Wire into ADK agent
        agent = LlmAgent(
            before_tool_callback=evaluator.before_tool_callback,
            after_tool_callback=evaluator.after_tool_callback,
        )
    """

    def __init__(
        self,
        policy_path: Optional[str | Path] = None,
        blocked_tools: Optional[list[str]] = None,
        allowed_tools: Optional[list[str]] = None,
        max_tool_calls: int = 100,
        require_approval_for: Optional[list[str]] = None,
    ):
        self._policy_path = policy_path
        self._blocked_tools = set(blocked_tools or [])
        self._allowed_tools = set(allowed_tools or [])
        self._max_tool_calls = max_tool_calls
        self._require_approval = set(require_approval_for or [])
        self._call_count: dict[str, int] = {}
        self._audit_log: list[dict] = []

        if policy_path:
            self._load_policy(policy_path)

    def _load_policy(self, path: str | Path) -> None:
        """Load governance policy from YAML config."""
        import yaml
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy config not found: {path}")
        with open(path, encoding="utf-8") as f:
            config = yaml.safe_load(f)

        adk = config.get("adk_governance", {})
        self._blocked_tools.update(adk.get("blocked_tools", []))
        self._allowed_tools.update(adk.get("allowed_tools", []))
        self._max_tool_calls = adk.get("max_tool_calls", self._max_tool_calls)
        self._require_approval.update(adk.get("require_approval_for", []))

    @classmethod
    def from_config(cls, config_path: str | Path) -> "ADKPolicyEvaluator":
        """Create an evaluator from a YAML config file."""
        return cls(policy_path=config_path)

    async def evaluate_tool_call(
        self, *, tool_name: str, tool_args: dict, agent_name: str, context: Any = None
    ) -> PolicyDecision:
        """Evaluate whether a tool call should be allowed."""
        # Track call count per agent
        self._call_count.setdefault(agent_name, 0)
        self._call_count[agent_name] += 1

        # Check rate limit
        if self._call_count[agent_name] > self._max_tool_calls:
            return self._deny(
                f"Agent '{agent_name}' exceeded max tool calls ({self._max_tool_calls})",
                rule="rate_limit",
                tool_name=tool_name,
                agent_name=agent_name,
            )

        # Check blocked tools
        if tool_name in self._blocked_tools:
            return self._deny(
                f"Tool '{tool_name}' is blocked by policy",
                rule="blocked_tool",
                tool_name=tool_name,
                agent_name=agent_name,
            )

        # Check allowed tools (if allowlist is set, only those are permitted)
        if self._allowed_tools and tool_name not in self._allowed_tools:
            return self._deny(
                f"Tool '{tool_name}' is not in the allowed tools list",
                rule="allowed_tools",
                tool_name=tool_name,
                agent_name=agent_name,
            )

        # Check approval requirement
        if tool_name in self._require_approval:
            return PolicyDecision(
                verdict=Verdict.ESCALATE,
                reason=f"Tool '{tool_name}' requires human approval",
                matched_rule="require_approval",
                metadata={"tool_name": tool_name, "agent_name": agent_name},
            )

        self._log_audit("tool_call_allowed", tool_name=tool_name, agent_name=agent_name)
        return PolicyDecision(verdict=Verdict.ALLOW)

    async def evaluate_agent_delegation(
        self, *, parent_agent: str, child_agent: str, scope: Any = None, context: Any = None
    ) -> PolicyDecision:
        """Evaluate whether agent delegation should be allowed."""
        self._log_audit(
            "delegation_evaluated",
            parent=parent_agent,
            child=child_agent,
            scope=str(scope),
        )
        return PolicyDecision(verdict=Verdict.ALLOW)

    def before_tool_callback(self, tool_name: str, tool_args: dict, **kwargs) -> Optional[dict]:
        """ADK before_tool_callback hook.

        Returns None to allow, or a dict with error to block.
        """
        import asyncio
        decision = asyncio.get_event_loop().run_until_complete(
            self.evaluate_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                agent_name=kwargs.get("agent_name", "unknown"),
            )
        )
        if decision.verdict == Verdict.DENY:
            logger.warning("BLOCKED: %s — %s", tool_name, decision.reason)
            return {"error": f"Governance policy violation: {decision.reason}"}
        if decision.verdict == Verdict.ESCALATE:
            logger.info("ESCALATE: %s — %s", tool_name, decision.reason)
            return {"error": f"Requires approval: {decision.reason}"}
        return None

    def after_tool_callback(self, tool_name: str, result: Any, **kwargs) -> None:
        """ADK after_tool_callback hook for audit logging."""
        self._log_audit(
            "tool_call_completed",
            tool_name=tool_name,
            agent_name=kwargs.get("agent_name", "unknown"),
        )

    def get_audit_log(self) -> list[dict]:
        """Return the audit trail."""
        return list(self._audit_log)

    def reset_counters(self) -> None:
        """Reset per-agent call counters."""
        self._call_count.clear()

    def _deny(self, reason: str, rule: str, **meta) -> PolicyDecision:
        self._log_audit("tool_call_denied", reason=reason, rule=rule, **meta)
        return PolicyDecision(verdict=Verdict.DENY, reason=reason, matched_rule=rule, metadata=meta)

    def _log_audit(self, event_type: str, **details) -> None:
        self._audit_log.append({
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **details,
        })
