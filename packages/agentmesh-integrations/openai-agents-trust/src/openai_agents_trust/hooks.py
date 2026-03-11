"""Lifecycle hooks for governance tracking in OpenAI Agents SDK."""

from __future__ import annotations

import time
from typing import Any, Optional

from agents import Agent
from agents.items import ModelResponse, TResponseInputItem
from agents.lifecycle import RunHooksBase
from agents.run_context import AgentHookContext, RunContextWrapper
from agents.tool import Tool

from .audit import AuditLog
from .policy import GovernancePolicy
from .trust import TrustScorer


class GovernanceHooks(RunHooksBase[Any, Agent]):
    """Run-level hooks that enforce governance across all agents in a run.

    Tracks tool calls against rate limits, logs policy decisions, and records
    hash chain audit entries for every lifecycle event.
    """

    def __init__(
        self,
        policy: GovernancePolicy,
        scorer: Optional[TrustScorer] = None,
        audit_log: Optional[AuditLog] = None,
    ):
        self.policy = policy
        self.scorer = scorer or TrustScorer()
        self.audit_log = audit_log or AuditLog()
        self._tool_call_counts: dict[str, int] = {}
        self._agent_start_times: dict[str, float] = {}

    async def on_agent_start(
        self, context: AgentHookContext[Any], agent: Agent[Any]
    ) -> None:
        self._agent_start_times[agent.name] = time.time()
        self.audit_log.record(
            agent_id=agent.name,
            action="agent_start",
            decision="allow",
        )

    async def on_agent_end(
        self, context: AgentHookContext[Any], agent: Agent[Any], output: Any
    ) -> None:
        duration = time.time() - self._agent_start_times.get(agent.name, time.time())
        self.scorer.record_success(agent.name)
        self.audit_log.record(
            agent_id=agent.name,
            action="agent_end",
            decision="allow",
            details={"duration_ms": round(duration * 1000, 2)},
        )

    async def on_tool_start(
        self, context: RunContextWrapper[Any], agent: Agent[Any], tool: Tool
    ) -> None:
        agent_id = agent.name
        count = self._tool_call_counts.get(agent_id, 0) + 1
        self._tool_call_counts[agent_id] = count

        # Check tool allowlist
        violation = self.policy.check_tool(tool.name)
        if violation:
            self.scorer.record_failure(agent_id, "security", penalty=0.15)
            self.audit_log.record(
                agent_id=agent_id,
                action=f"tool_start:{tool.name}",
                decision="warn",
                details={"reason": violation, "call_count": count},
            )
            return

        # Check rate limit
        if count > self.policy.max_tool_calls:
            self.scorer.record_failure(agent_id, "compliance", penalty=0.1)
            self.audit_log.record(
                agent_id=agent_id,
                action=f"tool_start:{tool.name}",
                decision="warn",
                details={
                    "reason": f"Tool call limit exceeded ({count}/{self.policy.max_tool_calls})",
                    "call_count": count,
                },
            )
            return

        self.audit_log.record(
            agent_id=agent_id,
            action=f"tool_start:{tool.name}",
            decision="allow",
            details={"call_count": count},
        )

    async def on_tool_end(
        self, context: RunContextWrapper[Any], agent: Agent[Any], tool: Tool, result: str
    ) -> None:
        # Check tool output against blocked patterns
        violation = self.policy.check_content(result)
        if violation:
            self.scorer.record_failure(agent.name, "security", penalty=0.1)
            self.audit_log.record(
                agent_id=agent.name,
                action=f"tool_end:{tool.name}",
                decision="warn",
                details={"reason": violation},
            )
        else:
            self.audit_log.record(
                agent_id=agent.name,
                action=f"tool_end:{tool.name}",
                decision="allow",
            )

    async def on_handoff(
        self, context: RunContextWrapper[Any], from_agent: Agent[Any], to_agent: Agent[Any]
    ) -> None:
        from_score = self.scorer.get_score(from_agent.name)
        to_score = self.scorer.get_score(to_agent.name)
        self.audit_log.record(
            agent_id=from_agent.name,
            action=f"handoff_to:{to_agent.name}",
            decision="allow",
            details={
                "from_trust": from_score.overall,
                "to_trust": to_score.overall,
            },
        )

    def get_tool_call_count(self, agent_id: str) -> int:
        """Get the total tool calls made by an agent."""
        return self._tool_call_counts.get(agent_id, 0)

    def get_summary(self) -> dict:
        """Get a summary of governance activity during this run."""
        entries = self.audit_log.get_entries()
        return {
            "total_events": len(entries),
            "tool_calls": dict(self._tool_call_counts),
            "denials": len([e for e in entries if e.decision == "deny"]),
            "warnings": len([e for e in entries if e.decision == "warn"]),
            "chain_valid": self.audit_log.verify_chain(),
        }

