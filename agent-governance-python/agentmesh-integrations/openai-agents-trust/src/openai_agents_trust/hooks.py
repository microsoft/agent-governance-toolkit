# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenAI Agents lifecycle hooks backed by the native ACS runtime."""

from __future__ import annotations

import time
from typing import Any, Optional

from agents import Agent
from agents.lifecycle import RunHooksBase
from agents.run_context import AgentHookContext, RunContextWrapper
from agents.tool import Tool
from agt.policies.session import AdapterRuntimeSession

from .audit import AuditLog
from .trust import TrustScorer


class GovernanceHooks(RunHooksBase[Any, Agent]):
    """Run-level hooks that combine native enforcement, audit, and trust."""

    def __init__(
        self,
        runtime: Any,
        scorer: Optional[TrustScorer] = None,
        audit_log: Optional[AuditLog] = None,
    ) -> None:
        self.runtime = runtime
        self.scorer = scorer or TrustScorer()
        self.audit_log = audit_log or AuditLog()
        self._sessions: dict[str, AdapterRuntimeSession] = {}
        self._tool_call_counts: dict[str, int] = {}
        self._agent_start_times: dict[str, float] = {}

    def _session(self, agent_id: str) -> AdapterRuntimeSession:
        session = self._sessions.get(agent_id)
        if session is None:
            session = AdapterRuntimeSession(
                self.runtime,
                agent_id=agent_id,
                session_id=f"openai-agents-{agent_id}",
            )
            self._sessions[agent_id] = session
        return session

    @staticmethod
    def _require_allowed(evaluation: Any) -> None:
        if not evaluation.is_allowed():
            raise PermissionError(
                evaluation.message or evaluation.reason_code or evaluation.verdict
            )

    async def on_agent_start(
        self, context: AgentHookContext[Any], agent: Agent[Any]
    ) -> None:
        self._agent_start_times[agent.name] = time.time()
        evaluation = self._session(agent.name).evaluate_agent_startup()
        self._require_allowed(evaluation)
        self.audit_log.record(
            agent_id=agent.name,
            action="agent_start",
            decision=evaluation.verdict,
            details=evaluation.audit_record(),
        )

    async def on_agent_end(
        self, context: AgentHookContext[Any], agent: Agent[Any], output: Any
    ) -> None:
        evaluation = self._session(agent.name).evaluate_output(content=str(output or ""))
        self._require_allowed(evaluation)
        duration = time.time() - self._agent_start_times.get(agent.name, time.time())
        self.scorer.record_success(agent.name)
        self.audit_log.record(
            agent_id=agent.name,
            action="agent_end",
            decision=evaluation.verdict,
            details={"duration_ms": round(duration * 1000, 2), **evaluation.audit_record()},
        )

    async def on_tool_start(
        self, context: RunContextWrapper[Any], agent: Agent[Any], tool: Tool
    ) -> None:
        count = self._tool_call_counts.get(agent.name, 0) + 1
        evaluation = self._session(agent.name).evaluate_pre_tool_call(
            tool_name=tool.name,
            args={},
            call_id=f"tool-{count}",
        )
        if not evaluation.is_allowed():
            self.scorer.record_failure(agent.name, "security", penalty=0.15)
        self.audit_log.record(
            agent_id=agent.name,
            action=f"tool_start:{tool.name}",
            decision=evaluation.verdict,
            details={"call_count": count, **evaluation.audit_record()},
        )
        self._require_allowed(evaluation)
        self._tool_call_counts[agent.name] = count

    async def on_tool_end(
        self, context: RunContextWrapper[Any], agent: Agent[Any], tool: Tool, result: str
    ) -> None:
        evaluation = self._session(agent.name).evaluate_post_tool_call(
            tool_name=tool.name,
            args={},
            result=result,
            call_id=f"tool-{self._tool_call_counts.get(agent.name, 0)}",
        )
        if not evaluation.is_allowed():
            self.scorer.record_failure(agent.name, "security", penalty=0.1)
        self.audit_log.record(
            agent_id=agent.name,
            action=f"tool_end:{tool.name}",
            decision=evaluation.verdict,
            details=evaluation.audit_record(),
        )
        self._require_allowed(evaluation)

    async def on_handoff(
        self, context: RunContextWrapper[Any], from_agent: Agent[Any], to_agent: Agent[Any]
    ) -> None:
        self.audit_log.record(
            agent_id=from_agent.name,
            action=f"handoff_to:{to_agent.name}",
            decision="allow",
            details={
                "from_trust": self.scorer.get_score(from_agent.name).overall,
                "to_trust": self.scorer.get_score(to_agent.name).overall,
            },
        )

    def get_tool_call_count(self, agent_id: str) -> int:
        return self._tool_call_counts.get(agent_id, 0)

    def get_summary(self) -> dict[str, Any]:
        entries = self.audit_log.get_entries()
        return {
            "total_events": len(entries),
            "tool_calls": dict(self._tool_call_counts),
            "denials": len([e for e in entries if e.decision == "deny"]),
            "warnings": len([e for e in entries if e.decision == "warn"]),
            "chain_valid": self.audit_log.verify_chain(),
        }
