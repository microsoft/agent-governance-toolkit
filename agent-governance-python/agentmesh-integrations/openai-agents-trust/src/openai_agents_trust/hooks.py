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
from agent_control_specification import Decision, HostSession

from .audit import AuditLog, audit_record as _audit_record
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
        self._sessions: dict[str, HostSession] = {}
        self._tool_call_counts: dict[str, int] = {}
        self._agent_start_times: dict[str, float] = {}

    def _session(self, agent_id: str) -> HostSession:
        session = self._sessions.get(agent_id)
        if session is None:
            session = HostSession(
                self.runtime,
                agent_id=agent_id,
                session_id=f"openai-agents-{agent_id}",
            )
            self._sessions[agent_id] = session
        return session

    @staticmethod
    def _require_allowed(evaluation: Any) -> None:
        """Stop the run unless the verdict permits it unchanged.

        ``transform`` is a permitting decision, but these are lifecycle hooks:
        they observe the run and cannot rewrite the payload the agent is about
        to use. Letting a transform through would run the original, unredacted
        content while the policy believed it had been rewritten, so a redaction
        policy would silently not redact. Refusing is the only honest outcome
        until the hook can apply the replacement.
        """
        if evaluation.verdict.decision is Decision.TRANSFORM:
            raise PermissionError(
                "policy returned a transform verdict, which these hooks cannot "
                "apply; use the guardrail integration or handle the transform "
                "at the call site"
            )
        if not evaluation.verdict.decision.permits:
            raise PermissionError(
                evaluation.verdict.message or evaluation.verdict.reason or evaluation.verdict.decision.value
            )

    async def on_agent_start(
        self, context: AgentHookContext[Any], agent: Agent[Any]
    ) -> None:
        self._agent_start_times[agent.name] = time.time()
        evaluation = self._session(agent.name).agent_startup()
        self._require_allowed(evaluation)
        self.audit_log.record(
            agent_id=agent.name,
            action="agent_start",
            decision=evaluation.verdict.decision.value,
            details=_audit_record(evaluation),
        )

    async def on_agent_end(
        self, context: AgentHookContext[Any], agent: Agent[Any], output: Any
    ) -> None:
        evaluation = self._session(agent.name).output(str(output or ""))
        self._require_allowed(evaluation)
        duration = time.time() - self._agent_start_times.get(agent.name, time.time())
        self.scorer.record_success(agent.name)
        self.audit_log.record(
            agent_id=agent.name,
            action="agent_end",
            decision=evaluation.verdict.decision.value,
            details={"duration_ms": round(duration * 1000, 2), **_audit_record(evaluation)},
        )

    async def on_tool_start(
        self, context: RunContextWrapper[Any], agent: Agent[Any], tool: Tool
    ) -> None:
        count = self._tool_call_counts.get(agent.name, 0) + 1
        # The openai-agents lifecycle hook signature does not carry the
        # tool-call arguments, so args is always empty here: policy rules that
        # condition on tool arguments never match on this path. Enforce them
        # via the guardrail integration instead.
        evaluation = self._session(agent.name).pre_tool_call(
            tool_name=tool.name,
            args={},
            call_id=f"tool-{count}",
        )
        if not evaluation.verdict.decision.permits:
            self.scorer.record_failure(agent.name, "security", penalty=0.15)
        self.audit_log.record(
            agent_id=agent.name,
            action=f"tool_start:{tool.name}",
            decision=evaluation.verdict.decision.value,
            details={"call_count": count, **_audit_record(evaluation)},
        )
        self._require_allowed(evaluation)
        self._tool_call_counts[agent.name] = count

    async def on_tool_end(
        self, context: RunContextWrapper[Any], agent: Agent[Any], tool: Tool, result: str
    ) -> None:
        # As in on_tool_start: the hook signature does not carry the tool-call
        # arguments, so arg-conditioned policy rules never match on this path.
        evaluation = self._session(agent.name).post_tool_call(
            tool_name=tool.name,
            args={},
            result=result,
            call_id=f"tool-{self._tool_call_counts.get(agent.name, 0)}",
        )
        if not evaluation.verdict.decision.permits:
            self.scorer.record_failure(agent.name, "security", penalty=0.1)
        self.audit_log.record(
            agent_id=agent.name,
            action=f"tool_end:{tool.name}",
            decision=evaluation.verdict.decision.value,
            details=_audit_record(evaluation),
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
