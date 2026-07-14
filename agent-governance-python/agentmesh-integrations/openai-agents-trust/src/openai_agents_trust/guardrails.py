# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenAI Agents guardrails for native governance and AgentMesh trust."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

from agents import Agent, InputGuardrail, OutputGuardrail
from agents.guardrail import GuardrailFunctionOutput
from agents.items import TResponseInputItem
from agents.run_context import RunContextWrapper
from agt.policies.session import AdapterRuntimeSession

from .audit import AuditLog
from .identity import AgentIdentity
from .trust import TrustScorer


@dataclass
class TrustGuardrailConfig:
    scorer: TrustScorer
    min_score: float = 0.5
    identities: Dict[str, AgentIdentity] = field(default_factory=dict)
    require_identity: bool = False
    audit_log: Optional[AuditLog] = None


@dataclass
class RuntimeGuardrailConfig:
    runtime: Any
    audit_log: Optional[AuditLog] = None
    sessions: dict[str, AdapterRuntimeSession] = field(default_factory=dict)

    def session(self, agent_id: str) -> AdapterRuntimeSession:
        session = self.sessions.get(agent_id)
        if session is None:
            session = AdapterRuntimeSession(
                self.runtime,
                agent_id=agent_id,
                session_id=f"openai-guardrail-{agent_id}",
            )
            self.sessions[agent_id] = session
        return session


def trust_input_guardrail(config: TrustGuardrailConfig) -> InputGuardrail:
    def _check_trust(
        ctx: RunContextWrapper[Any],
        agent: Agent[Any],
        input: Union[str, list[TResponseInputItem]],
    ) -> GuardrailFunctionOutput:
        agent_id = agent.name
        score = config.scorer.get_score(agent_id)
        identified = not config.require_identity or agent_id in config.identities
        trusted = identified and score.overall >= config.min_score
        if config.audit_log is not None:
            config.audit_log.record(
                agent_id=agent_id,
                action="trust_check",
                decision="allow" if trusted else "deny",
                details={"score": score.overall, "min_score": config.min_score},
            )
        return GuardrailFunctionOutput(
            output_info={"check": "trust", "agent_id": agent_id, "passed": trusted},
            tripwire_triggered=not trusted,
        )

    return InputGuardrail(guardrail_function=_check_trust, name="agentmesh_trust_guardrail")


def governance_input_guardrail(config: RuntimeGuardrailConfig) -> InputGuardrail:
    def _check(
        ctx: RunContextWrapper[Any],
        agent: Agent[Any],
        input: Union[str, list[TResponseInputItem]],
    ) -> GuardrailFunctionOutput:
        body = input if isinstance(input, str) else [
            item if isinstance(item, dict) else str(item) for item in input
        ]
        evaluation = config.session(agent.name).evaluate_input(body=body)
        if config.audit_log is not None:
            config.audit_log.record(
                agent_id=agent.name,
                action="input_check",
                decision=evaluation.verdict,
                details=evaluation.audit_record(),
            )
        return GuardrailFunctionOutput(
            output_info=evaluation.audit_record(),
            tripwire_triggered=not evaluation.is_allowed(),
        )

    return InputGuardrail(guardrail_function=_check, name="agentmesh_governance_guardrail")


def governance_output_guardrail(config: RuntimeGuardrailConfig) -> OutputGuardrail:
    def _check(
        ctx: RunContextWrapper[Any], agent: Agent[Any], output: Any
    ) -> GuardrailFunctionOutput:
        evaluation = config.session(agent.name).evaluate_output(content=str(output or ""))
        if config.audit_log is not None:
            config.audit_log.record(
                agent_id=agent.name,
                action="output_check",
                decision=evaluation.verdict,
                details=evaluation.audit_record(),
            )
        return GuardrailFunctionOutput(
            output_info=evaluation.audit_record(),
            tripwire_triggered=not evaluation.is_allowed(),
        )

    return OutputGuardrail(guardrail_function=_check, name="agentmesh_output_guardrail")
