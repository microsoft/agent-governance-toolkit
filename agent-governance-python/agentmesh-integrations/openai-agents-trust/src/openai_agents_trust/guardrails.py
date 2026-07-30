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
from agent_control_specification import Decision, HostSession

from .audit import AuditLog, audit_record as _audit_record
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
    sessions: dict[str, HostSession] = field(default_factory=dict)

    def session(self, agent_id: str) -> HostSession:
        session = self.sessions.get(agent_id)
        if session is None:
            session = HostSession(
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


def _should_trip(evaluation: Any) -> bool:
    """Whether a guardrail must stop the run for this verdict.

    A guardrail can trip or not; it cannot rewrite the payload. ``transform``
    permits, so trusting ``is_allowed`` alone would let the original content
    through while the policy believed it had been rewritten, and a redaction
    policy would silently not redact.
    """
    if evaluation.verdict.decision is Decision.TRANSFORM:
        return True
    return not evaluation.verdict.decision.permits


def governance_input_guardrail(config: RuntimeGuardrailConfig) -> InputGuardrail:
    def _check(
        ctx: RunContextWrapper[Any],
        agent: Agent[Any],
        input: Union[str, list[TResponseInputItem]],
    ) -> GuardrailFunctionOutput:
        body = input if isinstance(input, str) else [
            item if isinstance(item, dict) else str(item) for item in input
        ]
        evaluation = config.session(agent.name).input(body)
        if config.audit_log is not None:
            config.audit_log.record(
                agent_id=agent.name,
                action="input_check",
                decision=evaluation.verdict.decision.value,
                details=_audit_record(evaluation),
            )
        return GuardrailFunctionOutput(
            output_info=_audit_record(evaluation),
            tripwire_triggered=_should_trip(evaluation),
        )

    return InputGuardrail(guardrail_function=_check, name="agentmesh_governance_guardrail")


def governance_output_guardrail(config: RuntimeGuardrailConfig) -> OutputGuardrail:
    def _check(
        ctx: RunContextWrapper[Any], agent: Agent[Any], output: Any
    ) -> GuardrailFunctionOutput:
        evaluation = config.session(agent.name).output(str(output or ""))
        if config.audit_log is not None:
            config.audit_log.record(
                agent_id=agent.name,
                action="output_check",
                decision=evaluation.verdict.decision.value,
                details=_audit_record(evaluation),
            )
        return GuardrailFunctionOutput(
            output_info=_audit_record(evaluation),
            tripwire_triggered=_should_trip(evaluation),
        )

    return OutputGuardrail(guardrail_function=_check, name="agentmesh_output_guardrail")
