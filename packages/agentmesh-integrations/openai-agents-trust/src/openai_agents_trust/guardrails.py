"""Guardrails for OpenAI Agents SDK — trust, policy, and content enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from agents import Agent, InputGuardrail, OutputGuardrail
from agents.guardrail import GuardrailFunctionOutput
from agents.items import TResponseInputItem
from agents.run_context import RunContextWrapper

from .audit import AuditLog
from .identity import AgentIdentity
from .policy import GovernancePolicy
from .trust import TrustScorer


@dataclass
class TrustGuardrailConfig:
    """Configuration for the trust guardrail."""

    scorer: TrustScorer
    min_score: float = 0.5
    identities: Dict[str, AgentIdentity] = field(default_factory=dict)
    require_identity: bool = False
    audit_log: Optional[AuditLog] = None


@dataclass
class PolicyGuardrailConfig:
    """Configuration for the policy guardrail."""

    policy: GovernancePolicy
    audit_log: Optional[AuditLog] = None
    tool_call_counts: Dict[str, int] = field(default_factory=dict)


def trust_input_guardrail(config: TrustGuardrailConfig) -> InputGuardrail:
    """Create an InputGuardrail that checks agent trust scores.

    Triggers tripwire if the agent's trust score is below the configured minimum.
    """

    def _check_trust(
        ctx: RunContextWrapper[Any],
        agent: Agent[Any],
        input: Union[str, list[TResponseInputItem]],
    ) -> GuardrailFunctionOutput:
        agent_id = agent.name
        score = config.scorer.get_score(agent_id)

        # Check identity if required
        if config.require_identity and agent_id not in config.identities:
            if config.audit_log is not None:
                config.audit_log.record(
                    agent_id=agent_id,
                    action="identity_check",
                    decision="deny",
                    details={"reason": "No registered identity"},
                )
            return GuardrailFunctionOutput(
                output_info={
                    "check": "trust",
                    "agent_id": agent_id,
                    "reason": "Agent has no registered identity",
                },
                tripwire_triggered=True,
            )

        trusted = score.overall >= config.min_score
        decision = "allow" if trusted else "deny"

        if config.audit_log is not None:
            config.audit_log.record(
                agent_id=agent_id,
                action="trust_check",
                decision=decision,
                details={
                    "score": score.overall,
                    "min_score": config.min_score,
                    "dimensions": score.to_dict(),
                },
            )

        return GuardrailFunctionOutput(
            output_info={
                "check": "trust",
                "agent_id": agent_id,
                "score": score.overall,
                "min_score": config.min_score,
                "passed": trusted,
            },
            tripwire_triggered=not trusted,
        )

    return InputGuardrail(
        guardrail_function=_check_trust,
        name="agentmesh_trust_guardrail",
    )


def policy_input_guardrail(config: PolicyGuardrailConfig) -> InputGuardrail:
    """Create an InputGuardrail that enforces governance policies.

    Checks input content against blocked patterns and tool call limits.
    """

    def _check_policy(
        ctx: RunContextWrapper[Any],
        agent: Agent[Any],
        input: Union[str, list[TResponseInputItem]],
    ) -> GuardrailFunctionOutput:
        agent_id = agent.name
        policy = config.policy

        # Extract text content for pattern checking
        if isinstance(input, str):
            content = input
        else:
            content = " ".join(
                str(item.get("content", "")) if isinstance(item, dict) else str(item)
                for item in input
            )

        # Check blocked patterns
        violation = policy.check_content(content)
        if violation:
            if config.audit_log is not None:
                config.audit_log.record(
                    agent_id=agent_id,
                    action="policy_check",
                    decision="deny",
                    details={"reason": violation, "policy": policy.name},
                )
            return GuardrailFunctionOutput(
                output_info={
                    "check": "policy",
                    "agent_id": agent_id,
                    "violation": violation,
                    "policy": policy.name,
                },
                tripwire_triggered=True,
            )

        if config.audit_log is not None:
            config.audit_log.record(
                agent_id=agent_id,
                action="policy_check",
                decision="allow",
                details={"policy": policy.name},
            )

        return GuardrailFunctionOutput(
            output_info={
                "check": "policy",
                "agent_id": agent_id,
                "passed": True,
                "policy": policy.name,
            },
            tripwire_triggered=False,
        )

    return InputGuardrail(
        guardrail_function=_check_policy,
        name="agentmesh_policy_guardrail",
    )


def content_output_guardrail(
    policy: GovernancePolicy,
    audit_log: Optional[AuditLog] = None,
) -> OutputGuardrail:
    """Create an OutputGuardrail that validates output content against blocked patterns."""

    def _check_output(
        ctx: RunContextWrapper[Any],
        agent: Agent[Any],
        output: Any,
    ) -> GuardrailFunctionOutput:
        agent_id = agent.name
        content = str(output) if output else ""

        violation = policy.check_content(content)
        if violation:
            if audit_log is not None:
                audit_log.record(
                    agent_id=agent_id,
                    action="output_check",
                    decision="deny",
                    details={"reason": violation},
                )
            return GuardrailFunctionOutput(
                output_info={
                    "check": "output_content",
                    "agent_id": agent_id,
                    "violation": violation,
                },
                tripwire_triggered=True,
            )

        if audit_log is not None:
            audit_log.record(
                agent_id=agent_id,
                action="output_check",
                decision="allow",
            )

        return GuardrailFunctionOutput(
            output_info={
                "check": "output_content",
                "agent_id": agent_id,
                "passed": True,
            },
            tripwire_triggered=False,
        )

    return OutputGuardrail(
        guardrail_function=_check_output,
        name="agentmesh_content_guardrail",
    )

