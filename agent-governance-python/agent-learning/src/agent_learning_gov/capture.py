# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governance instrumentation for Agent Learning episode capture."""

from __future__ import annotations

import copy
import json
import math
from collections.abc import Mapping
from dataclasses import replace
from hashlib import sha256
from typing import Any

from .audit import AuditEvent, AuditEventType, AuditSink, emit_audit_event
from .models import (
    GovernanceTelemetry,
    ToolUsageRecord,
)
from .policy import GovernanceDeniedError, PolicyEvaluation, PolicyEvaluatorAdapter
from .provenance import resolve_provenance_key, sign_decision_certificate


class UnresolvedDecisionError(ValueError):
    """Raised when capture is started before Agent Learning resolves an action."""

    def __init__(self, status: str) -> None:
        self.status = status
        super().__init__(
            f"Agent Learning decision status {status!r} is not executable; "
            "resolve or adjudicate it before capture"
        )


class EpisodePersistenceError(RuntimeError):
    """Raised when Agent Learning returns an episode that was not persisted."""


class GovernedEpisodeCapture:
    """Delegate to Agent Learning capture while enriching episode metadata."""

    def __init__(
        self,
        kernel: Any,
        *,
        capture: Any | None = None,
        config: Any | None = None,
        store: Any | None = None,
        fail_closed: bool = True,
        raise_on_denied: bool = True,
        policy_name: str | None = None,
        audit_sink: AuditSink | None = None,
        provenance_key: bytes | str | None = None,
    ) -> None:
        if capture is None:
            try:
                from agent_learning import EpisodeCapture
            except ImportError as exc:
                raise ImportError(
                    "Install agent-learning>=0.8.0,<0.9.0 to create episode capture"
                ) from exc
            capture = EpisodeCapture(config, store)
        self.capture = capture
        self.policy = PolicyEvaluatorAdapter(
            kernel,
            fail_closed=fail_closed,
            policy_name=policy_name,
        )
        self.raise_on_denied = raise_on_denied
        self.audit_sink = audit_sink
        self._provenance_key = resolve_provenance_key(provenance_key)
        self._tool_authorizations: dict[str, PolicyEvaluation] = {}

    @property
    def store(self) -> Any:
        return self.capture.store

    @property
    def config(self) -> Any:
        return self.capture.config

    def is_enabled(self) -> bool:
        return self.capture.is_enabled()

    def start(
        self,
        user_input: str,
        *,
        decision_result: Any | None = None,
        governance_context: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Start capture and authorize the selected discrete action."""
        _require_resolved_decision(decision_result)
        decision_fields = _decision_fields(decision_result)
        for key, value in decision_fields.items():
            if key in kwargs and kwargs[key] is not None and kwargs[key] != value:
                raise ValueError(f"{key} conflicts with the resolved Agent Learning decision")
            kwargs[key] = value
        _validate_decision_scope(self.config, decision_result)

        selection_basis = getattr(decision_result, "selection_basis", None)
        action_logprob = kwargs.get("action_logprob")
        _validate_action_logprob(selection_basis, action_logprob)

        existing = GovernanceTelemetry.from_metadata(kwargs.get("metadata"))
        reinforce_eligible = _reinforce_eligibility(selection_basis, action_logprob)
        telemetry = replace(
            existing,
            selection_basis=selection_basis or existing.selection_basis,
            reinforce_eligible=(
                reinforce_eligible
                if reinforce_eligible is not None
                else existing.reinforce_eligible
            ),
        )

        evaluation = None
        action_id = kwargs.get("action_id") or kwargs.get("action_name")
        if action_id:
            evaluation = self.policy.evaluate(
                str(action_id),
                content=user_input,
                context={
                    **dict(governance_context or {}),
                    "phase": "episode_capture",
                    "agent_id": getattr(self.config, "agent_id", None),
                    "task_id": kwargs.get("task_id", "default"),
                    "policy_id": kwargs.get("policy_id"),
                    "policy_version": kwargs.get("policy_version"),
                    "action_id": action_id,
                },
            )
            telemetry = _append_evaluation(telemetry, evaluation)
            if evaluation.decision.outcome.value == "modified":
                kwargs["action_id"] = evaluation.effective_action_id
                if kwargs.get("action_name") == action_id:
                    kwargs["action_name"] = evaluation.effective_action_id
                kwargs["action_logprob"] = None
                telemetry = replace(telemetry, reinforce_eligible=False)

        kwargs["metadata"] = telemetry.merge_metadata(kwargs.get("metadata"))
        context = self.capture.start(user_input, **kwargs)
        _verify_decision_scope(
            context,
            decision_result,
            expected_action_id=kwargs.get("action_id"),
        )
        decision_certificate = _decision_certificate(
            decision_result,
            self._provenance_key,
            episode_id=getattr(context, "episode_id", None),
        )
        if decision_certificate is not None:
            telemetry_metadata = dict(telemetry.metadata)
            telemetry_metadata["decision_certificate"] = decision_certificate
            telemetry = replace(telemetry, metadata=telemetry_metadata)
            context.metadata = telemetry.merge_metadata(context.metadata)
        if evaluation is not None:
            self._emit_policy_evaluation(context, evaluation, artifact_type="episode")

        if evaluation is not None and not evaluation.allowed and self.raise_on_denied:
            self.end(
                context,
                "",
                execution_status="governance_denied",
                result_summary=evaluation.decision.reason,
            )
            raise GovernanceDeniedError(evaluation, capture_context=context)
        return context

    def record_tool_call(
        self,
        context: Any,
        name: str,
        arguments: dict[str, Any],
        result: str | None = None,
        *,
        duration_ms: int | None = None,
        error: str | None = None,
        cost: float | None = None,
        authorization: PolicyEvaluation | None = None,
        governance_context: Mapping[str, Any] | None = None,
    ) -> None:
        """Authorize and capture a tool call without bypassing redaction."""
        if cost is not None and (not math.isfinite(cost) or cost < 0):
            raise ValueError("cost must be finite and non-negative")
        telemetry = GovernanceTelemetry.from_metadata(context.metadata)
        if authorization is None:
            evaluation = self._evaluate_tool_call(
                context,
                name,
                arguments,
                governance_context=governance_context,
            )
        else:
            issued_evaluation = self._tool_authorizations.pop(
                authorization.decision.id,
                None,
            )
            _verify_tool_authorization(
                context,
                name,
                arguments,
                authorization,
                issued_evaluation,
                telemetry,
            )
            evaluation = issued_evaluation
        evaluation_recorded = any(
            decision.id == evaluation.decision.id for decision in telemetry.decisions
        )
        usage = ToolUsageRecord(
            tool_name=evaluation.effective_action_id,
            outcome=evaluation.decision.outcome,
            action_id=evaluation.effective_action_id,
            decision_id=evaluation.decision.id,
            duration_ms=duration_ms,
            cost=cost,
        )
        if not evaluation_recorded:
            telemetry = _append_evaluation(telemetry, evaluation)
        telemetry = replace(
            telemetry,
            tool_usage=(*telemetry.tool_usage, usage),
        )
        context.metadata = telemetry.merge_metadata(context.metadata)
        if not evaluation_recorded:
            self._emit_policy_evaluation(context, evaluation, artifact_type="tool_call")

        if evaluation.allowed:
            self.capture.record_tool_call(
                context,
                evaluation.effective_action_id,
                arguments,
                result,
                duration_ms=duration_ms,
                error=error,
            )
            return

        self.capture.record_tool_call(
            context,
            name,
            arguments,
            None,
            duration_ms=duration_ms,
            error=evaluation.decision.reason or "Denied by governance policy",
        )
        if self.raise_on_denied:
            raise GovernanceDeniedError(evaluation, capture_context=context)

    def authorize_tool_call(
        self,
        context: Any,
        name: str,
        arguments: Mapping[str, Any],
        *,
        governance_context: Mapping[str, Any] | None = None,
    ) -> PolicyEvaluation:
        """Authorize a tool before execution and return its effective action."""
        evaluation = self._evaluate_tool_call(
            context,
            name,
            arguments,
            governance_context=governance_context,
        )
        telemetry = GovernanceTelemetry.from_metadata(context.metadata)
        telemetry = _append_evaluation(telemetry, evaluation)
        context.metadata = telemetry.merge_metadata(context.metadata)
        self._tool_authorizations[evaluation.decision.id] = copy.deepcopy(evaluation)
        self._emit_policy_evaluation(context, evaluation, artifact_type="tool_call")
        if not evaluation.allowed and self.raise_on_denied:
            raise GovernanceDeniedError(evaluation, capture_context=context)
        return evaluation

    def end(self, context: Any, assistant_output: str, **kwargs: Any) -> Any:
        """Finish and persist the governed episode through Agent Learning."""
        episode = self.capture.end(context, assistant_output, **kwargs)
        if episode is not None:
            get_episode = getattr(self.store, "get_episode", None)
            if callable(get_episode) and get_episode(episode.id, episode.agent_id) is None:
                raise EpisodePersistenceError(
                    f"Agent Learning did not persist episode {episode.id!r}"
                )
            telemetry = GovernanceTelemetry.from_metadata(episode.metadata)
            emit_audit_event(
                self.audit_sink,
                AuditEvent(
                    event_type=AuditEventType.EPISODE_CAPTURED,
                    agent_id=episode.agent_id,
                    task_id=episode.task_id,
                    artifact_type="episode",
                    artifact_id=episode.id,
                    outcome=episode.execution_status or "captured",
                    policy_id=episode.policy_id,
                    policy_version=episode.policy_version,
                    action_id=episode.action_id,
                    correlation_id=episode.correlation_id,
                    details={
                        "decision_count": len(telemetry.decisions),
                        "violation_count": len(telemetry.violations),
                        "tool_call_count": len(telemetry.tool_usage),
                        "selection_basis": telemetry.selection_basis,
                        "reinforce_eligible": telemetry.reinforce_eligible,
                    },
                ),
            )
        return episode

    def _emit_policy_evaluation(
        self,
        context: Any,
        evaluation: PolicyEvaluation,
        *,
        artifact_type: str,
    ) -> None:
        emit_audit_event(
            self.audit_sink,
            AuditEvent(
                event_type=AuditEventType.POLICY_EVALUATED,
                agent_id=getattr(context, "agent_id", "unknown"),
                task_id=getattr(context, "task_id", "default"),
                artifact_type=artifact_type,
                artifact_id=getattr(context, "episode_id", "unknown"),
                outcome=evaluation.decision.outcome.value,
                policy_id=getattr(context, "policy_id", None),
                policy_version=getattr(context, "policy_version", None),
                action_id=evaluation.decision.action_id,
                correlation_id=getattr(context, "correlation_id", None),
                details={
                    "policy_name": evaluation.decision.policy_name,
                    "risk_level": evaluation.decision.risk_level.value,
                    "blocked": not evaluation.allowed,
                },
            ),
        )

    def _evaluate_tool_call(
        self,
        context: Any,
        name: str,
        arguments: Mapping[str, Any],
        *,
        governance_context: Mapping[str, Any] | None,
    ) -> PolicyEvaluation:
        argument_snapshot = dict(arguments)
        evaluation = self.policy.evaluate(
            name,
            content=json.dumps(
                argument_snapshot,
                separators=(",", ":"),
                sort_keys=True,
                default=str,
            ),
            context={
                **dict(governance_context or {}),
                "phase": "tool_call",
                "agent_id": getattr(context, "agent_id", None),
                "task_id": getattr(context, "task_id", None),
                "policy_id": getattr(context, "policy_id", None),
                "policy_version": getattr(context, "policy_version", None),
                "episode_id": getattr(context, "episode_id", None),
                "target": name,
                "arguments": argument_snapshot,
            },
        )
        binding = dict(evaluation.decision.metadata)
        binding["tool_authorization"] = {
            "version": 1,
            "fingerprint": _tool_call_fingerprint(context, name, argument_snapshot),
        }
        return replace(
            evaluation,
            decision=replace(evaluation.decision, metadata=binding),
        )


def _decision_fields(decision_result: Any | None) -> dict[str, Any]:
    if decision_result is None:
        return {}
    action = getattr(decision_result, "selected_action", None)
    return {
        key: value
        for key, value in {
            "task_id": getattr(decision_result, "task_id", None),
            "policy_id": getattr(decision_result, "policy_id", None),
            "policy_version": getattr(decision_result, "policy_version", None),
            "action_id": getattr(action, "id", None),
            "action_name": getattr(action, "id", None),
            "action_logprob": getattr(decision_result, "action_logprob", None),
        }.items()
        if value is not None
    }


def _require_resolved_decision(decision_result: Any | None) -> None:
    if decision_result is None:
        return
    raw_status = getattr(decision_result, "status", None)
    status = getattr(raw_status, "value", raw_status)
    selected_action = getattr(decision_result, "selected_action", None)
    if str(status) != "resolved":
        raise UnresolvedDecisionError(str(status))
    if selected_action is None:
        raise UnresolvedDecisionError(str(status or "pending"))


def _decision_certificate(
    decision_result: Any | None,
    provenance_key: bytes,
    *,
    episode_id: str | None,
) -> dict[str, Any] | None:
    if decision_result is None:
        return None

    def action_id(value: Any) -> str | None:
        identifier = getattr(value, "id", None)
        return str(identifier) if identifier is not None else None

    assessments = []
    for assessment in getattr(decision_result, "assessments", ()) or ():
        assessments.append(
            {
                "action_id": action_id(getattr(assessment, "action", None)),
                "feasible": getattr(assessment, "feasible", None),
                "expected_utility": getattr(assessment, "expected_utility", None),
                "uncertainty": getattr(assessment, "uncertainty", None),
                "robust_utility": getattr(assessment, "robust_utility", None),
                "ruled_out_by": list(getattr(assessment, "ruled_out_by", ()) or ()),
                "criteria": [
                    {
                        "criterion_id": getattr(criterion, "criterion_id", None),
                        "support": getattr(criterion, "support", None),
                        "entropy_bits": getattr(criterion, "entropy_bits", None),
                        "disagreement_bits": getattr(
                            criterion,
                            "disagreement_bits",
                            None,
                        ),
                        "source_count": getattr(criterion, "source_count", None),
                    }
                    for criterion in getattr(assessment, "criteria", ()) or ()
                ],
            }
        )

    information_needs = [
        {
            "kind": getattr(need, "kind", None),
            "option_id": getattr(need, "option_id", None),
            "field_id": getattr(need, "field_id", None),
            "estimated_information_gain_bits": getattr(
                need,
                "estimated_information_gain_bits",
                None,
            ),
            "reason": getattr(need, "reason", None),
        }
        for need in getattr(decision_result, "information_needs", ()) or ()
    ]
    raw_status = getattr(decision_result, "status", None)
    certificate = {
        "episode_id": episode_id,
        "agent_id": getattr(decision_result, "agent_id", None),
        "task_id": getattr(decision_result, "task_id", None),
        "status": getattr(raw_status, "value", raw_status),
        "reason": getattr(decision_result, "reason", None),
        "selection_basis": getattr(decision_result, "selection_basis", None),
        "policy_id": getattr(decision_result, "policy_id", None),
        "policy_version": getattr(decision_result, "policy_version", None),
        "selected_action_id": action_id(getattr(decision_result, "selected_action", None)),
        "proposed_action_id": action_id(getattr(decision_result, "proposed_action", None)),
        "candidate_action_ids": [
            identifier
            for action in getattr(decision_result, "candidate_actions", ()) or ()
            if (identifier := action_id(action)) is not None
        ],
        "assessments": assessments,
        "information_needs": information_needs,
        "rejected_action_ids": list(getattr(decision_result, "rejected_action_ids", ()) or ()),
        "authorization_basis": getattr(decision_result, "authorization_basis", None),
        "action_probabilities": dict(getattr(decision_result, "action_probabilities", {}) or {}),
        "action_logprob": getattr(decision_result, "action_logprob", None),
    }
    return sign_decision_certificate(certificate, provenance_key)


def _validate_decision_scope(config: Any, decision_result: Any | None) -> None:
    if decision_result is None:
        return
    decision_agent_id = getattr(decision_result, "agent_id", None)
    configured_agent_id = getattr(config, "agent_id", None)
    if (
        decision_agent_id is not None
        and configured_agent_id is not None
        and decision_agent_id != configured_agent_id
    ):
        raise ValueError("agent_id conflicts with the resolved Agent Learning decision")


def _verify_decision_scope(
    context: Any,
    decision_result: Any | None,
    *,
    expected_action_id: str | None,
) -> None:
    if decision_result is None:
        return
    for field in ("agent_id", "task_id", "policy_id", "policy_version"):
        expected = getattr(decision_result, field, None)
        if expected is not None and getattr(context, field, None) != expected:
            raise ValueError(f"capture {field} conflicts with the resolved Agent Learning decision")
    if expected_action_id is not None and getattr(context, "action_id", None) != expected_action_id:
        raise ValueError("capture action_id conflicts with the resolved Agent Learning decision")


def _validate_action_logprob(
    selection_basis: str | None,
    action_logprob: float | None,
) -> None:
    if selection_basis == "bayesian_decision":
        if action_logprob is not None:
            raise ValueError("Bayesian decisions must not carry an action_logprob")
        return
    if selection_basis != "learned_policy":
        return
    if action_logprob is None or not math.isfinite(action_logprob) or action_logprob > 0:
        raise ValueError("Learned-policy decisions require a finite non-positive action_logprob")


def _tool_call_fingerprint(
    context: Any,
    name: str,
    arguments: Mapping[str, Any],
) -> str:
    payload = json.dumps(
        {
            "episode_id": getattr(context, "episode_id", None),
            "tool_name": name,
            "arguments": dict(arguments),
        },
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def _verify_tool_authorization(
    context: Any,
    name: str,
    arguments: Mapping[str, Any],
    supplied_evaluation: PolicyEvaluation,
    issued_evaluation: PolicyEvaluation | None,
    telemetry: GovernanceTelemetry,
) -> None:
    if issued_evaluation is None:
        raise ValueError("authorization was not issued or has already been used")
    if supplied_evaluation.decision.id != issued_evaluation.decision.id:
        raise ValueError("authorization does not match the issued policy decision")
    if issued_evaluation.decision.action_id != name:
        raise ValueError("authorization does not belong to this tool call")
    authorization = issued_evaluation.decision.metadata.get("tool_authorization")
    if not isinstance(authorization, Mapping):
        raise TypeError("authorization is not bound to a tool call")
    expected = _tool_call_fingerprint(context, name, arguments)
    if authorization.get("version") != 1 or authorization.get("fingerprint") != expected:
        raise ValueError("authorization does not match this tool call")
    if not any(decision.id == issued_evaluation.decision.id for decision in telemetry.decisions):
        raise ValueError("authorization was not issued for this capture context")


def _reinforce_eligibility(
    selection_basis: str | None,
    action_logprob: float | None,
) -> bool | None:
    if selection_basis == "bayesian_decision":
        return False
    if selection_basis == "learned_policy":
        return action_logprob is not None
    return None


def _append_evaluation(
    telemetry: GovernanceTelemetry,
    evaluation: PolicyEvaluation,
) -> GovernanceTelemetry:
    violations = telemetry.violations
    if evaluation.violation is not None:
        violations = (*violations, evaluation.violation)
    return replace(
        telemetry,
        decisions=(*telemetry.decisions, evaluation.decision),
        violations=violations,
    )


__all__ = [
    "EpisodePersistenceError",
    "GovernedEpisodeCapture",
    "UnresolvedDecisionError",
]
