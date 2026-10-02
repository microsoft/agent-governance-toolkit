# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Normalize Agent Governance Toolkit policy evaluators for discrete actions."""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .models import (
    GovernanceOutcome,
    GovernanceViolation,
    PolicyDecisionRecord,
    RiskLevel,
)

_ALLOW_VALUES = {
    "allow",
    "allowed",
    "modify",
    "modified",
    "pass",
    "passed",
    "permit",
    "permitted",
    "warn",
    "warned",
}
_DENY_VALUES = {"block", "blocked", "deny", "denied", "reject", "rejected"}
_SEVERITY_PENALTIES = {
    RiskLevel.LOW: 0.05,
    RiskLevel.MEDIUM: 0.25,
    RiskLevel.HIGH: 0.75,
    RiskLevel.CRITICAL: 1.0,
}


@dataclass(frozen=True)
class PolicyEvaluation:
    """Normalized decision and optional violation from one policy check."""

    decision: PolicyDecisionRecord
    violation: GovernanceViolation | None = None

    @property
    def allowed(self) -> bool:
        return self.decision.outcome is not GovernanceOutcome.DENIED

    @property
    def effective_action_id(self) -> str:
        """Return the policy-approved action identifier."""
        if self.decision.outcome is GovernanceOutcome.MODIFIED:
            return self.decision.modified_action_id or self.decision.action_id
        return self.decision.action_id


class AsyncPolicyEvaluatorError(TypeError):
    """Raised when a synchronous Agent Learning hook receives an async evaluator."""


class GovernanceDeniedError(PermissionError):
    """Raised when governance blocks an action before execution."""

    def __init__(self, evaluation: PolicyEvaluation, capture_context: Any = None) -> None:
        self.evaluation = evaluation
        self.capture_context = capture_context
        super().__init__(evaluation.decision.reason or "Action denied by governance policy")


class PolicyEvaluatorAdapter:
    """Adapt AGT Lite, external backends, and compatible policy callbacks."""

    def __init__(
        self,
        evaluator: Any,
        *,
        fail_closed: bool = True,
        policy_name: str | None = None,
    ) -> None:
        if evaluator is None:
            raise ValueError("A governance policy evaluator is required")
        self.evaluator = evaluator
        self.fail_closed = fail_closed
        self.policy_name = policy_name or self._infer_policy_name(evaluator)

    def evaluate(
        self,
        action_id: str,
        *,
        content: str = "",
        context: Mapping[str, Any] | None = None,
    ) -> PolicyEvaluation:
        """Evaluate one action and convert the result to durable records."""
        if not action_id:
            raise ValueError("action_id must not be empty")
        evaluation_context = dict(context or {})
        try:
            raw_result = self._invoke(action_id, content, evaluation_context)
            if inspect.isawaitable(raw_result):
                close = getattr(raw_result, "close", None)
                if callable(close):
                    close()
                raise AsyncPolicyEvaluatorError(
                    "Agent Learning capture and offline batches are synchronous; "
                    "provide a synchronous policy evaluator"
                )
            return self._normalize(action_id, raw_result)
        except AsyncPolicyEvaluatorError:
            raise
        except Exception as exc:  # noqa: BLE001
            allowed = not self.fail_closed
            outcome = GovernanceOutcome.WARNED if allowed else GovernanceOutcome.DENIED
            risk = RiskLevel.HIGH if allowed else RiskLevel.CRITICAL
            decision = PolicyDecisionRecord(
                policy_name=self.policy_name,
                action_id=action_id,
                outcome=outcome,
                reason=f"Policy evaluation failed ({type(exc).__name__})",
                risk_level=risk,
                metadata={"evaluation_error": type(exc).__name__},
            )
            violation = GovernanceViolation(
                policy_name=self.policy_name,
                description=decision.reason,
                severity=risk,
                action_id=action_id,
                blocked=not allowed,
                penalty=_SEVERITY_PENALTIES[risk],
                decision_id=decision.id,
                metadata={"evaluation_error": type(exc).__name__},
            )
            return PolicyEvaluation(decision=decision, violation=violation)

    def _invoke(self, action_id: str, content: str, context: dict[str, Any]) -> Any:
        method = self._find_method()
        signature = inspect.signature(method)
        parameters = signature.parameters

        if "content" in parameters:
            accepts_keyword_context = any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
            )
            positional_parameters = [
                name
                for name, parameter in parameters.items()
                if parameter.kind
                in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
            reserved = {"content", *positional_parameters[:1]}
            extra_context = {
                key: value
                for key, value in context.items()
                if key not in reserved
                and (
                    accepts_keyword_context
                    or (
                        key in parameters
                        and parameters[key].kind
                        in (
                            inspect.Parameter.POSITIONAL_OR_KEYWORD,
                            inspect.Parameter.KEYWORD_ONLY,
                        )
                    )
                )
            }
            return method(action_id, content=content, **extra_context)
        if "context" in parameters:
            return method(action_id, context=context)
        if "target" in parameters:
            return method(action_id, target=str(context.get("target", "")))
        if len(parameters) >= 2:
            return method(action_id, context)
        return method(action_id)

    def _find_method(self) -> Any:
        for name in ("evaluate", "evaluate_action", "authorize", "is_allowed", "check_policy"):
            method = getattr(self.evaluator, name, None)
            if callable(method):
                return method
        if callable(self.evaluator):
            return self.evaluator
        raise TypeError("Governance evaluator has no supported policy-check method")

    def _normalize(self, action_id: str, result: Any) -> PolicyEvaluation:
        values = result if isinstance(result, Mapping) else _ObjectView(result)
        allowed = _extract_allowed(result, values)
        outcome = _extract_outcome(values, allowed)
        reason = str(values.get("reason", values.get("description", "")))
        policy_name = str(
            values.get(
                "policy_name",
                values.get("matched_rule", values.get("backend", self.policy_name)),
            )
            or self.policy_name
        )
        default_risk = RiskLevel.LOW if allowed else RiskLevel.HIGH
        risk_level = _coerce_risk(values.get("severity", values.get("risk_level")), default_risk)
        modified_action_id = _extract_modified_action(values)
        if outcome is GovernanceOutcome.MODIFIED and modified_action_id is None:
            raise ValueError("A modified policy result must provide a replacement action")

        decision = PolicyDecisionRecord(
            policy_name=policy_name,
            action_id=action_id,
            outcome=outcome,
            reason=reason,
            risk_level=risk_level,
            modified_action_id=modified_action_id,
        )
        if allowed and outcome is GovernanceOutcome.ALLOWED:
            return PolicyEvaluation(decision=decision)

        violation = GovernanceViolation(
            policy_name=policy_name,
            description=reason or f"Governance policy returned {outcome.value}",
            severity=risk_level,
            action_id=action_id,
            blocked=not allowed,
            penalty=_SEVERITY_PENALTIES[risk_level],
            decision_id=decision.id,
        )
        return PolicyEvaluation(decision=decision, violation=violation)

    @staticmethod
    def _infer_policy_name(evaluator: Any) -> str:
        name = getattr(evaluator, "name", None)
        return str(name) if name else type(evaluator).__name__


class _ObjectView(dict[str, Any]):
    def __init__(self, value: Any) -> None:
        super().__init__()
        for name in (
            "allowed",
            "backend",
            "decision",
            "description",
            "matched_rule",
            "modified_action",
            "modified_action_id",
            "outcome",
            "policy_name",
            "reason",
            "risk_level",
            "severity",
            "success",
            "verdict",
        ):
            if hasattr(value, name):
                self[name] = getattr(value, name)


def _extract_allowed(result: Any, values: Mapping[str, Any]) -> bool:
    if isinstance(result, bool):
        return result
    candidates: list[bool] = []
    for key in ("allowed", "permit", "success"):
        if key in values:
            candidates.append(_coerce_allowed(values[key]))
    for key in ("outcome", "decision", "verdict"):
        if key not in values:
            continue
        value = values[key]
        if isinstance(value, Enum):
            value = value.value
        normalized = str(value).lower()
        if normalized in _ALLOW_VALUES:
            candidates.append(True)
        elif normalized in _DENY_VALUES:
            candidates.append(False)
    if not candidates:
        raise TypeError("Policy result must expose an allowed flag or allow/deny verdict")
    if any(candidate != candidates[0] for candidate in candidates[1:]):
        raise ValueError("Policy result contains contradictory allow and deny fields")
    return candidates[0]


def _coerce_allowed(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _ALLOW_VALUES | {"true", "yes", "1"}:
            return True
        if normalized in _DENY_VALUES | {"false", "no", "0"}:
            return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise TypeError("Policy allowed flag must be a boolean or recognized verdict")


def _extract_outcome(values: Mapping[str, Any], allowed: bool) -> GovernanceOutcome:
    if not allowed:
        return GovernanceOutcome.DENIED
    for key in ("outcome", "decision", "verdict"):
        value = values.get(key)
        if isinstance(value, Enum):
            value = value.value
        normalized = str(value).lower() if value is not None else ""
        if normalized in {"modify", "modified"}:
            return GovernanceOutcome.MODIFIED
        if normalized in {"warn", "warned"}:
            return GovernanceOutcome.WARNED
    return GovernanceOutcome.ALLOWED if allowed else GovernanceOutcome.DENIED


def _coerce_risk(value: Any, default: RiskLevel) -> RiskLevel:
    if isinstance(value, RiskLevel):
        return value
    try:
        return RiskLevel(str(value).lower())
    except ValueError:
        return default


def _extract_modified_action(values: Mapping[str, Any]) -> str | None:
    value = values.get("modified_action_id", values.get("modified_action"))
    if value is None:
        return None
    if isinstance(value, Mapping):
        value = value.get("id")
    else:
        value = getattr(value, "id", value)
    return str(value) if value is not None else None


__all__ = [
    "AsyncPolicyEvaluatorError",
    "GovernanceDeniedError",
    "PolicyEvaluation",
    "PolicyEvaluatorAdapter",
]
