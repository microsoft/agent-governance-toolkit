# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for governance policy evaluator normalization."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agent_learning_gov import (
    AsyncPolicyEvaluatorError,
    GovernanceOutcome,
    PolicyEvaluatorAdapter,
    RiskLevel,
)


class _LiteEvaluator:
    name = "lite-policy"

    def __init__(self) -> None:
        self.received: tuple[str, str, dict[str, Any]] | None = None

    def evaluate(self, action: str, content: str = "", **context: Any) -> Any:
        self.received = (action, content, context)
        return SimpleNamespace(allowed=True, reason="allowed")


def test_lite_signature_receives_content_and_context() -> None:
    evaluator = _LiteEvaluator()
    adapter = PolicyEvaluatorAdapter(evaluator)

    result = adapter.evaluate(
        "search",
        content="public query",
        context={"agent_id": "agent-1", "target": "catalog"},
    )

    assert result.allowed == True
    assert evaluator.received == (
        "search",
        "public query",
        {"agent_id": "agent-1", "target": "catalog"},
    )


def test_content_signature_forwards_declared_context_and_ignores_unknown() -> None:
    received: dict[str, str] = {}

    class Evaluator:
        def evaluate(self, action: str, content: str = "", target: str = "") -> bool:
            received.update(action=action, content=content, target=target)
            return True

    result = PolicyEvaluatorAdapter(Evaluator()).evaluate(
        "read",
        content="document",
        context={"target": "handbook", "correlation_id": "private"},
    )

    assert result.allowed == True
    assert received == {"action": "read", "content": "document", "target": "handbook"}


def test_context_backend_receives_mapping_and_normalizes_denial() -> None:
    received: dict[str, Any] = {}

    class Evaluator:
        def evaluate(self, action: str, context: dict[str, Any]) -> dict[str, Any]:
            received.update(action=action, context=context)
            return {
                "verdict": "deny",
                "reason": "restricted resource",
                "severity": "critical",
                "matched_rule": "restricted-resource",
            }

    result = PolicyEvaluatorAdapter(Evaluator()).evaluate(
        "download",
        context={"target": "confidential"},
    )

    assert received == {"action": "download", "context": {"target": "confidential"}}
    assert result.allowed == False
    assert result.decision.outcome is GovernanceOutcome.DENIED
    assert result.decision.policy_name == "restricted-resource"
    assert result.violation is not None
    assert result.violation.severity is RiskLevel.CRITICAL


def test_string_false_is_denied() -> None:
    result = PolicyEvaluatorAdapter(lambda action: {"allowed": "false"}).evaluate("transfer")

    assert result.allowed == False
    assert result.decision.outcome is GovernanceOutcome.DENIED


def test_contradictory_modified_denial_remains_denied() -> None:
    result = PolicyEvaluatorAdapter(
        lambda action: {
            "allowed": False,
            "verdict": "modified",
            "modified_action_id": f"safe_{action}",
        }
    ).evaluate("export")

    assert result.allowed == False
    assert result.decision.outcome is GovernanceOutcome.DENIED


def test_contradictory_allowed_and_deny_verdict_fails_closed() -> None:
    result = PolicyEvaluatorAdapter(lambda action: {"allowed": True, "verdict": "deny"}).evaluate(
        "export"
    )

    assert result.allowed == False
    assert result.decision.outcome is GovernanceOutcome.DENIED
    assert result.decision.reason == "Policy evaluation failed (ValueError)"


def test_modified_result_without_replacement_fails_closed() -> None:
    result = PolicyEvaluatorAdapter(
        lambda action: {"allowed": True, "verdict": "modified"}
    ).evaluate("export")

    assert result.allowed == False
    assert result.decision.outcome is GovernanceOutcome.DENIED
    assert result.decision.reason == "Policy evaluation failed (ValueError)"


def test_evaluator_exception_fails_closed_without_exposing_message() -> None:
    class Evaluator:
        def authorize(self, action: str) -> bool:
            del action
            raise RuntimeError("backend token=secret")

    result = PolicyEvaluatorAdapter(Evaluator()).evaluate("transfer")

    assert result.allowed == False
    assert result.decision.outcome is GovernanceOutcome.DENIED
    assert result.decision.risk_level is RiskLevel.CRITICAL
    assert result.decision.reason == "Policy evaluation failed (RuntimeError)"
    assert "secret" not in result.decision.reason
    assert result.violation is not None
    assert result.violation.blocked == True


def test_async_evaluator_is_rejected() -> None:
    class Evaluator:
        async def evaluate(self, action: str) -> bool:
            del action
            return True

    with pytest.raises(AsyncPolicyEvaluatorError, match="synchronous"):
        PolicyEvaluatorAdapter(Evaluator()).evaluate("search")


def test_modified_result_preserves_replacement_action() -> None:
    evaluator = lambda action: {
        "allowed": True,
        "verdict": "modified",
        "reason": "least-privilege replacement",
        "severity": "medium",
        "modified_action": {"id": f"safe_{action}"},
    }

    result = PolicyEvaluatorAdapter(evaluator, policy_name="rewrite-policy").evaluate("export")

    assert result.allowed == True
    assert result.decision.outcome is GovernanceOutcome.MODIFIED
    assert result.decision.modified_action_id == "safe_export"
    assert result.effective_action_id == "safe_export"
    assert result.violation is not None
    assert result.violation.blocked == False
