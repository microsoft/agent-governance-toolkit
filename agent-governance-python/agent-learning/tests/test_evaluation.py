# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Agent Learning governance evaluation pack."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_learning_gov import (
    CostPolicyEvaluation,
    GovernanceEvaluationPack,
    GovernanceOutcome,
    GovernanceTelemetry,
    GovernanceViolation,
    RiskLevel,
    ToolUsageRecord,
)


def _action(action_id: str, **parameters):
    return SimpleNamespace(id=action_id, parameters=parameters)


def _policy(*actions):
    return SimpleNamespace(
        id="policy-2",
        version=2,
        actions=list(actions),
        metadata={},
    )


def _episode(episode_id: str, telemetry: GovernanceTelemetry):
    return SimpleNamespace(
        id=episode_id,
        metadata=telemetry.merge_metadata(),
    )


def test_clean_policy_passes_standard_pack() -> None:
    report = GovernanceEvaluationPack().evaluate(
        _policy(_action("search", privilege="user", scopes=["read"])),
        episodes=[_episode("clean", GovernanceTelemetry())],
        baseline={"violation_rate": 0.0},
    )

    assert report.passed == True
    assert len(report.results) == 6
    assert report.findings == ()


def test_pack_reports_tools_privilege_restrictions_and_cost() -> None:
    violation = GovernanceViolation(
        policy_name="restricted-tools",
        description="delete blocked",
        severity=RiskLevel.HIGH,
        action_id="delete",
        blocked=True,
    )
    telemetry = GovernanceTelemetry(
        violations=(violation,),
        tool_usage=(
            ToolUsageRecord(
                tool_name="delete",
                outcome=GovernanceOutcome.DENIED,
                cost=150.0,
            ),
        ),
    )
    report = GovernanceEvaluationPack().evaluate(
        _policy(
            _action("delete", privilege="admin", restricted=True),
            _action("expensive", estimated_cost=150.0),
        ),
        episodes=[_episode("unsafe", telemetry)],
        baseline={"violation_rate": 0.0},
    )

    assert report.passed == False
    failed = {result.check_id for result in report.results if not result.passed}
    assert failed == {
        "unsafe_tool_selection",
        "excessive_privilege",
        "restricted_action_attempts",
        "cost_policy",
        "policy_regression",
    }
    assert len(report.findings) >= 5


def test_regression_check_uses_approved_baseline() -> None:
    telemetry = GovernanceTelemetry(
        violations=(
            GovernanceViolation(
                policy_name="policy",
                description="warning",
                severity=RiskLevel.LOW,
            ),
        )
    )
    report = GovernanceEvaluationPack().evaluate(
        _policy(_action("search")),
        episodes=[_episode("regressed", telemetry)],
        baseline={"violation_rate": 0.25},
    )
    regression = next(result for result in report.results if result.check_id == "policy_regression")

    assert regression.passed == False
    assert regression.metrics["violation_rate_delta"] == 0.75


def test_regression_check_requires_approved_baseline() -> None:
    report = GovernanceEvaluationPack().evaluate(
        _policy(_action("search")),
        episodes=[_episode("clean", GovernanceTelemetry())],
    )
    regression = next(result for result in report.results if result.check_id == "policy_regression")

    assert regression.passed == False
    assert regression.metrics["baseline_violation_rate"] is None
    assert "baseline" in regression.findings[0].message


def test_bayesian_decision_with_logprob_fails_route_integrity() -> None:
    episode = SimpleNamespace(
        id="bayesian",
        action_id="east",
        action_logprob=-0.5,
        metadata=GovernanceTelemetry(
            selection_basis="bayesian_decision",
            reinforce_eligible=True,
        ).merge_metadata(),
    )

    report = GovernanceEvaluationPack().evaluate(
        _policy(_action("east"), _action("west")),
        episodes=[episode],
    )
    route = next(
        result for result in report.results if result.check_id == "decision_route_integrity"
    )

    assert route.passed == False
    assert len(route.findings) == 2
    assert {finding.severity for finding in route.findings} == {
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    }


@pytest.mark.parametrize("limit", [float("nan"), float("inf"), -1.0, True, "invalid"])
def test_cost_policy_rejects_invalid_limits(limit) -> None:
    with pytest.raises(ValueError, match="finite and non-negative"):
        CostPolicyEvaluation(max_action_cost=limit)


@pytest.mark.parametrize("cost", [float("nan"), float("inf"), -1.0, True, "invalid"])
def test_cost_policy_fails_closed_on_invalid_action_cost(cost) -> None:
    result = CostPolicyEvaluation().evaluate(
        _policy(_action("expensive", estimated_cost=cost)),
        (),
        None,
    )

    assert result.passed == False
    assert result.findings[0].message == "Candidate action cost must be finite and non-negative"


@pytest.mark.parametrize("cost", [float("nan"), float("inf"), -1.0])
def test_cost_policy_fails_closed_on_invalid_observed_cost(cost: float) -> None:
    telemetry = GovernanceTelemetry(
        tool_usage=(
            ToolUsageRecord(
                tool_name="lookup",
                action_id="lookup",
                outcome=GovernanceOutcome.ALLOWED,
                cost=cost,
            ),
        )
    )

    result = CostPolicyEvaluation().evaluate(
        _policy(_action("lookup")),
        (_episode("invalid-cost", telemetry),),
        None,
    )

    assert result.passed == False
    assert result.metrics["observed_cost"] == 0.0
    assert result.findings[0].message == "Observed tool cost must be finite and non-negative"
