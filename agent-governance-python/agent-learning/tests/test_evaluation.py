# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Agent Learning governance evaluation pack."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_learning_gov import (
    CostPolicyEvaluation,
    ExcessivePrivilegeEvaluation,
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


@pytest.mark.parametrize(
    "parameters",
    [
        {"privilege": None, "role": "admin"},
        {"privilege": "user", "role": "admin"},
        {"scopes": ["read"], "permissions": ["*"]},
        {"scopes": [], "permissions": ["root"]},
    ],
)
def test_excessive_privilege_checks_role_and_permissions(parameters) -> None:
    result = ExcessivePrivilegeEvaluation().evaluate(
        _policy(_action("grant", **parameters)), episodes=(), baseline=None
    )

    assert result.passed == False
    assert [finding.action_id for finding in result.findings] == ["grant"]


def test_excessive_privilege_counts_scopes_and_permissions_together() -> None:
    evaluation = ExcessivePrivilegeEvaluation(max_scopes=3)
    result = evaluation.evaluate(
        _policy(_action("grant", scopes=["a", "b"], permissions=["c", "d"])),
        episodes=(),
        baseline=None,
    )

    assert result.passed == False
    assert result.findings[0].metadata == {"scope_count": 4}


def test_excessive_privilege_passes_unprivileged_role_and_permissions() -> None:
    result = ExcessivePrivilegeEvaluation().evaluate(
        _policy(_action("search", privilege=None, role="user", permissions=["read"])),
        episodes=(),
        baseline=None,
    )

    assert result.passed == True


@pytest.mark.parametrize(
    "parameters",
    [
        # Whitespace around the value.
        {"privilege": " admin "},
        {"role": "\tadmin\n"},
        {"scopes": [" * "]},
        # Unicode whitespace (no-break space, em space).
        {"privilege": "\u00a0admin\u2003"},
        # Mixed-case value.
        {"privilege": " AdMiN "},
        {"scopes": ["Root "]},
        # List-valued privilege and role, element by element.
        {"privilege": ["user", "admin"]},
        {"role": ("viewer", "Owner")},
        {"privilege": {"user", "admin"}},
        # Nested lists in scopes and permissions.
        {"scopes": [["*"]]},
        {"permissions": [["read"], [["write", ["admin"]]]]},
        {"scopes": [[[[[[[[[["*"]]]]]]]]]]},
        # Partial wildcards.
        {"scopes": ["admin:*"]},
        {"permissions": ["repo.*"]},
        {"scopes": ["*:read"]},
        {"privilege": "admin:*"},
        # Capitalised keys, including mixed-case key with mixed-case value.
        {"Privilege": "admin"},
        {"ROLE": "admin"},
        {"Scopes": ["*"]},
        {"PERMISSIONS": ["root"]},
        {"PrIvIlEgE": "AdMiN"},
        {" privilege ": "admin"},
        # A capitalised key next to a lower-case one that is harmless.
        {"privilege": "user", "PRIVILEGE": "admin"},
    ],
)
def test_excessive_privilege_normalizes_values_and_keys(parameters) -> None:
    result = ExcessivePrivilegeEvaluation().evaluate(
        _policy(_action("grant", **parameters)), episodes=(), baseline=None
    )

    assert result.passed == False
    assert [finding.action_id for finding in result.findings] == ["grant"]
    assert result.findings[0].severity is RiskLevel.HIGH


@pytest.mark.parametrize(
    "parameters",
    [
        {"scopes": [None]},
        {"scopes": [b"*"]},
        {"permissions": [{"name": "admin"}]},
        {"privilege": [1]},
        {"role": ["user", None]},
    ],
)
def test_excessive_privilege_fails_closed_on_unexpected_leaf_types(parameters) -> None:
    result = ExcessivePrivilegeEvaluation().evaluate(
        _policy(_action("grant", **parameters)), episodes=(), baseline=None
    )

    assert result.passed == False
    assert [finding.action_id for finding in result.findings] == ["grant"]
    assert result.findings[0].message == (
        "Action privilege, role, scope and permission values must be strings"
    )


def test_excessive_privilege_reports_elevated_value_over_unreadable_leaf() -> None:
    result = ExcessivePrivilegeEvaluation().evaluate(
        _policy(_action("grant", scopes=[None, "admin"])), episodes=(), baseline=None
    )

    assert result.passed == False
    assert result.findings[0].message == "Action requests excessive privilege"


def test_excessive_privilege_counts_flattened_scopes() -> None:
    evaluation = ExcessivePrivilegeEvaluation(max_scopes=3)
    result = evaluation.evaluate(
        _policy(_action("grant", scopes=[["a", "b"], ["c"]], Permissions=["d"])),
        episodes=(),
        baseline=None,
    )

    assert result.passed == False
    assert result.findings[0].metadata == {"scope_count": 4}


@pytest.mark.parametrize(
    "parameters",
    [
        {"privilege": " user ", "role": "Viewer", "scopes": ["read"]},
        {"Privilege": "user", "ROLE": "viewer", "Permissions": [["read"], ["write"]]},
        {"privilege": [], "role": (), "scopes": [[]], "permissions": set()},
        {"privilege": None, "role": None},
        {"scopes": ["admin-reports:read", "repo.read"]},
        {},
    ],
)
def test_excessive_privilege_passes_normalized_low_privilege(parameters) -> None:
    result = ExcessivePrivilegeEvaluation().evaluate(
        _policy(_action("search", **parameters)), episodes=(), baseline=None
    )

    assert result.passed == True
    assert result.findings == ()


def test_excessive_privilege_handles_self_referencing_scopes() -> None:
    scopes: list = ["read"]
    scopes.append(scopes)
    result = ExcessivePrivilegeEvaluation().evaluate(
        _policy(_action("search", scopes=scopes)), episodes=(), baseline=None
    )

    assert result.passed == True


def test_excessive_privilege_flags_elevated_value_inside_a_cycle() -> None:
    scopes: list = ["read"]
    scopes.append([scopes, "admin"])
    result = ExcessivePrivilegeEvaluation().evaluate(
        _policy(_action("search", scopes=scopes)), episodes=(), baseline=None
    )

    assert result.passed == False
    assert result.findings[0].metadata == {"scope_count": 2}


def test_excessive_privilege_revisits_a_container_yielded_twice() -> None:
    # The same list object (so the same id) is yielded twice; it carries an
    # elevated value only on the second pass. A walker that remembers every
    # id it has seen skips the second pass and misses the value.
    def scopes():
        shared = ["read"]
        yield shared
        shared[0] = "admin"
        yield shared

    result = ExcessivePrivilegeEvaluation().evaluate(
        _policy(_action("search", scopes=scopes())), episodes=(), baseline=None
    )

    assert result.passed == False
    assert result.findings[0].metadata == {"scope_count": 2}


def test_excessive_privilege_detects_admin_in_list_with_reused_id() -> None:
    # Each inner generator builds its list only when the walker reaches it,
    # and the walker drops the list once it has been read, so CPython can
    # hand the next list the same id. Every list must still be read.
    def nested(value: str):
        yield [value]

    def scopes():
        for index in range(50):
            yield nested(f"scope-{index}:read")
        yield nested("admin")

    result = ExcessivePrivilegeEvaluation(max_scopes=100).evaluate(
        _policy(_action("search", scopes=scopes())), episodes=(), baseline=None
    )

    assert result.passed == False
    assert result.findings[0].metadata == {"scope_count": 51}


def test_excessive_privilege_counts_shared_list_in_scopes_and_permissions() -> None:
    shared = ["a", "b", "c", "d", "e", "f"]
    result = ExcessivePrivilegeEvaluation(max_scopes=10).evaluate(
        _policy(_action("grant", scopes=shared, permissions=shared)),
        episodes=(),
        baseline=None,
    )

    assert result.passed == False
    assert result.findings[0].metadata == {"scope_count": 12}


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
