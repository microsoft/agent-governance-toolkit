# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

from agent_os.policies.evaluator import PolicyEvaluator
from agent_os.policies.schema import (
    DynamicCondition,
    DynamicConditionType,
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)


def _temporal_evaluator(dynamic_condition: DynamicCondition) -> PolicyEvaluator:
    doc = PolicyDocument(
        name="temporal-policy",
        rules=[
            PolicyRule(
                name="temporal-rule",
                condition=PolicyCondition(
                    field="action_type",
                    operator=PolicyOperator.EQ,
                    value="tool_call",
                ),
                dynamic_condition=dynamic_condition,
                action=PolicyAction.DENY,
            )
        ],
    )
    return PolicyEvaluator(policies=[doc])


def _budget_allow_evaluator(dynamic_condition: DynamicCondition) -> PolicyEvaluator:
    doc = PolicyDocument(
        name="budget-policy",
        rules=[
            PolicyRule(
                name="budget-rule",
                condition=PolicyCondition(
                    field="action_type",
                    operator=PolicyOperator.EQ,
                    value="tool_call",
                ),
                dynamic_condition=dynamic_condition,
                action=PolicyAction.ALLOW,
            )
        ],
        defaults=PolicyDefaults(action=PolicyAction.DENY),
    )
    return PolicyEvaluator(policies=[doc])


def test_time_window_inside_match_denies():
    evaluator = _temporal_evaluator(
        DynamicCondition(
            type=DynamicConditionType.TIME_WINDOW,
            timezone="UTC",
            start_time="09:00",
            end_time="17:00",
            days_of_week=[1, 2, 3, 4, 5],
        )
    )

    result = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={"timestamp": "2026-01-05T10:00:00Z"},
    )

    assert not result.allowed


def test_time_window_outside_window_does_not_match():
    evaluator = _temporal_evaluator(
        DynamicCondition(
            type=DynamicConditionType.TIME_WINDOW,
            timezone="UTC",
            start_time="09:00",
            end_time="17:00",
            days_of_week=[1, 2, 3, 4, 5],
        )
    )

    result = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={"timestamp": "2026-01-05T19:00:00Z"},
    )

    assert result.allowed


def test_day_of_week_match_denies():
    evaluator = _temporal_evaluator(
        DynamicCondition(
            type=DynamicConditionType.DAY_OF_WEEK,
            timezone="UTC",
            days_of_week=[1],
        )
    )

    monday = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={"timestamp": "2026-01-05T12:00:00Z"},
    )
    sunday = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={"timestamp": "2026-01-04T12:00:00Z"},
    )

    assert not monday.allowed
    assert sunday.allowed


def test_dst_spring_forward_uses_timezone_conversion():
    evaluator = _temporal_evaluator(
        DynamicCondition(
            type=DynamicConditionType.TIME_WINDOW,
            timezone="America/New_York",
            start_time="03:00",
            end_time="04:00",
        )
    )

    # 2026-03-08 07:30:00Z == 03:30 local after DST spring-forward.
    in_window = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={"timestamp": "2026-03-08T07:30:00Z"},
    )
    # 2026-03-08 06:30:00Z == 01:30 local before the jump.
    out_window = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={"timestamp": "2026-03-08T06:30:00Z"},
    )

    assert not in_window.allowed
    assert out_window.allowed


def test_token_budget_within_limit_allows():
    evaluator = _budget_allow_evaluator(
        DynamicCondition(
            type=DynamicConditionType.TOKEN_COUNT_PER_WINDOW,
            window="1h",
            limit=100,
        )
    )

    result = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={
            "timestamp": "2026-01-05T10:00:00Z",
            "budget": {"token_count": 80},
        },
    )

    assert result.allowed


def test_token_budget_exceed_limit_denies_via_default():
    evaluator = _budget_allow_evaluator(
        DynamicCondition(
            type=DynamicConditionType.TOKEN_COUNT_PER_WINDOW,
            window="1h",
            limit=100,
        )
    )

    first = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={
            "timestamp": "2026-01-05T10:00:00Z",
            "budget": {"token_count": 60},
        },
    )
    second = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={
            "timestamp": "2026-01-05T10:15:00Z",
            "budget": {"token_count": 50},
        },
    )

    assert first.allowed
    assert not second.allowed


def test_token_budget_boundary_equal_limit_allows():
    evaluator = _budget_allow_evaluator(
        DynamicCondition(
            type=DynamicConditionType.TOKEN_COUNT_PER_WINDOW,
            window="1h",
            limit=100,
        )
    )

    first = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={
            "timestamp": "2026-01-05T10:00:00Z",
            "budget": {"token_count": 40},
        },
    )
    second = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={
            "timestamp": "2026-01-05T10:30:00Z",
            "budget": {"token_count": 60},
        },
    )

    assert first.allowed
    assert second.allowed


def test_cost_budget_window_rollover_resets_accumulator():
    evaluator = _budget_allow_evaluator(
        DynamicCondition(
            type=DynamicConditionType.COST_PER_WINDOW,
            window="1h",
            limit=10,
        )
    )

    first = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={
            "timestamp": "2026-01-05T10:00:00Z",
            "budget": {"cost": 8},
        },
    )
    second = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={
            "timestamp": "2026-01-05T10:20:00Z",
            "budget": {"cost": 5},
        },
    )
    third = evaluator.evaluate(
        {"action_type": "tool_call"},
        dynamic_context={
            "timestamp": "2026-01-05T11:00:00Z",
            "budget": {"cost": 3},
        },
    )

    assert first.allowed
    assert not second.allowed
    assert third.allowed
