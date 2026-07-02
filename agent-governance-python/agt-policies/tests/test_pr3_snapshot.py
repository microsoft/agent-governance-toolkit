# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for snapshot type-safety hygiene."""

from __future__ import annotations

import pytest

from agt.policies.snapshot import SnapshotBuilder, input_snapshot


@pytest.mark.parametrize("method_name", ["record_tool_call", "record_tokens"])
def test_integer_budget_mutators_reject_bool_without_mutating(method_name: str) -> None:
    builder = SnapshotBuilder(agent_id="bot")

    with pytest.raises(ValueError):
        getattr(builder, method_name)(True)

    assert builder.tool_call_count == 0
    assert builder.token_count == 0


@pytest.mark.parametrize("method_name", ["record_cost", "record_elapsed"])
def test_float_budget_mutators_reject_bool_without_mutating(method_name: str) -> None:
    builder = SnapshotBuilder(agent_id="bot")

    with pytest.raises(ValueError):
        getattr(builder, method_name)(True)

    assert builder.cost_usd == 0.0
    assert builder.elapsed_seconds == 0.0


def test_record_tokens_rejects_negative_without_mutating() -> None:
    builder = SnapshotBuilder(agent_id="bot", token_count=5)

    with pytest.raises(ValueError):
        builder.record_tokens(-1)

    assert builder.token_count == 5


@pytest.mark.parametrize(
    ("kwargs", "field_name"),
    [
        ({"agent_id": "", "body": "hi"}, "agent_id"),
        ({"agent_id": "bot", "body": "hi", "session_id": ""}, "session_id"),
        ({"agent_id": 42, "body": "hi"}, "agent_id"),
        ({"agent_id": "bot", "body": "hi", "session_id": 42}, "session_id"),
    ],
)
def test_module_helper_rejects_invalid_identifier_strings(
    kwargs: dict[str, object], field_name: str
) -> None:
    with pytest.raises(ValueError, match=field_name):
        input_snapshot(**kwargs)


def test_builder_envelope_rejects_empty_intervention_point() -> None:
    builder = SnapshotBuilder(agent_id="bot")

    with pytest.raises(ValueError, match="intervention_point"):
        builder.envelope("")


def test_snapshot_helpers_and_mutators_accept_valid_values() -> None:
    builder = SnapshotBuilder(agent_id="bot", session_id="session-1")

    builder.record_tool_call(2)
    builder.record_tokens(3)
    builder.record_cost(0.25)
    builder.record_elapsed(1.5)

    envelope = builder.envelope("input")
    snap = input_snapshot(agent_id="bot", session_id="session-1", body={"text": "hi"})

    assert envelope["budgets"] == {
        "tool_call_count": 2,
        "token_count": 3,
        "elapsed_seconds": 1.5,
        "cost_usd": 0.25,
    }
    assert snap["envelope"]["agent"]["id"] == "bot"
    assert snap["envelope"]["session"]["id"] == "session-1"
