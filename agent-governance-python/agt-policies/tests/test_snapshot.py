# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for policies.snapshot: shapes, finite-number validation, deep-copy determinism."""

from __future__ import annotations

import json

import pytest

from agt._harness import snapshot as harness_snapshot
from agt.policies import (
    SnapshotBuilder,
    agent_shutdown_snapshot,
    agent_startup_snapshot,
    input_snapshot,
    output_snapshot,
    post_model_call_snapshot,
    post_tool_call_snapshot,
    pre_model_call_snapshot,
    pre_tool_call_snapshot,
)
from agt.policies import snapshot as snapshot_module
from agt.policies.snapshot import _validate_budget_counter


def _assert_envelope(envelope: dict, *, intervention_point: str) -> None:
    assert envelope["intervention_point"] == intervention_point
    assert "agent" in envelope and envelope["agent"]["id"] == "bot"
    assert envelope["agent"]["version"] == "1.0.0"
    assert envelope["agent"]["name"] == "bot"
    assert "session" in envelope and envelope["session"]["id"] == "session-1"
    assert "started_at" in envelope["session"]
    assert "timestamp" in envelope
    assert envelope["budgets"] == {
        "tool_call_count": 0,
        "token_count": 0,
        "elapsed_seconds": 0.0,
        "cost_usd": 0.0,
    }


def _canonical_snapshot_bytes(snapshot: dict) -> bytes:
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")


def test_input_snapshot_shape() -> None:
    snap = input_snapshot(
        agent_id="bot",
        body={"text": "hi"},
        source="user",
        headers={"x-trace": "abc"},
        source_labels=["public"],
    )
    _assert_envelope(snap["envelope"], intervention_point="input")
    assert snap["input"] == {
        "body": {"text": "hi"},
        "source": "user",
        "headers": {"x-trace": "abc"},
        "ifc": {"source_labels": ["public"]},
    }


def test_pre_model_call_snapshot_shape() -> None:
    snap = pre_model_call_snapshot(
        agent_id="bot",
        model_name="gpt-x",
        messages=[{"role": "user", "content": "hi"}],
        tools=[{"name": "search"}],
        request_id="r-1",
        model_vendor="openai",
        model_params={"temperature": 0.7},
    )
    _assert_envelope(snap["envelope"], intervention_point="pre_model_call")
    assert snap["model"] == {"name": "gpt-x", "vendor": "openai", "params": {"temperature": 0.7}}
    assert snap["messages"] == [{"role": "user", "content": "hi"}]
    assert snap["tools"] == [{"name": "search"}]
    assert snap["request_id"] == "r-1"


def test_post_model_call_snapshot_shape() -> None:
    snap = post_model_call_snapshot(
        agent_id="bot",
        model_name="gpt-x",
        response={"content": "ok"},
        usage={"prompt_tokens": 12, "completion_tokens": 3},
        request_id="r-2",
    )
    _assert_envelope(snap["envelope"], intervention_point="post_model_call")
    assert snap["model"] == {"name": "gpt-x", "vendor": "test"}
    assert snap["response"] == {"content": "ok"}
    assert snap["usage"] == {"prompt_tokens": 12, "completion_tokens": 3}
    assert snap["request_id"] == "r-2"


def test_pre_tool_call_snapshot_with_content_hash() -> None:
    snap = pre_tool_call_snapshot(
        agent_id="bot",
        tool_name="lookup",
        args={"q": "x"},
        call_id="call-9",
        content_hash="sha256:abc",
    )
    _assert_envelope(snap["envelope"], intervention_point="pre_tool_call")
    assert snap["tool_call"] == {
        "name": "lookup",
        "args": {"q": "x"},
        "id": "call-9",
        "content_hash": "sha256:abc",
    }


def test_pre_tool_call_snapshot_omits_content_hash_when_absent() -> None:
    snap = pre_tool_call_snapshot(agent_id="bot", tool_name="t", args={})
    assert "content_hash" not in snap["tool_call"]


def test_post_tool_call_snapshot_shape() -> None:
    snap = post_tool_call_snapshot(
        agent_id="bot",
        tool_name="lookup",
        args={"q": "x"},
        result={"hits": 3},
        duration_ms=12.5,
    )
    _assert_envelope(snap["envelope"], intervention_point="post_tool_call")
    assert snap["tool_call"] == {"name": "lookup", "args": {"q": "x"}, "id": "call-1"}
    assert snap["tool_result"] == {"value": {"hits": 3}, "error": None, "duration_ms": 12.5}


def test_output_snapshot_shape() -> None:
    snap = output_snapshot(
        agent_id="bot",
        content="hello",
        message_chain=[{"role": "assistant", "content": "hello"}],
        result_labels=["confidential"],
    )
    _assert_envelope(snap["envelope"], intervention_point="output")
    assert snap["response"] == {"content": "hello", "ifc": {"result_labels": ["confidential"]}}
    assert snap["message_chain"] == [{"role": "assistant", "content": "hello"}]


def test_agent_startup_snapshot_shape() -> None:
    snap = agent_startup_snapshot(
        agent_id="bot",
        capabilities=["chat", "tools"],
        model_name="gpt-x",
        tools_registered=["search"],
    )
    _assert_envelope(snap["envelope"], intervention_point="agent_startup")
    assert snap["agent_init"] == {
        "capabilities": ["chat", "tools"],
        "model": {"name": "gpt-x", "vendor": "test"},
        "tools_registered": ["search"],
    }


def test_agent_shutdown_snapshot_shape() -> None:
    snap = agent_shutdown_snapshot(
        agent_id="bot",
        tool_calls=5,
        tokens=200,
        errors=1,
        duration_seconds=12.3,
    )
    _assert_envelope(snap["envelope"], intervention_point="agent_shutdown")
    assert snap["summary"] == {
        "tool_calls": 5,
        "tokens": 200,
        "errors": 1,
        "duration_seconds": 12.3,
    }


def test_module_helper_includes_tenant_when_given() -> None:
    snap = input_snapshot(agent_id="bot", body="hi", tenant_id="tenant-a")
    envelope = snap["envelope"]
    assert envelope["tenant"] == {"id": "tenant-a", "name": "tenant-a"}


def test_module_helper_skips_tenant_when_absent() -> None:
    snap = input_snapshot(agent_id="bot", body="hi")
    assert "tenant" not in snap["envelope"]


def test_module_helper_rejects_malformed_budget_counters() -> None:
    with pytest.raises(ValueError, match="token_count"):
        pre_tool_call_snapshot(
            agent_id="bot", tool_name="lookup", args={}, token_count="999999"
        )
    with pytest.raises(ValueError, match="elapsed_seconds"):
        input_snapshot(agent_id="bot", body="hi", elapsed_seconds=None)
    with pytest.raises(ValueError, match="tool_call_count"):
        input_snapshot(agent_id="bot", body="hi", tool_call_count=True)


def test_builder_validates_agent_and_session_ids() -> None:
    with pytest.raises(ValueError):
        SnapshotBuilder(agent_id="", session_id="s")
    with pytest.raises(ValueError):
        SnapshotBuilder(agent_id="bot", session_id="")
    with pytest.raises(ValueError):
        SnapshotBuilder(agent_id="bot", token_count=-1)
    with pytest.raises(ValueError):
        SnapshotBuilder(agent_id="bot", token_count="999999")
    with pytest.raises(ValueError):
        SnapshotBuilder(agent_id="bot", cost_usd=-0.01)


def test_builder_emits_each_intervention_point_with_running_budgets() -> None:
    b = SnapshotBuilder(
        agent_id="bot",
        session_id="s-1",
        tool_call_count=3,
        token_count=120,
        elapsed_seconds=4.5,
        cost_usd=0.02,
    )

    pre_tool = b.pre_tool_call(tool_name="lookup", args={"q": "x"})
    assert pre_tool["envelope"]["budgets"] == {
        "tool_call_count": 3,
        "token_count": 120,
        "elapsed_seconds": 4.5,
        "cost_usd": 0.02,
    }
    assert pre_tool["envelope"]["intervention_point"] == "pre_tool_call"
    assert pre_tool["tool_call"]["name"] == "lookup"

    post_tool = b.post_tool_call(tool_name="lookup", args={"q": "x"}, result={"ok": True})
    assert post_tool["envelope"]["intervention_point"] == "post_tool_call"
    assert post_tool["tool_result"]["value"] == {"ok": True}

    input_snap = b.input(body="hi", source_labels=("internal",))
    assert input_snap["input"]["ifc"]["source_labels"] == ["internal"]

    pre_model = b.pre_model_call(model_name="gpt-x", messages=[{"role": "user", "content": "hi"}])
    assert pre_model["envelope"]["intervention_point"] == "pre_model_call"
    assert pre_model["model"]["name"] == "gpt-x"

    post_model = b.post_model_call(model_name="gpt-x", response={"content": "ok"})
    assert post_model["envelope"]["intervention_point"] == "post_model_call"

    out = b.output(content="bye")
    assert out["envelope"]["intervention_point"] == "output"

    startup = b.agent_startup(capabilities=["chat"], model_name="gpt-x")
    assert startup["envelope"]["intervention_point"] == "agent_startup"

    shutdown = b.agent_shutdown(errors=0)
    assert shutdown["envelope"]["intervention_point"] == "agent_shutdown"
    # Defaults pull from running budgets.
    assert shutdown["summary"]["tool_calls"] == 3
    assert shutdown["summary"]["tokens"] == 120
    assert shutdown["summary"]["duration_seconds"] == 4.5


def test_builder_mutators_advance_running_budgets() -> None:
    b = SnapshotBuilder(agent_id="bot")

    b.record_tool_call()
    b.record_tool_call(2)
    b.record_tokens(50)
    b.record_tokens(75)
    b.record_cost(0.5)
    b.record_cost(0.125)
    b.record_elapsed(1.5)
    b.record_elapsed(2.0)

    assert b.tool_call_count == 3
    assert b.token_count == 125
    assert b.cost_usd == pytest.approx(0.625)
    assert b.elapsed_seconds == pytest.approx(3.5)

    snap = b.pre_tool_call(tool_name="t", args={})
    assert snap["envelope"]["budgets"] == {
        "tool_call_count": 3,
        "token_count": 125,
        "elapsed_seconds": pytest.approx(3.5),
        "cost_usd": pytest.approx(0.625),
    }


def test_builder_mutators_reject_negative_arguments() -> None:
    b = SnapshotBuilder(agent_id="bot")
    with pytest.raises(ValueError):
        b.record_tool_call(-1)
    with pytest.raises(ValueError):
        b.record_tokens(-2)
    with pytest.raises(ValueError):
        b.record_cost(-0.01)
    with pytest.raises(ValueError):
        b.record_elapsed(-0.5)


def test_builder_reset_budgets_zeros_counters() -> None:
    b = SnapshotBuilder(
        agent_id="bot", tool_call_count=4, token_count=99, elapsed_seconds=1.0, cost_usd=0.3
    )
    b.reset_budgets()
    assert b.tool_call_count == 0
    assert b.token_count == 0
    assert b.elapsed_seconds == 0.0
    assert b.cost_usd == 0.0


def test_builder_tenant_inclusion() -> None:
    b = SnapshotBuilder(agent_id="bot", tenant_id="tenant-x")
    env = b.envelope("input")
    assert env["tenant"] == {"id": "tenant-x", "name": "tenant-x"}

    snap = b.input(body="hi")
    assert snap["envelope"]["tenant"] == {"id": "tenant-x", "name": "tenant-x"}


def test_builder_omits_tenant_when_absent() -> None:
    b = SnapshotBuilder(agent_id="bot")
    snap = b.input(body="hi")
    assert "tenant" not in snap["envelope"]


def test_builder_trace_correlation_fields_pass_through() -> None:
    b = SnapshotBuilder(agent_id="bot", trace_id="t-1", span_id="s-1")
    snap = b.input(body="hi")
    assert snap["envelope"]["trace"] == {"trace_id": "t-1", "span_id": "s-1"}


def test_builder_envelope_method_emits_bare_envelope() -> None:
    b = SnapshotBuilder(agent_id="bot", token_count=10)
    env = b.envelope("custom")
    assert env["intervention_point"] == "custom"
    assert env["budgets"]["token_count"] == 10


def test_builder_record_tool_call_then_post_tool_call_snapshot() -> None:
    # End-to-end mutation: post a tool call, advance budgets, see new
    # value on the next snapshot. Matches the v4 ExecutionContext.call_count
    # += 1 flow.
    b = SnapshotBuilder(agent_id="bot")
    first = b.pre_tool_call(tool_name="t", args={})
    assert first["envelope"]["budgets"]["tool_call_count"] == 0
    b.record_tool_call()
    second = b.pre_tool_call(tool_name="t", args={})
    assert second["envelope"]["budgets"]["tool_call_count"] == 1


def test_builder_agent_shutdown_overrides_take_precedence_over_budgets() -> None:
    b = SnapshotBuilder(agent_id="bot", tool_call_count=2, token_count=10)
    snap = b.agent_shutdown(tool_calls=99, tokens=999, duration_seconds=1.5)
    assert snap["summary"] == {
        "tool_calls": 99,
        "tokens": 999,
        "errors": 0,
        "duration_seconds": 1.5,
    }


def test_harness_shim_reexports_module_helpers() -> None:
    # Existing scenario tests import from agt._harness.snapshot. The
    # shim must keep serving the same names so they don't break.
    assert harness_snapshot.input_snapshot is snapshot_module.input_snapshot
    assert harness_snapshot.pre_tool_call_snapshot is snapshot_module.pre_tool_call_snapshot
    assert harness_snapshot.post_tool_call_snapshot is snapshot_module.post_tool_call_snapshot
    assert harness_snapshot.pre_model_call_snapshot is snapshot_module.pre_model_call_snapshot
    assert harness_snapshot.post_model_call_snapshot is snapshot_module.post_model_call_snapshot
    assert harness_snapshot.output_snapshot is snapshot_module.output_snapshot


def test_harness_shim_reexports_builder_class() -> None:
    assert harness_snapshot.SnapshotBuilder is SnapshotBuilder


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_validate_budget_counter_rejects_non_finite_cost(value: float) -> None:
    with pytest.raises(ValueError, match="cost_usd"):
        _validate_budget_counter("cost_usd", value)


def test_record_cost_rejects_infinity_without_mutating() -> None:
    builder = SnapshotBuilder(agent_id="bot", cost_usd=1.25)

    with pytest.raises(ValueError, match="usd"):
        builder.record_cost(float("inf"))

    assert builder.cost_usd == pytest.approx(1.25)


def test_record_elapsed_rejects_nan_without_mutating() -> None:
    builder = SnapshotBuilder(agent_id="bot", elapsed_seconds=2.5)

    with pytest.raises(ValueError, match="seconds"):
        builder.record_elapsed(float("nan"))

    assert builder.elapsed_seconds == pytest.approx(2.5)


def test_envelope_rejects_non_finite_float_budget() -> None:
    with pytest.raises(ValueError, match="elapsed_seconds"):
        input_snapshot(agent_id="bot", body="hi", elapsed_seconds=float("inf"))


def test_finite_cost_and_elapsed_serialize_without_non_standard_floats() -> None:
    builder = SnapshotBuilder(agent_id="bot")

    builder.record_cost(0.25)
    builder.record_elapsed(1.5)

    envelope = builder.envelope("input")
    encoded = json.dumps(envelope)

    assert "NaN" not in encoded
    assert "Infinity" not in encoded
    assert json.loads(encoded)["budgets"] == {
        "tool_call_count": 0,
        "token_count": 0,
        "elapsed_seconds": 1.5,
        "cost_usd": 0.25,
    }


def test_pre_model_call_snapshot_deep_copies_messages() -> None:
    messages = [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
    snap = pre_model_call_snapshot(agent_id="bot", model_name="gpt-x", messages=messages)
    before_bytes = _canonical_snapshot_bytes(snap)

    messages[0]["content"][0]["text"] = "mutated"
    messages.append({"role": "assistant", "content": "late"})

    assert snap["messages"] == [
        {"role": "user", "content": [{"type": "text", "text": "hello"}]}
    ]
    assert _canonical_snapshot_bytes(snap) == before_bytes


def test_pre_tool_call_snapshot_deep_copies_args() -> None:
    args = {"query": {"text": "hello", "filters": ["safe"]}}
    snap = pre_tool_call_snapshot(agent_id="bot", tool_name="search", args=args)
    before_bytes = _canonical_snapshot_bytes(snap)

    args["query"]["filters"].append("mutated")
    args["late"] = True

    assert snap["tool_call"]["args"] == {"query": {"text": "hello", "filters": ["safe"]}}
    assert _canonical_snapshot_bytes(snap) == before_bytes


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


def test_reviewed_mutable_inputs_are_deep_copied_for_stable_snapshot_bytes() -> None:
    model_params = {"nested": {"k": 1}}
    model_snap = pre_model_call_snapshot(
        agent_id="a",
        session_id="s",
        model_name="m",
        model_vendor="v",
        messages=[],
        model_params=model_params,
    )

    headers = {"nested": {"h": ["original"]}}
    source_labels = [{"label": ["internal"]}]
    capabilities = [{"capability": ["chat"]}]
    tools_registered = [{"tool": ["search"]}]
    result = {"nested": {"value": ["ok"]}}
    error = {"nested": {"code": [1]}}
    result_labels = [{"label": ["safe"]}]
    builder = SnapshotBuilder(agent_id="a", session_id="s")
    input_snap = builder.input(body={"text": "hi"}, headers=headers, source_labels=source_labels)
    startup_snap = builder.agent_startup(
        capabilities=capabilities,
        tools_registered=tools_registered,
    )
    tool_snap = builder.post_tool_call(tool_name="lookup", args={}, result=result, error=error)
    output_snap = builder.output(content="done", result_labels=result_labels)

    snapshots = [model_snap, input_snap, startup_snap, tool_snap, output_snap]
    before_bytes = [_canonical_snapshot_bytes(snapshot) for snapshot in snapshots]

    model_params["nested"]["k"] = 999
    headers["nested"]["h"].append("mutated")
    source_labels[0]["label"].append("mutated")
    capabilities[0]["capability"].append("mutated")
    tools_registered[0]["tool"].append("mutated")
    result["nested"]["value"].append("mutated")
    error["nested"]["code"].append(999)
    result_labels[0]["label"].append("mutated")

    assert model_snap["model"]["params"]["nested"]["k"] == 1
    assert input_snap["input"]["headers"] == {"nested": {"h": ["original"]}}
    assert input_snap["input"]["ifc"]["source_labels"] == [{"label": ["internal"]}]
    assert startup_snap["agent_init"]["capabilities"] == [{"capability": ["chat"]}]
    assert startup_snap["agent_init"]["tools_registered"] == [{"tool": ["search"]}]
    assert tool_snap["tool_result"]["value"] == {"nested": {"value": ["ok"]}}
    assert tool_snap["tool_result"]["error"] == {"nested": {"code": [1]}}
    assert output_snap["response"]["ifc"]["result_labels"] == [{"label": ["safe"]}]
    assert [_canonical_snapshot_bytes(snapshot) for snapshot in snapshots] == before_bytes


@pytest.mark.parametrize("duration_ms", [float("nan"), float("inf"), float("-inf")])
def test_post_tool_call_snapshot_rejects_non_finite_duration_ms(duration_ms: float) -> None:
    with pytest.raises(ValueError, match="duration_ms"):
        post_tool_call_snapshot(
            agent_id="a",
            tool_name="lookup",
            args={},
            result={"ok": True},
            duration_ms=duration_ms,
        )


@pytest.mark.parametrize(
    ("kwargs", "field_name"),
    [
        ({"tool_calls": float("nan")}, "tool_calls"),
        ({"tokens": float("inf")}, "tokens"),
        ({"errors": float("-inf")}, "errors"),
        ({"duration_seconds": float("nan")}, "duration_seconds"),
    ],
)
def test_agent_shutdown_snapshot_rejects_non_finite_numeric_fields(
    kwargs: dict[str, float], field_name: str
) -> None:
    with pytest.raises(ValueError, match=field_name):
        agent_shutdown_snapshot(agent_id="a", **kwargs)

    snap = post_tool_call_snapshot(
        agent_id="a",
        tool_name="lookup",
        args={"q": "x"},
        result={"ok": True},
        duration_ms=12.5,
    )
    encoded = json.dumps(snap)
    assert "NaN" not in encoded
    assert "Infinity" not in encoded
    assert json.loads(encoded)["tool_result"]["duration_ms"] == 12.5
