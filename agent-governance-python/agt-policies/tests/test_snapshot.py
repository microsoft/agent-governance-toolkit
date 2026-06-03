# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for :mod:`agt.policies.snapshot`.

Covers AGT-SNAPSHOT-1.0.md §1 (envelope) and §§2.1-2.8 (per-intervention-
point shapes) for both the module-level helpers and the long-lived
:class:`SnapshotBuilder` class. The tests also assert the back-compat
``agt._harness.snapshot`` shim still serves the helpers so the existing
scenario suite keeps working.
"""

from __future__ import annotations

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


# ── module-level helpers (per-IP shapes) ────────────────────────────


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


# ── SnapshotBuilder class ────────────────────────────────────────────


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


# ── back-compat shim ────────────────────────────────────────────────


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
