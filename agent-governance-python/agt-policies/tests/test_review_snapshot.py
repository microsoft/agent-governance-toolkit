# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deep-review regression tests for AGT snapshot determinism."""

from __future__ import annotations

import json

import pytest

from agt.policies import (
    SnapshotBuilder,
    agent_shutdown_snapshot,
    post_tool_call_snapshot,
    pre_model_call_snapshot,
)


def _canonical_snapshot_bytes(snapshot: dict) -> bytes:
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")


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
