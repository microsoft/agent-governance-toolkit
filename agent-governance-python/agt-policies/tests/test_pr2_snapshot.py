# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for snapshot deep-copy determinism."""

from __future__ import annotations

import json

from agt.policies import pre_model_call_snapshot, pre_tool_call_snapshot


def _canonical_snapshot_bytes(snapshot: dict) -> bytes:
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")


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
