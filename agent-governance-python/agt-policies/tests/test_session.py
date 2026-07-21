# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for native adapter session orchestration."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Literal

import pytest

from agt.policies import (
    AdapterManifestContract,
    AdapterRuntimeSession,
    AgtManifest,
    PolicyEvaluation,
)


class _Runtime:
    def __init__(
        self,
        *,
        verdict: Literal[
            "allow", "warn", "deny", "escalate", "transform"
        ] = "allow",
        manifest: AgtManifest | None = None,
        fail: bool = False,
    ) -> None:
        self.verdict = verdict
        self.manifest = manifest
        self.fail = fail
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False
        self.lock = threading.Lock()

    def evaluate(
        self, intervention_point: str, snapshot: dict[str, Any]
    ) -> PolicyEvaluation:
        with self.lock:
            self.calls.append((intervention_point, snapshot))
        if self.fail:
            raise RuntimeError("dispatcher failed")
        return PolicyEvaluation(verdict=self.verdict)

    def close(self) -> None:
        self.closed = True


def _manifest() -> AgtManifest:
    return AgtManifest.model_validate(
        {
            "agent_control_specification_version": "0.3.1-beta",
            "policies": {"p": {"type": "test"}},
            "intervention_points": {
                "pre_tool_call": {
                    "policy_target": "$.tool_call.args",
                    "policy": {"id": "p"},
                }
            },
        }
    )


def test_pre_tool_attempt_is_charged_even_when_denied() -> None:
    runtime = _Runtime(verdict="deny")
    session = AdapterRuntimeSession(runtime, agent_id="bot", session_id="s-1")

    result = session.evaluate_pre_tool_call(tool_name="lookup", args={})

    assert result.verdict == "deny"
    assert runtime.calls[0][1]["envelope"]["budgets"]["tool_call_count"] == 0
    assert session.builder.tool_call_count == 1


def test_pre_tool_attempt_is_charged_when_runtime_raises() -> None:
    runtime = _Runtime(fail=True)
    session = AdapterRuntimeSession(runtime, agent_id="bot", session_id="s-1")

    with pytest.raises(RuntimeError, match="dispatcher failed"):
        session.evaluate_pre_tool_call(tool_name="lookup", args={})

    assert session.builder.tool_call_count == 1


def test_concurrent_attempts_reserve_distinct_budget_slots() -> None:
    runtime = _Runtime()
    session = AdapterRuntimeSession(runtime, agent_id="bot", session_id="s-1")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(
            pool.map(
                lambda index: session.evaluate_pre_tool_call(
                    tool_name="lookup", args={"index": index}
                ),
                range(16),
            )
        )

    observed = sorted(
        snapshot["envelope"]["budgets"]["tool_call_count"]
        for _, snapshot in runtime.calls
    )
    assert observed == list(range(16))
    assert session.builder.tool_call_count == 16


def test_post_model_usage_is_charged_after_evaluation() -> None:
    runtime = _Runtime()
    session = AdapterRuntimeSession(runtime, agent_id="bot", session_id="s-1")

    session.evaluate_post_model_call(
        model_name="model",
        response={"content": "ok"},
        usage={"input_tokens": 3, "output_tokens": 5},
    )

    assert runtime.calls[0][1]["envelope"]["budgets"]["token_count"] == 0
    assert session.builder.token_count == 8


def test_bridge_compatibility_can_disable_native_charging() -> None:
    runtime = _Runtime()
    session = AdapterRuntimeSession(runtime, agent_id="bot", session_id="s-1")

    session.evaluate_pre_tool_call(
        tool_name="lookup", args={}, count_attempt=False
    )
    session.evaluate_post_model_call(
        model_name="model",
        response={"content": "ok"},
        usage={"total_tokens": 10},
        charge_usage=False,
    )

    assert session.builder.tool_call_count == 0
    assert session.builder.token_count == 0


def test_counter_synchronization_never_moves_backwards() -> None:
    session = AdapterRuntimeSession(
        _Runtime(), agent_id="bot", session_id="s-1"
    )
    session.record_usage(tokens=9, tool_calls=3)

    session.synchronize_counters(tool_call_count=1, token_count=4)

    assert session.builder.tool_call_count == 3
    assert session.builder.token_count == 9


def test_public_builder_view_is_read_only() -> None:
    """session.builder exposes counter reads and snapshots but blocks mutation,
    keeping the session the sole writer of budget counters."""
    session = AdapterRuntimeSession(_Runtime(), agent_id="bot", session_id="s-1")
    session.record_usage(tokens=5, tool_calls=2)

    view = session.builder
    # reads and snapshot building still work
    assert view.tool_call_count == 2
    assert view.token_count == 5
    assert view.pre_tool_call(tool_name="lookup", args={})["envelope"]["budgets"][
        "tool_call_count"
    ] == 2

    # every counter mutator is refused
    for mutator in (
        "record_tool_call",
        "record_tokens",
        "record_cost",
        "record_elapsed",
        "reset_budgets",
    ):
        with pytest.raises(AttributeError):
            getattr(view, mutator)
    with pytest.raises(AttributeError):
        view.tool_call_count = 0

    # the real counters are untouched by the blocked attempts
    assert session.builder.tool_call_count == 2


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_record_usage_rejects_non_finite_cost_before_charging(bad: float) -> None:
    """NaN/inf cost must be rejected, not poison the budget counter.

    ``float('nan') < 0`` is False, so a bare sign check accepted NaN; the
    poisoned counter then never satisfies budgets.rego's ``>=`` limit and the
    budget silently never fires (fail open).
    """
    session = AdapterRuntimeSession(_Runtime(), agent_id="bot", session_id="s-1")

    with pytest.raises(ValueError, match="finite"):
        session.record_usage(cost_usd=bad)
    with pytest.raises(ValueError, match="finite"):
        session.synchronize_counters(cost_usd=bad)

    assert session.builder.cost_usd == 0.0


def test_all_intervention_point_helpers_are_reachable() -> None:
    runtime = _Runtime()
    session = AdapterRuntimeSession(runtime, agent_id="bot", session_id="s-1")

    session.evaluate_agent_startup()
    session.evaluate_input(body="hello")
    session.evaluate_pre_model_call(model_name="m", messages=[])
    session.evaluate_post_model_call(
        model_name="m", response={"content": "ok"}, charge_usage=False
    )
    session.evaluate_pre_tool_call(
        tool_name="lookup", args={}, count_attempt=False
    )
    session.evaluate_post_tool_call(
        tool_name="lookup", args={}, result={"ok": True}
    )
    session.evaluate_output(content="done")
    session.evaluate_agent_shutdown()

    assert [point for point, _ in runtime.calls] == [
        "agent_startup",
        "input",
        "pre_model_call",
        "post_model_call",
        "pre_tool_call",
        "post_tool_call",
        "output",
        "agent_shutdown",
    ]


def test_session_preflight_uses_typed_runtime_manifest() -> None:
    runtime = _Runtime(manifest=_manifest())
    contract = AdapterManifestContract(
        name="tool-host",
        required_intervention_points=frozenset({"pre_tool_call"}),
    )

    session = AdapterRuntimeSession(
        runtime,
        agent_id="bot",
        session_id="s-1",
        contract=contract,
    )

    assert session.contract == contract


def test_owned_runtime_is_closed_once() -> None:
    runtime = _Runtime()
    session = AdapterRuntimeSession(
        runtime,
        agent_id="bot",
        session_id="s-1",
        owns_runtime=True,
    )

    session.close()
    session.close()

    assert runtime.closed is True
    with pytest.raises(RuntimeError, match="closed"):
        session.evaluate_input(body="hello")


@pytest.mark.parametrize(
    "usage",
    [
        {"total_tokens": -1},
        {"input_tokens": True},
        {"prompt_tokens": -2, "completion_tokens": 1},
    ],
)
def test_invalid_usage_fails_before_policy_evaluation(usage: dict[str, int]) -> None:
    runtime = _Runtime()
    session = AdapterRuntimeSession(runtime, agent_id="bot", session_id="s-1")

    with pytest.raises(ValueError):
        session.evaluate_post_model_call(
            model_name="model",
            response={"content": "ok"},
            usage=usage,
        )

    assert runtime.calls == []


def test_public_session_import_does_not_require_native_sdk() -> None:
    src_root = Path(__file__).resolve().parents[1] / "src"
    env = {**os.environ, "PYTHONPATH": str(src_root)}
    script = """
import builtins
real_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith("agent_control_specification"):
        raise ImportError("native SDK intentionally unavailable")
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded
from agt.policies import AdapterRuntimeSession
print(AdapterRuntimeSession.__name__)
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "AdapterRuntimeSession"
