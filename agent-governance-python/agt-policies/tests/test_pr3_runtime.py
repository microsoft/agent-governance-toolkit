# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for runtime liveness and manifest hygiene fixes."""

from __future__ import annotations

import asyncio
from pathlib import Path
import threading
import time
from typing import Any

import pytest
import yaml

pytest.importorskip("agent_control_specification")

from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402
from agt.policies import runtime as runtime_module  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: agt_runtime_pr3_test
extends: []
policies:
  test_policy:
    type: custom
    adapter: agt_runtime_test_adapter
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: test_policy
tools:
  lookup:
    clearance: public
"""


class _ScriptedPolicy:
    def __init__(self, verdicts: list[dict[str, Any]]):
        self._verdicts = list(verdicts)

    def evaluate(self, invocation):  # type: ignore[no-untyped-def]
        if not self._verdicts:
            raise AssertionError("ScriptedPolicy ran out of verdicts.")
        return self._verdicts.pop(0)


def _write_manifest(tmp_path: Path, approval: str = "") -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(_MANIFEST + approval, encoding="utf-8")
    return path


def _snapshot() -> dict[str, Any]:
    return SnapshotBuilder(agent_id="bot", session_id="s-1").pre_tool_call(
        tool_name="lookup", args={"q": "x"}
    )


def test_run_sync_timeout_none_inside_running_loop_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runtime_module, "_DEFAULT_INLOOP_TIMEOUT_SECONDS", 0.05, raising=False
    )
    outcome: dict[str, BaseException] = {}

    async def _in_running_loop() -> None:
        awaitable = asyncio.Event().wait()
        runtime_module._run_sync(awaitable)

    def _target() -> None:
        try:
            asyncio.run(_in_running_loop())
        except BaseException as exc:  # noqa: BLE001 - assert propagated failure type
            outcome["error"] = exc

    thread = threading.Thread(target=_target, name="run-sync-regression", daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(1.0)
    elapsed = time.monotonic() - started

    assert not thread.is_alive(), "_run_sync(timeout=None) hung inside a running loop"
    assert elapsed < 1.0
    assert isinstance(outcome.get("error"), TimeoutError)


def test_resolver_event_loop_binding_error_fails_closed_promptly(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        raise RuntimeError("Future attached to a different loop")

    runtime = AgtRuntime(
        _write_manifest(tmp_path, "approval:\n  timeout_seconds: 5\n"),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )
    outcome: dict[str, EvaluationResult | BaseException] = {}

    def _target() -> None:
        try:
            outcome["result"] = runtime.evaluate_intervention_point(
                "pre_tool_call", _snapshot()
            )
        except BaseException as exc:  # noqa: BLE001 - surfaced for assertion
            outcome["error"] = exc

    thread = threading.Thread(target=_target, name="binding-error-regression", daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(1.0)
    elapsed = time.monotonic() - started

    assert not thread.is_alive(), "resolver binding error waited for approval timeout"
    assert elapsed < 1.0
    assert "error" not in outcome
    result = outcome["result"]
    assert isinstance(result, EvaluationResult)
    assert result.verdict == "deny"
    assert result.allowed is False
    assert result.reason == "runtime_error:approval_timeout"


def test_manifest_text_dead_helper_removed_and_yaml_errors_wrapped(
    tmp_path: Path,
) -> None:
    assert getattr(runtime_module, "_approval_settings_from_manifest_text", None) is None

    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text("approval: [unterminated\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid manifest YAML") as exc_info:
        AgtRuntime(
            manifest_path,
            policy_dispatcher=_ScriptedPolicy([{"decision": "allow"}]),
        )

    assert isinstance(exc_info.value.__cause__, yaml.YAMLError)


def test_runtime_context_manager_cleans_resolution_bundle(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    action_path = root / "agent.py"
    action_path.write_text("# agent\n", encoding="utf-8")
    (root / "governance.yaml").write_text(
        """
rules: []
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: agt_legacy_rules
tools:
  lookup:
    clearance: public
""",
        encoding="utf-8",
    )

    with AgtRuntime(action_path, resolution_root=root) as runtime:
        bundle_dir = Path(runtime._resolution_bundle_dir.name)  # type: ignore[union-attr]
        assert bundle_dir.exists()

    assert not bundle_dir.exists()
