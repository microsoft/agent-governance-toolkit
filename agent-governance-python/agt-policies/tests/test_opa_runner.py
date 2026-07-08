# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the OPA runner harness: verdict decoding and error-path hardening."""

from __future__ import annotations

from pathlib import Path
import sys
import pytest
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agt._harness.opa_runner import _decode_opa_verdict  # noqa: E402
from agt._harness import opa_runner  # noqa: E402
from agt._harness.opa_runner import _resolve_path  # noqa: E402


_TESTS_DIR = Path(__file__).resolve().parent

def _opa_response(verdict: dict[str, object]) -> dict[str, object]:
    return {"result": [{"expressions": [{"value": verdict}]}]}


def _stub_run_scenario_manifest(
    monkeypatch: pytest.MonkeyPatch,
    intervention_point: str,
    ip_config: dict[str, object],
) -> None:
    def resolve_manifest_stub(*_args: object, **_kwargs: object) -> dict[str, Any]:
        return {
            "intervention_points": {intervention_point: ip_config},
            "policies": {
                "agt_legacy_rules": {
                    "bundle": str(_TESTS_DIR),
                    "query": "data.agt.test.verdict",
                }
            },
            "tools": {},
        }

    monkeypatch.setattr(opa_runner.shutil, "which", lambda _name: "/usr/bin/opa")
    monkeypatch.setattr(opa_runner, "_find_stock_rego_root", lambda: _TESTS_DIR)
    monkeypatch.setattr(opa_runner, "resolve_manifest", resolve_manifest_stub)


def test_decode_missing_decision_fails_closed() -> None:
    verdict = {"reason": "policy:missing_decision"}

    result = _decode_opa_verdict(_opa_response(verdict))

    assert result.decision == "deny"
    assert result.reason == "runtime_error:engine_invalid_verdict"
    assert result.message == (
        "opa returned verdict without recognized decision: "
        "{'reason': 'policy:missing_decision'}"
    )
    assert result.raw == verdict


def test_decode_unknown_decision_fails_closed() -> None:
    verdict = {"decision": "maybe", "reason": "policy:unknown_decision"}

    result = _decode_opa_verdict(_opa_response(verdict))

    assert result.decision == "deny"
    assert result.reason == "runtime_error:engine_invalid_verdict"
    assert result.message == (
        "opa returned verdict without recognized decision: "
        "{'decision': 'maybe', 'reason': 'policy:unknown_decision'}"
    )
    assert result.raw == verdict


def test_decode_empty_result_raises_runtime_error() -> None:
    with pytest.raises(RuntimeError, match="opa eval produced no result"):
        _decode_opa_verdict({"result": []})


def test_decode_valid_deny_verdict_is_preserved() -> None:
    verdict = {
        "decision": "deny",
        "reason": "policy:blocked",
        "message": "blocked by policy",
        "evidence": {"rule": "deny_tools"},
        "result_labels": ["blocked"],
    }

    result = _decode_opa_verdict(_opa_response(verdict))

    assert result.decision == "deny"
    assert result.reason == "policy:blocked"
    assert result.message == "blocked by policy"
    assert result.evidence == {"rule": "deny_tools"}
    assert result.result_labels == ["blocked"]
    assert result.raw == verdict


def test_decode_valid_allow_verdict_is_preserved() -> None:
    verdict = {
        "decision": "allow",
        "reason": "policy:ok",
        "message": "allowed by policy",
    }

    result = _decode_opa_verdict(_opa_response(verdict))

    assert result.decision == "allow"
    assert result.reason == "policy:ok"
    assert result.message == "allowed by policy"
    assert result.raw == verdict


def test_run_scenario_non_json_stdout_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_run_scenario_manifest(
        monkeypatch,
        "pre_prompt",
        {"policy_target": "$"},
    )

    def run_stub(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="not-json", stderr="")

    monkeypatch.setattr(opa_runner.subprocess, "run", run_stub)

    with pytest.raises(RuntimeError) as exc_info:
        opa_runner.run_scenario(
            workspace_root=_TESTS_DIR,
            governance_yaml={},
            intervention_point="pre_prompt",
            snapshot={"prompt": "hello"},
        )

    assert str(exc_info.value) == "opa produced non-JSON output: 'not-json'"


@pytest.mark.parametrize(
    ("path", "snapshot"),
    [
        ("$snap.missing", {"present": "value"}),
        ("$snap.items[2]", {"items": ["first"]}),
        ("$snap.scalar.child", {"scalar": 42}),
        ("$snap.items[bad]", {"items": ["first"]}),
        ("$snap.items[0", {"items": ["first"]}),
    ],
)
def test_resolve_path_failures_raise_runtime_error(
    path: str,
    snapshot: dict[str, object],
) -> None:
    with pytest.raises(RuntimeError) as exc_info:
        _resolve_path(snapshot, path)

    assert (
        str(exc_info.value)
        == f"policy_target path {path!r} does not resolve in snapshot"
    )


def test_run_scenario_missing_tool_name_from_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_run_scenario_manifest(
        monkeypatch,
        "pre_tool_call",
        {"policy_target": "$"},
    )

    def run_stub(*_args: object, **_kwargs: object) -> SimpleNamespace:
        raise AssertionError("subprocess.run should not be called")

    monkeypatch.setattr(opa_runner.subprocess, "run", run_stub)

    with pytest.raises(RuntimeError) as exc_info:
        opa_runner.run_scenario(
            workspace_root=_TESTS_DIR,
            governance_yaml={},
            intervention_point="pre_tool_call",
            snapshot={"tool": {"name": "search"}},
        )

    assert str(exc_info.value) == (
        "intervention point 'pre_tool_call' is missing a string 'tool_name_from'"
    )


@pytest.mark.parametrize("labels", ["x", [1], ["ok", 2]])
def test_decode_opa_verdict_rejects_invalid_result_labels(labels: object) -> None:
    verdict = {"decision": "allow", "result_labels": labels}

    with pytest.raises(RuntimeError) as exc_info:
        _decode_opa_verdict(_opa_response(verdict))

    assert str(exc_info.value) == f"opa returned non-list[str] result_labels: {labels!r}"


@pytest.mark.parametrize("labels", [None, ["alpha", "beta"]])
def test_decode_opa_verdict_accepts_valid_result_labels(
    labels: list[str] | None,
) -> None:
    verdict = {"decision": "allow", "result_labels": labels}

    result = _decode_opa_verdict(_opa_response(verdict))

    assert result.result_labels == labels
