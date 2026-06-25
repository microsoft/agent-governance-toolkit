# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for the OPA scenario harness decode/resolve helpers.

These pin the fail-closed contract of :func:`agt._harness.opa_runner`:
a verdict without a recognized ``decision`` resolves to ``deny`` (not the
old silent ``allow`` default), malformed OPA output raises ``RuntimeError``
rather than ``IndexError``/``JSONDecodeError``, and an unresolvable
``policy_target`` path raises a typed ``RuntimeError`` instead of a bare
``KeyError``/``ValueError``. None of this needs the ``opa`` binary.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agt._harness.opa_runner import _decode_verdict, _resolve_path


def _opa_stdout(value: Any) -> str:
    return json.dumps({"result": [{"expressions": [{"value": value}]}]})


def test_decode_valid_decision() -> None:
    result = _decode_verdict(_opa_stdout({"decision": "allow"}))
    assert result.decision == "allow" and result.is_allow


def test_decode_missing_decision_fails_closed() -> None:
    result = _decode_verdict(_opa_stdout({"reason": "whatever"}))
    assert result.decision == "deny"
    assert result.reason == "runtime_error:engine_invalid_verdict"


def test_decode_unrecognized_decision_fails_closed() -> None:
    result = _decode_verdict(_opa_stdout({"decision": "permit"}))
    assert result.decision == "deny"


@pytest.mark.parametrize(
    "stdout",
    ['{"result": []}', '{"result": [{"expressions": []}]}', "{}"],
)
def test_decode_no_usable_result_raises(stdout: str) -> None:
    with pytest.raises(RuntimeError, match="no result|non-object"):
        _decode_verdict(stdout)


def test_decode_non_json_raises_runtime_error() -> None:
    with pytest.raises(RuntimeError, match="non-JSON"):
        _decode_verdict("not json <<<")


@pytest.mark.parametrize("stdout", ["[]", "5", '"a string"', "true", "null"])
def test_decode_non_object_toplevel_fails_closed(stdout: str) -> None:
    # Valid JSON that parses to a non-dict (list/scalar) must fail closed,
    # not raise AttributeError at response.get(...).
    with pytest.raises(RuntimeError, match="non-object top-level"):
        _decode_verdict(stdout)


@pytest.mark.parametrize("stdout", [None, b"{}"])
def test_decode_non_string_stdout_fails_closed(stdout: object) -> None:
    with pytest.raises(RuntimeError, match="no decodable stdout"):
        _decode_verdict(stdout)  # type: ignore[arg-type]


def test_decode_bad_result_labels_raises() -> None:
    with pytest.raises(RuntimeError, match="result_labels"):
        _decode_verdict(_opa_stdout({"decision": "allow", "result_labels": "nope"}))


def test_decode_valid_result_labels_passthrough() -> None:
    result = _decode_verdict(
        _opa_stdout({"decision": "warn", "result_labels": ["a", "b"]})
    )
    assert result.result_labels == ["a", "b"]


def test_resolve_path_valid() -> None:
    snapshot = {"tool_call": {"args": ["x", "y"]}}
    assert _resolve_path(snapshot, "$snap.tool_call.args[1]") == "y"


@pytest.mark.parametrize(
    "path",
    ["$snap.a.missing", "$snap.a[3]", "$snap.a[x]"],
)
def test_resolve_path_unresolvable_raises_runtime_error(path: str) -> None:
    with pytest.raises(RuntimeError, match="does not resolve"):
        _resolve_path({"a": [1]}, path)


def test_resolve_path_unclosed_bracket_raises() -> None:
    with pytest.raises(RuntimeError, match="unclosed"):
        _resolve_path({"a": [1]}, "$snap.a[0")


@pytest.mark.parametrize("path", ["bad_root.key", "x.tool_call", "tool_call"])
def test_resolve_path_unsupported_root_raises_runtime_error(path: str) -> None:
    with pytest.raises(RuntimeError, match="unsupported policy_target path root"):
        _resolve_path({}, path)
