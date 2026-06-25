# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for agt.manifest_resolution.build robustness fixes.

Pins the fail-open / contract-leak fixes: an invalid ``regex`` operator value
becomes a fail-closed deny instead of an OPA eval error that defaults to allow;
YAML-native non-JSON scalars (dates) no longer crash ``json.dumps``; and IO
errors map to ``ResolutionError`` rather than escaping the documented contract.
"""

from __future__ import annotations

import datetime
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from agt.manifest_resolution.build import (
    _is_re2_compatible_regex,
    _load_yaml,
    _materialize_rego_bundle,
    _rego_op_clause,
    _render_rego,
)
from agt.manifest_resolution.errors import ResolutionError


@pytest.fixture
def opa() -> str:
    path = shutil.which("opa") or str(Path.home() / ".local" / "bin" / "opa")
    if not Path(path).exists():
        pytest.skip("opa binary required for RE2 / verdict checks")
    return path


def _opa_verdict(rego_body: str, snapshot: dict[str, Any], opa: str) -> dict | None:
    with tempfile.TemporaryDirectory() as d:
        rego = Path(d) / "agt_legacy.rego"
        rego.write_text(rego_body, encoding="utf-8")
        proc = subprocess.run(
            [opa, "eval", "--stdin-input", "--data", str(rego),
             "--format", "json", "data.agt.legacy.verdict"],
            input=json.dumps({"snapshot": snapshot}),
            capture_output=True,
            text=True,
            timeout=10,
        )
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, ValueError):
        return None


# ── regex validation (fail-open fix) ──────────────────────────────────────


@pytest.mark.parametrize(
    "value, ok",
    [
        ("secret", True),
        ("a.*b", True),
        ("(", False),                  # invalid syntax
        (r"(a)\1", False),             # numeric backreference
        ("(?=secret)", False),          # look-ahead
        ("(?<=secret)", False),         # look-behind
        ("(?P<n>x)(?P=n)", False),     # named backreference (Python-valid)
        ("(?>x)", False),              # atomic group (Python-valid)
        ("(x)(?(1)y|z)", False),       # conditional (Python-valid)
        (123, False),                  # non-string
        (None, False),
    ],
)
def test_is_re2_compatible_regex(value: Any, ok: bool) -> None:
    assert _is_re2_compatible_regex(value) is ok


def test_invalid_regex_deny_message_names_the_pattern_not_the_operator() -> None:
    # The fail-closed deny for an invalid regex must not mislabel the cause as
    # an "unsupported operator" (the operator IS supported; the value is bad).
    rego = _render_rego(
        [{
            "name": "bad",
            "action": "deny",
            "condition": {
                "field": "tool_call.args",
                "operator": "regex",
                "value": "(?=secret)",
            },
        }]
    )
    assert "regex value" in rego
    assert "unsupported operator 'regex'" not in rego


def test_rego_op_clause_invalid_regex_returns_none() -> None:
    assert _rego_op_clause("regex", "input.snapshot.x", "(?=secret)") is None


def test_rego_op_clause_valid_regex_renders() -> None:
    clause = _rego_op_clause("regex", "input.snapshot.x", "secret")
    assert clause is not None and "regex.match" in clause


def test_invalid_regex_rule_is_failclosed_deny_under_opa(opa: str) -> None:
    rego = _render_rego(
        [{
            "name": "bad",
            "action": "deny",
            "condition": {
                "field": "tool_call.args",
                "operator": "regex",
                "value": "(?=secret)",  # RE2 rejects -> old code failed open
            },
        }]
    )
    verdict = _opa_verdict(rego, {"tool_call": {"args": "anything"}}, opa)
    assert verdict is not None, "generated rego must compile under OPA"
    assert verdict["decision"] == "deny"


def test_valid_regex_rule_matches_under_opa(opa: str) -> None:
    rego = _render_rego(
        [{
            "name": "block_secret",
            "action": "deny",
            "condition": {
                "field": "tool_call.args",
                "operator": "regex",
                "value": "secret",
            },
        }]
    )
    deny = _opa_verdict(rego, {"tool_call": {"args": "has secret here"}}, opa)
    allow = _opa_verdict(rego, {"tool_call": {"args": "clean input"}}, opa)
    assert deny is not None and deny["decision"] == "deny"
    assert allow is not None and allow["decision"] == "allow"


# ── non-JSON condition values (TypeError fix) ──────────────────────────────


def test_rego_op_clause_date_value_does_not_crash() -> None:
    clause = _rego_op_clause("eq", "input.snapshot.x", datetime.date(2026, 6, 23))
    assert clause is not None
    assert "2026-06-23" in clause


# ── _load_yaml IO error contract ───────────────────────────────────────────


def test_load_yaml_missing_file_maps_to_resolution_error(tmp_path: Path) -> None:
    with pytest.raises(ResolutionError):
        _load_yaml(tmp_path / "does_not_exist.yaml")


# ── _materialize_rego_bundle atomicity / error mapping ─────────────────────


def test_materialize_writes_both_files(tmp_path: Path) -> None:
    policy_dir = _materialize_rego_bundle(tmp_path, [])
    rego = policy_dir / "agt_legacy.rego"
    sidecar = policy_dir / "agt_legacy.rego.sha256"
    assert rego.exists() and sidecar.exists()
    # No leftover temp files from the atomic write.
    assert not list(policy_dir.glob("*.tmp"))


def test_materialize_oserror_maps_to_resolution_error(tmp_path: Path) -> None:
    # bundle_root is a *file*, so mkdir(parents=True) under it raises OSError.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(ResolutionError):
        _materialize_rego_bundle(blocker, [])
