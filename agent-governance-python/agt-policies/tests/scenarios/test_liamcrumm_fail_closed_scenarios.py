# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OPA-backed regressions for @liamcrumm's review of PR #3529.

Two fail-open flips found on OPA 0.70.0 and fixed in
``_migrate_resolution/build.py``:

1. ``allow ... eq null`` fired on an ABSENT field because the array-path
   ``object.get(..., null)`` default collapses absent and present-null, so a
   higher-priority allow could preempt a lower-priority deny (fail open).
2. String predicates (``contains``/``startswith``/``endswith``/``matches``)
   emitted no ``is_string`` guard, so a non-string runtime value type-errors
   the OPA builtin -> undefined rule -> ``default allow`` (deny bypass), and an
   uncompilable regex pattern shipped a permanently-dead deny.

Each test exercises the full compiled Rego through the ``opa`` binary so a
render-level shortcut cannot mask a runtime regression. The bug tests FAIL
against pre-fix build.py and PASS after; the control tests pass both ways.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agt.cli._migrate_resolution.build import _render_rego

pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary required for scenario tests",
)


def _eval_verdict(tmp_path: Path, rego_source: str, snapshot: dict) -> str:
    bundle = tmp_path / "bundle"
    bundle.mkdir(exist_ok=True)
    (bundle / "agt_legacy.rego").write_text(rego_source, encoding="utf-8")
    proc = subprocess.run(  # noqa: S603
        [
            "opa", "eval", "--format", "raw", "--stdin-input",
            "--data", str(bundle),
            "data.agt.legacy.verdict.decision",
        ],
        input=json.dumps({"snapshot": snapshot}),
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0, f"opa stderr: {proc.stderr}"
    return proc.stdout.strip().strip('"')


def _eval_returncode(tmp_path: Path, rego_source: str, snapshot: dict) -> int:
    """Evaluate under --strict-builtin-errors; return the opa return code."""
    bundle = tmp_path / "bundle"
    bundle.mkdir(exist_ok=True)
    (bundle / "agt_legacy.rego").write_text(rego_source, encoding="utf-8")
    proc = subprocess.run(  # noqa: S603
        [
            "opa", "eval", "--format", "raw", "--stdin-input",
            "--strict-builtin-errors",
            "--data", str(bundle),
            "data.agt.legacy.verdict.decision",
        ],
        input=json.dumps({"snapshot": snapshot}),
        capture_output=True, text=True, timeout=10,
    )
    return proc.returncode


# --- Issue 1: allow eq null must not fire on an absent field -----------------

def _allow_eq_null_then_default_deny() -> str:
    return _render_rego([
        {
            "name": "allow_when_region_is_null",
            "condition": {"field": "tool_call.region", "operator": "eq", "value": None},
            "action": "allow",
            "message": "region explicitly null is allowed",
        },
        {
            "name": "default_region_deny",
            "condition": {"field": "tool_call.region", "operator": "ne", "value": "__never__"},
            "action": "deny",
            "message": "region governance default deny",
        },
    ])


def test_allow_eq_null_leaf_absent_fails_closed(tmp_path):
    # BUG (pre-fix): absent leaf -> allow eq null fires -> "allow" (fail open).
    rego = _allow_eq_null_then_default_deny()
    assert _eval_verdict(tmp_path, rego, {"tool_call": {"args": "x"}}) == "deny"


def test_allow_eq_null_intermediate_absent_fails_closed(tmp_path):
    # BUG (pre-fix): absent intermediate segment -> allow eq null fires.
    rego = _allow_eq_null_then_default_deny()
    assert _eval_verdict(tmp_path, rego, {}) == "deny"


def test_allow_eq_null_present_null_still_allows(tmp_path):
    # CONTROL: a genuinely present null must still match allow (both ways).
    rego = _allow_eq_null_then_default_deny()
    assert _eval_verdict(tmp_path, rego, {"tool_call": {"region": None}}) == "allow"


# --- Issue 2a: string predicate on a non-string value must not type-error ----

def _deny_contains_rego() -> str:
    return _render_rego([
        {
            "name": "deny_if_amount_contains_secret",
            "condition": {"field": "tool_call.amount", "operator": "contains", "value": "secret"},
            "action": "deny",
            "message": "value must not contain secret",
        },
    ])


def test_string_predicate_non_string_no_builtin_error(tmp_path):
    # BUG (pre-fix): contains() on a numeric value -> eval_type_error ->
    # nonzero rc under --strict-builtin-errors (silent default-allow otherwise).
    rego = _deny_contains_rego()
    assert _eval_returncode(tmp_path, rego, {"tool_call": {"amount": 123}}) == 0


def test_string_predicate_string_value_still_denies(tmp_path):
    # CONTROL: a matching string value still denies (both ways).
    rego = _deny_contains_rego()
    assert _eval_verdict(tmp_path, rego, {"tool_call": {"amount": "top-secret"}}) == "deny"


# --- Issue 2b: uncompilable / non-string regex pattern must fail closed ------

def test_invalid_regex_pattern_fails_closed(tmp_path):
    # BUG (pre-fix): regex.match on an uncompilable pattern -> undefined rule
    # -> "allow" (a permanently-dead deny). Post-fix build-time validation
    # returns None -> caller emits an always-matching fail-closed deny.
    rego = _render_rego([
        {
            "name": "deny_bad_region_pattern",
            "condition": {"field": "region", "operator": "matches", "value": "[unterminated"},
            "action": "deny",
            "message": "region pattern deny",
        },
    ])
    assert _eval_verdict(tmp_path, rego, {"region": "CN"}) == "deny"


def test_non_string_regex_pattern_fails_closed(tmp_path):
    # BUG (pre-fix): regex.match(<number>, _v) type-errors -> undefined -> allow.
    rego = _render_rego([
        {
            "name": "deny_numeric_pattern",
            "condition": {"field": "region", "operator": "matches", "value": 123},
            "action": "deny",
            "message": "region pattern deny",
        },
    ])
    assert _eval_verdict(tmp_path, rego, {"region": "CN"}) == "deny"


def test_valid_regex_pattern_still_matches(tmp_path):
    # CONTROL: a valid pattern still denies on match (both ways).
    rego = _render_rego([
        {
            "name": "deny_cn_region",
            "condition": {"field": "region", "operator": "matches", "value": "^C"},
            "action": "deny",
            "message": "CN region deny",
        },
    ])
    assert _eval_verdict(tmp_path, rego, {"region": "CN"}) == "deny"
