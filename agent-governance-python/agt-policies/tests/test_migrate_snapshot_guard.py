# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Regression tests for issue #3517.

``_render_rego`` emits ``default verdict := {"decision": "allow"}``. When
``input.snapshot`` is absent, null, or a non-object, every field accessor is
undefined, no ``_match_i`` rule fires, and evaluation would fall through to the
default-allow verdict, so a caller that omits or mistypes the snapshot root
would be allowed on a deny-side policy. The rendered module must instead fail
closed with a deny whenever the snapshot is not an object, while preserving the
existing behaviour for well-formed snapshots.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any

import pytest

from agt.cli._migrate_resolution.build import _render_rego


def _opa_bin() -> str | None:
    return os.environ.get("ACS_OPA_PATH") or shutil.which("opa")


_OPA = _opa_bin()
_needs_opa = pytest.mark.skipif(_OPA is None, reason="opa binary not available")

# A representative deny-side rule set: deny when the tool call amount exceeds a
# threshold; a well-formed snapshot that matches nothing falls to default-allow.
_RULES: list[dict[str, Any]] = [
    {
        "name": "deny_large_transfers",
        "action": "deny",
        "message": "amount exceeds limit",
        "condition": {
            "field": "tool_call.args.amount_usd",
            "operator": "gt",
            "value": 100,
        },
    }
]


def _eval_verdict(rego_src: str, input_doc: dict[str, Any]) -> dict[str, Any]:
    """Evaluate ``data.agt.legacy.verdict`` for ``input_doc`` via the opa binary."""
    assert _OPA is not None
    with tempfile.TemporaryDirectory() as work:
        rego_path = os.path.join(work, "agt_legacy.rego")
        with open(rego_path, "w", encoding="utf-8") as handle:
            handle.write(rego_src)
        proc = subprocess.run(
            [
                _OPA,
                "eval",
                "-f",
                "json",
                "-d",
                rego_path,
                "--stdin-input",
                "data.agt.legacy.verdict",
            ],
            input=json.dumps(input_doc),
            capture_output=True,
            text=True,
            check=False,
        )
    assert proc.returncode == 0, f"opa eval failed: {proc.stderr}\n{proc.stdout}"
    payload = json.loads(proc.stdout)
    # A complete-rule conflict surfaces here as an ``errors`` key; assert its
    # absence so the mutual-exclusivity of the guard is actually exercised.
    assert "errors" not in payload, f"opa reported errors: {payload.get('errors')}"
    return payload["result"][0]["expressions"][0]["value"]


def _verdict(input_doc: dict[str, Any], rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return _eval_verdict(_render_rego(_RULES if rules is None else rules), input_doc)


@_needs_opa
@pytest.mark.parametrize(
    "input_doc",
    [
        pytest.param({}, id="absent"),
        pytest.param({"snapshot": None}, id="null"),
        pytest.param({"snapshot": "not-an-object"}, id="string"),
        pytest.param({"snapshot": 42}, id="number"),
        pytest.param({"snapshot": ["a", "b"]}, id="array"),
    ],
)
def test_non_object_snapshot_fails_closed(input_doc: dict[str, Any]) -> None:
    verdict = _verdict(input_doc)
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "runtime_error:snapshot_invalid"


@_needs_opa
def test_valid_object_snapshot_without_match_still_allows() -> None:
    # Existing behaviour for valid inputs is preserved: a well-formed snapshot
    # that matches no rule falls through to the default-allow verdict.
    verdict = _verdict({"snapshot": {"tool_call": {"args": {"amount_usd": 5}}}})
    assert verdict["decision"] == "allow"


@_needs_opa
def test_valid_object_snapshot_matching_rule_denies() -> None:
    verdict = _verdict({"snapshot": {"tool_call": {"args": {"amount_usd": 500}}}})
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "deny_large_transfers"


@_needs_opa
def test_invalid_rule_and_bad_snapshot_do_not_conflict() -> None:
    # An unsupported operator renders an always-matching fail-closed deny branch.
    # With a non-object snapshot the snapshot guard also denies; the two must be
    # mutually exclusive so OPA does not raise a complete-rule conflict on
    # ``verdict``. _eval_verdict asserts no opa errors, so a conflict would fail.
    rules = [
        {
            "name": "unsupported_op",
            "action": "deny",
            "message": "x",
            "condition": {
                "field": "tool_call.args.amount_usd",
                "operator": "nonsense_operator",
                "value": 1,
            },
        }
    ]
    verdict = _verdict({}, rules=rules)
    assert verdict["decision"] == "deny"


def test_render_includes_snapshot_guard() -> None:
    # Render-level assertion (no opa needed): the guard rule, its negation gate
    # on rule branches, and the deny reason are present so evaluation cannot fall
    # through to default-allow on a malformed snapshot.
    rego = _render_rego(_RULES)
    assert "default _snapshot_valid := false" in rego
    assert "is_object(input.snapshot)" in rego
    assert "not _snapshot_valid" in rego
    assert "runtime_error:snapshot_invalid" in rego
