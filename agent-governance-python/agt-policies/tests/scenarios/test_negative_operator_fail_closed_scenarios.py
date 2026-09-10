# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OPA-backed scenarios: negative operators in deny rules must fail closed.

Regression for #3297 re-introduced by the v4-removal migration (#3451).
Both root causes (chained object.get producing undefined on a missing
intermediate segment, and the unconditional _v != null guard on ne/not_in
deny rules) were confirmed on OPA 1.18.2 (2026-07-30). These tests
exercise the full compiled Rego so that no render-level fix can mask a
runtime regression.
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
    """Write a bundle, evaluate data.agt.legacy.verdict, return decision."""
    bundle = tmp_path / "bundle"
    bundle.mkdir(exist_ok=True)
    (bundle / "agt_legacy.rego").write_text(rego_source, encoding="utf-8")
    proc = subprocess.run(  # noqa: S603
        [
            "opa", "eval",
            "--format", "raw",
            "--stdin-input",
            "--data", str(bundle),
            "data.agt.legacy.verdict.decision",
        ],
        input=json.dumps({"snapshot": snapshot}),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, f"opa stderr: {proc.stderr}"
    return proc.stdout.strip().strip('"')


def _deny_ne_rego() -> str:
    return _render_rego([{
        "name": "content_hash_pin",
        "condition": {
            "field": "tool_call.content_hash",
            "operator": "ne",
            "value": "sha256:REGISTERED",
        },
        "action": "deny",
        "priority": 10,
        "message": "content hash must match registered pin",
    }])


def _deny_not_in_rego() -> str:
    return _render_rego([{
        "name": "region_allowlist",
        "condition": {
            "field": "region",
            "operator": "not_in",
            "value": ["US", "EU"],
        },
        "action": "deny",
        "priority": 10,
        "message": "region must be in allowlist",
    }])


# ── deny ne: content_hash pin ────────────────────────────────────────

class TestDenyNeFailClosed:
    def test_intermediate_absent_denies(self, tmp_path: Path) -> None:
        """Omitting tool_call entirely must not bypass the deny rule."""
        verdict = _eval_verdict(tmp_path, _deny_ne_rego(), {})
        assert verdict == "deny", "intermediate absent should deny, got allow (bypass)"

    def test_leaf_absent_denies(self, tmp_path: Path) -> None:
        """tool_call present but content_hash omitted must deny."""
        verdict = _eval_verdict(tmp_path, _deny_ne_rego(), {"tool_call": {"args": "x"}})
        assert verdict == "deny", "leaf absent should deny, got allow (bypass)"

    def test_field_explicitly_null_denies(self, tmp_path: Path) -> None:
        """Explicitly null content_hash must deny."""
        verdict = _eval_verdict(tmp_path, _deny_ne_rego(), {"tool_call": {"content_hash": None}})
        assert verdict == "deny", "explicit null should deny, got allow (bypass)"

    def test_wrong_value_denies(self, tmp_path: Path) -> None:
        """An unregistered hash must deny."""
        verdict = _eval_verdict(
            tmp_path, _deny_ne_rego(),
            {"tool_call": {"content_hash": "sha256:ATTACKER"}},
        )
        assert verdict == "deny"

    def test_correct_pin_allows(self, tmp_path: Path) -> None:
        """The registered hash must allow."""
        verdict = _eval_verdict(
            tmp_path, _deny_ne_rego(),
            {"tool_call": {"content_hash": "sha256:REGISTERED"}},
        )
        assert verdict == "allow"


# ── deny not_in: region allowlist ────────────────────────────────────

class TestDenyNotInFailClosed:
    def test_field_absent_denies(self, tmp_path: Path) -> None:
        """Omitting region entirely must not bypass the deny rule."""
        verdict = _eval_verdict(tmp_path, _deny_not_in_rego(), {})
        assert verdict == "deny", "absent field should deny, got allow (bypass)"

    def test_field_explicitly_null_denies(self, tmp_path: Path) -> None:
        """Explicitly null region must deny."""
        verdict = _eval_verdict(tmp_path, _deny_not_in_rego(), {"region": None})
        assert verdict == "deny", "explicit null should deny, got allow (bypass)"

    def test_unlisted_region_denies(self, tmp_path: Path) -> None:
        """A region outside the allowlist must deny."""
        verdict = _eval_verdict(tmp_path, _deny_not_in_rego(), {"region": "CN"})
        assert verdict == "deny"

    def test_listed_region_allows(self, tmp_path: Path) -> None:
        """A region inside the allowlist must allow."""
        verdict = _eval_verdict(tmp_path, _deny_not_in_rego(), {"region": "US"})
        assert verdict == "allow"

    def test_second_listed_region_allows(self, tmp_path: Path) -> None:
        verdict = _eval_verdict(tmp_path, _deny_not_in_rego(), {"region": "EU"})
        assert verdict == "allow"


# ── allow polarity: null guard must be retained ───────────────────────
# An allow rule that fires on a missing field preempts a later deny in
# the first-match-wins chain, which is itself a fail-open. Verify the
# guard is kept when action == "allow".

def _allow_ne_then_deny_rego() -> str:
    """allow ne fires only when field is present and not equal; deny catches rest."""
    return _render_rego([
        {
            "name": "region_allow_non_us",
            "condition": {"field": "region", "operator": "ne", "value": "US"},
            "action": "allow",
            "priority": 20,
            "message": "",
        },
        {
            "name": "catch_all_deny",
            "condition": {"field": "tool_name", "operator": "exists", "value": None},
            "action": "deny",
            "priority": 10,
            "message": "denied by catch-all",
        },
    ])


def _allow_not_in_then_deny_rego() -> str:
    return _render_rego([
        {
            "name": "region_allow_not_in_restricted",
            "condition": {"field": "region", "operator": "not_in", "value": ["CN", "RU"]},
            "action": "allow",
            "priority": 20,
            "message": "",
        },
        {
            "name": "catch_all_deny",
            "condition": {"field": "tool_name", "operator": "exists", "value": None},
            "action": "deny",
            "priority": 10,
            "message": "denied by catch-all",
        },
    ])


class TestAllowPolarityGuardRetained:
    def test_allow_ne_null_field_does_not_fire(self, tmp_path: Path) -> None:
        """allow ne must NOT fire when field is explicitly null (guard must stay)."""
        verdict = _eval_verdict(
            tmp_path, _allow_ne_then_deny_rego(),
            {"tool_name": "transfer", "region": None},
        )
        assert verdict == "deny", (
            "allow ne fired on null field and preempted the deny; null guard missing"
        )

    def test_allow_ne_absent_field_does_not_fire(self, tmp_path: Path) -> None:
        """allow ne must NOT fire when the field key is omitted entirely."""
        verdict = _eval_verdict(
            tmp_path, _allow_ne_then_deny_rego(),
            {"tool_name": "transfer"},
        )
        assert verdict == "deny", (
            "allow ne fired on absent field and preempted the deny; null guard missing"
        )

    def test_allow_ne_fires_on_non_matching_present_field(self, tmp_path: Path) -> None:
        """allow ne fires correctly when field is present and != value."""
        verdict = _eval_verdict(
            tmp_path, _allow_ne_then_deny_rego(),
            {"tool_name": "transfer", "region": "EU"},
        )
        assert verdict == "allow"

    def test_allow_not_in_null_field_does_not_fire(self, tmp_path: Path) -> None:
        """allow not_in must NOT fire when field is explicitly null (guard must stay)."""
        verdict = _eval_verdict(
            tmp_path, _allow_not_in_then_deny_rego(),
            {"tool_name": "transfer", "region": None},
        )
        assert verdict == "deny", (
            "allow not_in fired on null field and preempted the deny; null guard missing"
        )

    def test_allow_not_in_absent_field_does_not_fire(self, tmp_path: Path) -> None:
        """allow not_in must NOT fire when the field key is omitted entirely."""
        verdict = _eval_verdict(
            tmp_path, _allow_not_in_then_deny_rego(),
            {"tool_name": "transfer"},
        )
        assert verdict == "deny", (
            "allow not_in fired on absent field and preempted the deny; null guard missing"
        )

    def test_allow_not_in_fires_on_non_restricted_region(self, tmp_path: Path) -> None:
        """allow not_in fires correctly when field is present and not in the set."""
        verdict = _eval_verdict(
            tmp_path, _allow_not_in_then_deny_rego(),
            {"tool_name": "transfer", "region": "US"},
        )
        assert verdict == "allow"
