#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for contributor_check_action.py risk aggregation."""

from __future__ import annotations

import json
import os
import sys
import textwrap
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contributor_check_action import _aggregate_risk, _run_check


# ---------------------------------------------------------------------------
# Fail-closed aggregation (issue #2950)
# ---------------------------------------------------------------------------

def test_all_unknown_aggregates_to_unknown_not_low():
    # Regression for #2950: when every check could not be determined (e.g. all
    # checks errored / were rate-limited), the aggregate must NOT be LOW.
    assert _aggregate_risk("UNKNOWN", "UNKNOWN", "UNKNOWN") == "UNKNOWN"


def test_unknown_outranks_low():
    # A single UNKNOWN must not be hidden behind clean LOW results.
    assert _aggregate_risk("LOW", "UNKNOWN", "LOW") == "UNKNOWN"


def test_unknown_outranks_medium():
    assert _aggregate_risk("MEDIUM", "UNKNOWN") == "UNKNOWN"


def test_high_still_dominates_unknown():
    # A confirmed HIGH signal is still worse than an uncertain one.
    assert _aggregate_risk("UNKNOWN", "HIGH") == "HIGH"
    assert _aggregate_risk("HIGH", "UNKNOWN", "LOW") == "HIGH"


def test_all_low_aggregates_to_low():
    assert _aggregate_risk("LOW", "LOW", "LOW") == "LOW"


def test_medium_dominates_low():
    assert _aggregate_risk("LOW", "MEDIUM", "LOW") == "MEDIUM"


def test_unrecognized_label_treated_as_unknown_not_low():
    # Defensive: an unexpected/garbage risk string fails closed, not open.
    assert _aggregate_risk("LOW", "BOGUS") == "UNKNOWN"


def test_empty_inputs_default_low():
    # No checks supplied (all skipped) is not an error condition.
    assert _aggregate_risk() == "LOW"


# ---------------------------------------------------------------------------
# _run_check NONE normalization (issue #3007)
# ---------------------------------------------------------------------------

def _make_script(risk: str, tmp_dir: str) -> str:
    """Write a tiny fake check script that prints JSON with the given risk."""
    path = os.path.join(tmp_dir, "fake_check.py")
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            import json, sys
            print(json.dumps({{"risk": "{risk}"}}))
        """))
    return path


def test_run_check_none_normalizes_to_low():
    # credential_audit returns "NONE" when a user has no merged PRs.
    # _run_check must normalize that to "LOW" so the aggregate does not
    # treat an absence of credential risk as UNKNOWN (regression for #3007).
    with tempfile.TemporaryDirectory() as tmp:
        script = _make_script("NONE", tmp)
        out = os.path.join(tmp, "out.json")
        result = _run_check(script, [], out)
    assert result == "LOW", f"expected LOW, got {result!r}"


def test_run_check_low_passes_through():
    with tempfile.TemporaryDirectory() as tmp:
        script = _make_script("LOW", tmp)
        out = os.path.join(tmp, "out.json")
        assert _run_check(script, [], out) == "LOW"


def test_run_check_high_passes_through():
    with tempfile.TemporaryDirectory() as tmp:
        script = _make_script("HIGH", tmp)
        out = os.path.join(tmp, "out.json")
        assert _run_check(script, [], out) == "HIGH"


def test_run_check_crash_returns_unknown():
    # A script that crashes must not silently score as LOW.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "crasher.py")
        with open(path, "w") as f:
            f.write("raise RuntimeError('simulated failure')\n")
        out = os.path.join(tmp, "out.json")
        assert _run_check(path, [], out) == "UNKNOWN"


def test_run_check_none_plus_low_aggregate_stays_low():
    # End-to-end: profile=LOW, credential=NONE → overall LOW, not UNKNOWN.
    with tempfile.TemporaryDirectory() as tmp:
        none_script = _make_script("NONE", tmp)
        low_script = os.path.join(tmp, "low.py")
        with open(low_script, "w") as f:
            f.write('import json; print(json.dumps({"risk": "LOW"}))\n')
        out1 = os.path.join(tmp, "out1.json")
        out2 = os.path.join(tmp, "out2.json")
        profile_risk = _run_check(low_script, [], out1)
        cred_risk = _run_check(none_script, [], out2)
    overall = _aggregate_risk(
        profile_risk or "LOW",
        cred_risk or "LOW",
    )
    assert overall == "LOW", f"expected LOW, got {overall!r}"
