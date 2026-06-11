#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for contributor_check_action.py risk aggregation."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contributor_check_action import _aggregate_risk


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
