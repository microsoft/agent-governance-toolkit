#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for check_build_hooks.py."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import _supply_chain_common as common  # noqa: E402
import check_build_hooks as cbh  # noqa: E402


def test_no_matches_returns_zero(capsys):
    with patch.object(common, "changed_manifests", return_value=[]):
        assert cbh.main_with_args([]) == 0
    out = capsys.readouterr().out
    assert "OK" in out


def test_setup_py_warns_by_default():
    with patch.object(common, "changed_manifests", return_value=["pkg/setup.py"]):
        rc = cbh.main_with_args([])
    assert rc == 0


def test_setup_py_strict_fails():
    with patch.object(common, "changed_manifests", return_value=["pkg/setup.py"]):
        rc = cbh.main_with_args(["--strict"])
    assert rc == 1


def test_build_rs_warns_by_default():
    with patch.object(common, "changed_manifests", return_value=["crates/x/build.rs"]):
        rc = cbh.main_with_args([])
    assert rc == 0


def test_build_rs_strict_fails():
    with patch.object(common, "changed_manifests", return_value=["crates/x/build.rs"]):
        rc = cbh.main_with_args(["--strict"])
    assert rc == 1


def test_both_listed_in_output(capsys):
    paths = ["pkg/setup.py", "crates/x/build.rs"]
    with patch.object(common, "changed_manifests", return_value=paths):
        cbh.main_with_args([])
    out = capsys.readouterr().out
    assert "pkg/setup.py" in out
    assert "crates/x/build.rs" in out


def test_root_setup_py_matches(capsys):
    """M2 regression: a root-level ``setup.py`` (no directory prefix) must be matched."""
    with patch.object(common, "changed_manifests", return_value=["setup.py"]):
        rc = cbh.main_with_args(["--strict"])
    assert rc == 1
    assert "setup.py" in capsys.readouterr().out


def test_changed_manifests_called_with_correct_basenames():
    """Sanity check: the scanner asks the helper for the right file types."""
    with patch.object(common, "changed_manifests", return_value=[]) as cm:
        cbh.main_with_args(["--base", "origin/feature"])
    cm.assert_called_once_with("origin/feature", ["setup.py", "build.rs"])
