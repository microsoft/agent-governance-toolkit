# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for check_example_intervention_points.py."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_example_intervention_points as chk  # noqa: E402

_REGO_FULL = """agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: full
policies:
  p:
    type: rego
    bundle: rego
intervention_points:
  input:
    policy_target: $.input.body
    policy:
      id: p
      query: data.pkg.acs_input_result
  output:
    policy_target: $.output.content
    policy:
      id: p
      query: data.pkg.acs_output_result
  pre_tool_call:
    policy_target: $.tool_call.args
    policy:
      id: p
      query: data.pkg.acs_pre_tool_call_result
"""

_REGO_MISSING = """agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: missing
policies:
  p:
    type: rego
    bundle: rego
intervention_points:
  input:
    policy_target: $.input.body
    policy:
      id: p
      query: data.pkg.acs_input_result
  output:
    policy_target: $.output.content
    policy:
      id: p
      query: data.pkg.acs_output_result
"""

_CUSTOM = """agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: custom
policies:
  p:
    type: custom
    adapter: example
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy:
      id: p
"""

_NO_POINTS = """metadata:
  name: not-an-acs-manifest
rules:
  - allow: everything
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_rego_manifest_with_all_points_passes(tmp_path):
    assert chk.check_file(_write(tmp_path, "full.yaml", _REGO_FULL)) == []


def test_rego_manifest_missing_pre_tool_call_errors(tmp_path):
    errors = chk.check_file(_write(tmp_path, "missing.yaml", _REGO_MISSING))
    assert len(errors) == 1
    assert "pre_tool_call" in errors[0]


def test_custom_adapter_manifest_is_exempt(tmp_path):
    assert chk.check_file(_write(tmp_path, "custom.yaml", _CUSTOM)) == []


def test_manifest_without_intervention_points_is_exempt(tmp_path):
    assert chk.check_file(_write(tmp_path, "plain.yaml", _NO_POINTS)) == []
