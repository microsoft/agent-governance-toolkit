# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression test for ``evaluate_policy_cli`` policy-path resolution.

Previously, passing a single policy file to ``--policy`` caused the CLI
to delegate to ``PolicyEvaluator.load_policies(path.parent)``, silently
loading every sibling ``*.yaml`` in the same directory. A repo with
``policies/strict.yaml`` and ``policies/scratch-draft.yaml`` would have
the draft applied even when only ``strict.yaml`` was requested.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("agent_os.policies")

from agent_marketplace import hooks


_POLICY_TEMPLATE = """\
version: "1.0"
name: {name}
description: {name} policy
rules:
  - name: {name}-rule
    condition:
      field: plugin_name
      operator: eq
      value: {name}
    action: allow
"""

_MANIFEST_TEMPLATE = """\
name: example-plugin
version: 1.0.0
author: test-author
description: Example
plugin_type: integration
"""


def _write_policy(directory: Path, name: str) -> Path:
    path = directory / f"{name}.yaml"
    path.write_text(_POLICY_TEMPLATE.format(name=name), encoding="utf-8")
    return path


def test_single_file_policy_does_not_pull_in_siblings(monkeypatch, tmp_path, capsys):
    """When --policy points at a file, sibling files must not be loaded."""
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    target_policy = _write_policy(policy_dir, "strict")
    _write_policy(policy_dir, "scratch-draft")  # must be ignored

    manifest = tmp_path / "agent-plugin.yaml"
    manifest.write_text(_MANIFEST_TEMPLATE, encoding="utf-8")

    captured: dict = {}

    from agent_os.policies import PolicyEvaluator as RealEvaluator

    original_init = RealEvaluator.__init__

    def spying_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        captured["evaluator"] = self

    monkeypatch.setattr(RealEvaluator, "__init__", spying_init)
    monkeypatch.setattr(
        sys, "argv",
        ["evaluate-policy", "--policy", str(target_policy), str(manifest)],
    )

    rc = hooks.evaluate_policy_cli()

    evaluator = captured["evaluator"]
    loaded_names = [p.name for p in evaluator.policies]
    assert "strict" in loaded_names
    assert "scratch-draft" not in loaded_names, (
        f"Sibling policy must not be auto-loaded; got {loaded_names!r}"
    )
    assert rc == 0


def test_directory_policy_still_loads_every_file(monkeypatch, tmp_path):
    """Pointing --policy at a directory keeps the existing fold-the-dir behavior."""
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    _write_policy(policy_dir, "a")
    _write_policy(policy_dir, "b")

    manifest = tmp_path / "agent-plugin.yaml"
    manifest.write_text(_MANIFEST_TEMPLATE, encoding="utf-8")

    captured: dict = {}
    from agent_os.policies import PolicyEvaluator as RealEvaluator

    original_init = RealEvaluator.__init__

    def spying_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        captured["evaluator"] = self

    monkeypatch.setattr(RealEvaluator, "__init__", spying_init)
    monkeypatch.setattr(
        sys, "argv",
        ["evaluate-policy", "--policy", str(policy_dir), str(manifest)],
    )

    rc = hooks.evaluate_policy_cli()

    evaluator = captured["evaluator"]
    loaded_names = sorted(p.name for p in evaluator.policies)
    assert loaded_names == ["a", "b"]
    assert rc == 0


def test_missing_policy_path_exits_nonzero(monkeypatch, tmp_path, capsys):
    """A nonexistent --policy path must report and exit non-zero, not silently no-op."""
    manifest = tmp_path / "agent-plugin.yaml"
    manifest.write_text(_MANIFEST_TEMPLATE, encoding="utf-8")

    monkeypatch.setattr(
        sys, "argv",
        [
            "evaluate-policy",
            "--policy", str(tmp_path / "does-not-exist.yaml"),
            str(manifest),
        ],
    )

    rc = hooks.evaluate_policy_cli()
    captured = capsys.readouterr()
    assert rc == 1
    assert "Policy path not found" in captured.err
