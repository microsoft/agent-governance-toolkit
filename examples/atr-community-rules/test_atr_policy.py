# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for native ATR manifest generation."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

from agt.policies import AgtManifest


def _module():
    path = Path(__file__).with_name("sync_atr_rules.py")
    spec = importlib.util.spec_from_file_location("atr_sync_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_atr(root: Path, *, pattern: str = "ignore previous") -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "rule.yaml").write_text(
        yaml.safe_dump(
            {
                "id": "ATR-1",
                "title": "Prompt injection",
                "severity": "high",
                "tags": {"category": "prompt-injection"},
                "detection": {
                    "conditions": [
                        {"operator": "regex", "value": pattern}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )


def test_compiles_native_manifest_and_rego(tmp_path: Path) -> None:
    module = _module()
    source = tmp_path / "rules"
    _write_atr(source)

    compiled = module.convert_atr_directory(source)
    output = tmp_path / "manifest.yaml"
    module.write_compiled(output, compiled)

    AgtManifest.from_path(output)
    assert compiled.pattern_count == 1
    assert "agent_control_specification_version" in output.read_text()
    assert "package agt.examples.atr.community" in compiled.rego


def test_draft_rules_are_skipped(tmp_path: Path) -> None:
    module = _module()
    source = tmp_path / "rules"
    _write_atr(source)
    path = source / "rule.yaml"
    document = yaml.safe_load(path.read_text())
    document["status"] = "draft"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert list(module.iter_atr_patterns(source)) == []


def test_strict_invalid_regex_fails(tmp_path: Path) -> None:
    module = _module()
    source = tmp_path / "rules"
    _write_atr(source, pattern="[")

    with pytest.raises(module.InvalidRegexError):
        list(module.iter_atr_patterns(source, strict_regex=True))
