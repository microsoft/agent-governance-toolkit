# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for native ATR manifest generation."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

from agent_control_specification import validate_manifest


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

    validate_manifest(output.read_text(encoding="utf-8"))
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


def test_backtick_pattern_cannot_escape_the_rego_string_literal(tmp_path: Path) -> None:
    """A corpus pattern must not be able to inject Rego.

    Patterns used to be interpolated into a backtick raw-string literal, which
    has no escape mechanism, so a pattern carrying a backtick closed the
    literal early and the rest was parsed as policy source. The sync runs
    unattended against a third-party feed, so this is a supply-chain path.
    """
    module = _module()
    hostile = 'evil`, target)\n\tinput.x == input.x\n}\ninjected := true\nx := regex.match(`y'

    compiled = module.compile_patterns(
        [
            module.AtrPattern(
                atr_id="ATR-1",
                category="prompt-injection",
                severity="high",
                name="atr-1",
                field="user_input",
                pattern=hostile,
                message="m",
            )
        ],
        name="atr",
        bundle="atr",
        package="atr",
    )
    rego = compiled.rego
    line = next(ln for ln in rego.splitlines() if ln.strip().startswith("regex.match("))
    emitted = line.strip()[len("regex.match(") : -len(", target)")]

    # The whole hostile pattern must survive as ONE quoted Rego string. If it
    # round-trips through json.loads it never escaped the literal, so the
    # trailing "injected := true" is inert text rather than policy source.
    assert json.loads(emitted) == hostile
    assert "\n" not in emitted, "a raw newline would break out of the string"


def test_validate_regex_rejects_a_backtick(tmp_path: Path) -> None:
    """The validator refuses a backtick outright under --strict-regex."""
    module = _module()

    assert module._validate_regex("plain", "src", strict=False) is True
    assert module._validate_regex("has`tick", "src", strict=False) is False
    with pytest.raises(module.InvalidRegexError):
        module._validate_regex("has`tick", "src", strict=True)
