# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for per-category native ATR compilation."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

from agt.policies import AgtManifest


def _module():
    path = Path(__file__).with_name("import_atr.py")
    spec = importlib.util.spec_from_file_location("atr_import_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_rule(root: Path, category: str, severity: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{category}.yaml").write_text(
        yaml.safe_dump(
            {
                "id": f"ATR-{category}",
                "title": category,
                "severity": severity,
                "tags": {"category": category},
                "detection": {
                    "conditions": [
                        {"operator": "regex", "value": "blocked"}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )


def test_compiles_one_manifest_per_category(tmp_path: Path) -> None:
    module = _module()
    source = tmp_path / "rules"
    output = tmp_path / "out"
    _write_rule(source, "prompt-injection", "high")
    _write_rule(source, "tool-poisoning", "medium")

    result = module.compile_per_category(source, output)

    assert result["total_compiled_rules"] == 2
    for path in output.glob("*.yaml"):
        AgtManifest.from_path(path)


def test_category_and_severity_filters(tmp_path: Path) -> None:
    module = _module()
    source = tmp_path / "rules"
    output = tmp_path / "out"
    _write_rule(source, "prompt-injection", "high")
    _write_rule(source, "tool-poisoning", "low")

    result = module.compile_per_category(
        source,
        output,
        categories={"prompt-injection"},
        min_severity="medium",
    )

    assert result["total_compiled_rules"] == 1
    assert [item["category"] for item in result["categories"]] == [
        "prompt-injection"
    ]
