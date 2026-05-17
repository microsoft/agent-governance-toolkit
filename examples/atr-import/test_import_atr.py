# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the ``examples/atr-import/import_atr.py`` standalone example.

Covers per-category compilation, severity / category filters, the watch
loop's change detection, and integration with the PR #908 conversion
helpers in ``examples/atr-community-rules/sync_atr_rules.py``.

Run from repo root: ``pytest examples/atr-import/test_import_atr.py``
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

# Load import_atr.py as a module from its file path. This example does
# not live in the package tree, so a regular ``import`` will not find it.
_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "import_atr_example", _HERE / "import_atr.py"
)
import_atr_example = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules["import_atr_example"] = import_atr_example
_spec.loader.exec_module(import_atr_example)  # type: ignore[union-attr]

cmd_atr_import = import_atr_example.cmd_atr_import
compile_per_category = import_atr_example.compile_per_category
watch_and_recompile = import_atr_example.watch_and_recompile

# ---------------------------------------------------------------------------
# Fixtures: realistic miniature ATR rule samples (drawn from the public
# Agent-Threat-Rule/agent-threat-rules MIT-licensed catalogue).
# ---------------------------------------------------------------------------


ATR_RULE_PROMPT_INJECTION: dict[str, Any] = {
    "title": "Direct Prompt Injection via User Input",
    "id": "ATR-2026-00001",
    "rule_version": 1,
    "status": "stable",
    "description": "Detects classic instruction override prompt injection.",
    "author": "ATR Community",
    "date": "2026/03/08",
    "schema_version": "0.1",
    "detection_tier": "pattern",
    "maturity": "stable",
    "severity": "high",
    "tags": {"category": "prompt-injection"},
    "detection": {
        "conditions": [
            {
                "field": "user_input",
                "operator": "regex",
                "value": r"(?i)\b(ignore|disregard)\s+(all\s+)?previous\s+instructions\b",
                "description": "Instruction override pattern",
            }
        ]
    },
}


ATR_RULE_TOOL_POISONING: dict[str, Any] = {
    "title": "Tool description bypasses consent prompts",
    "id": "ATR-2026-00027",
    "rule_version": 1,
    "status": "stable",
    "description": "Detects tool descriptions instructing agents to skip user consent.",
    "author": "ATR Community",
    "schema_version": "0.1",
    "detection_tier": "pattern",
    "maturity": "stable",
    "severity": "critical",
    "tags": {"category": "tool-poisoning"},
    "detection": {
        "conditions": [
            {
                "field": "tool_description",
                "operator": "regex",
                "value": r"(?i)\b(skip|bypass|do not ask)\s+(the\s+)?(user\s+)?consent\b",
                "description": "Consent bypass payload",
            }
        ]
    },
}


ATR_RULE_DRAFT: dict[str, Any] = {
    "title": "Draft rule that should be excluded",
    "id": "ATR-2026-09999",
    "status": "draft",
    "maturity": "test",
    "severity": "low",
    "tags": {"category": "prompt-injection"},
    "detection": {
        "conditions": [
            {
                "field": "user_input",
                "operator": "regex",
                "value": "incomplete-pattern",
            }
        ]
    },
}


def _write_atr_tree(root: Path) -> None:
    """Materialise a miniature ATR rules/ directory at *root*."""
    (root / "prompt-injection").mkdir(parents=True, exist_ok=True)
    (root / "tool-poisoning").mkdir(parents=True, exist_ok=True)

    with open(root / "prompt-injection" / "ATR-2026-00001.yaml", "w") as fh:
        yaml.safe_dump(ATR_RULE_PROMPT_INJECTION, fh)
    with open(root / "tool-poisoning" / "ATR-2026-00027.yaml", "w") as fh:
        yaml.safe_dump(ATR_RULE_TOOL_POISONING, fh)
    with open(root / "prompt-injection" / "ATR-2026-09999.yaml", "w") as fh:
        yaml.safe_dump(ATR_RULE_DRAFT, fh)


# ---------------------------------------------------------------------------
# compile_per_category
# ---------------------------------------------------------------------------


class TestCompilePerCategory:
    def test_emits_one_file_per_category(self, tmp_path: Path) -> None:
        src = tmp_path / "atr"
        out = tmp_path / "out"
        _write_atr_tree(src)

        manifest = compile_per_category(src, out)

        files = {p.name for p in out.iterdir()}
        assert files == {"prompt-injection.yaml", "tool-poisoning.yaml"}
        assert manifest["total_compiled_rules"] == 2
        assert manifest["skipped_maturity"] == 1  # the draft rule

    def test_each_category_yaml_is_valid_policy_document(
        self, tmp_path: Path
    ) -> None:
        """Structural validation of emitted PolicyDocument shape.

        We deliberately do not import ``agent_os.policies.schema`` here so the
        example stays runnable without installing the agent-os package. If
        agent-os is available in the environment, the import below will use it
        for stricter validation; otherwise we fall back to a structural check
        against the same field set that AGT's loader expects.
        """
        src = tmp_path / "atr"
        out = tmp_path / "out"
        _write_atr_tree(src)
        compile_per_category(src, out)

        try:
            from agent_os.policies.schema import PolicyDocument  # type: ignore
        except ImportError:
            PolicyDocument = None  # type: ignore

        for path in out.glob("*.yaml"):
            with open(path) as fh:
                data = yaml.safe_load(fh)
            if PolicyDocument is not None:
                document = PolicyDocument(**data)
                assert document.rules, f"{path.name} emitted no rules"
            else:
                # Structural shape: AGT PolicyDocument requires
                # name + version + rules (list of dicts each with name + condition).
                assert isinstance(data, dict)
                assert "name" in data and isinstance(data["name"], str)
                assert "version" in data
                assert "rules" in data and isinstance(data["rules"], list)
                assert data["rules"], f"{path.name} emitted no rules"
                for rule in data["rules"]:
                    assert "name" in rule
                    assert "condition" in rule

    def test_min_severity_filter(self, tmp_path: Path) -> None:
        src = tmp_path / "atr"
        out = tmp_path / "out"
        _write_atr_tree(src)

        manifest = compile_per_category(src, out, min_severity="critical")

        # Only the tool-poisoning rule (severity=critical) survives.
        categories = {c["category"] for c in manifest["categories"]}
        assert categories == {"tool-poisoning"}

    def test_category_restriction(self, tmp_path: Path) -> None:
        src = tmp_path / "atr"
        out = tmp_path / "out"
        _write_atr_tree(src)

        manifest = compile_per_category(
            src, out, categories={"prompt-injection"}
        )

        categories = {c["category"] for c in manifest["categories"]}
        assert categories == {"prompt-injection"}

    def test_id_prefix_filter(self, tmp_path: Path) -> None:
        src = tmp_path / "atr"
        out = tmp_path / "out"
        _write_atr_tree(src)

        # Both stable rules share the ATR-2026- prefix; draft excluded by
        # maturity gate (status=draft) regardless of prefix.
        manifest = compile_per_category(src, out, id_prefix="ATR-2026-")
        assert manifest["total_compiled_rules"] == 2

        # Narrow prefix matches only ATR-2026-00001.
        manifest = compile_per_category(src, out, id_prefix="ATR-2026-00001")
        assert manifest["total_compiled_rules"] == 1

        manifest = compile_per_category(src, out, id_prefix="ATR-2099-")
        assert manifest["total_compiled_rules"] == 0

    def test_emitted_rule_shape(self, tmp_path: Path) -> None:
        src = tmp_path / "atr"
        out = tmp_path / "out"
        _write_atr_tree(src)
        compile_per_category(src, out)

        with open(out / "prompt-injection.yaml") as fh:
            doc = yaml.safe_load(fh)

        rule = doc["rules"][0]
        assert rule["action"] == "deny"
        assert rule["condition"]["operator"] == "matches"
        assert rule["condition"]["field"] == "user_input"
        assert rule["priority"] == 80  # high -> 80
        assert "ATR-2026-00001" in rule["message"]

    def test_missing_atr_dir(self, tmp_path: Path) -> None:
        with pytest.raises(NotADirectoryError):
            compile_per_category(tmp_path / "nope", tmp_path / "out")


# ---------------------------------------------------------------------------
# Watch loop
# ---------------------------------------------------------------------------


class TestWatchLoop:
    def test_recompiles_on_signature_change(self, tmp_path: Path) -> None:
        src = tmp_path / "atr"
        out = tmp_path / "out"
        _write_atr_tree(src)

        cycles_seen: list[int] = []

        def _record(manifest: dict[str, Any]) -> None:
            cycles_seen.append(manifest["total_compiled_rules"])

        # First call: 2 iterations, but only 1 cycle should run (no mtime change
        # after the initial scan).
        cycles = watch_and_recompile(
            src, out, iterations=2, on_change=_record
        )
        assert cycles == 1
        assert cycles_seen == [2]

        # Mutate the tree, expect a second cycle.
        new_rule = dict(ATR_RULE_PROMPT_INJECTION)
        new_rule["id"] = "ATR-2026-00002"
        with open(src / "prompt-injection" / "ATR-2026-00002.yaml", "w") as fh:
            yaml.safe_dump(new_rule, fh)

        cycles = watch_and_recompile(
            src, out, iterations=2, on_change=_record
        )
        assert cycles == 1  # the change triggers exactly one recompile
        assert cycles_seen[-1] == 3


# ---------------------------------------------------------------------------
# JSON manifest
# ---------------------------------------------------------------------------


class TestManifest:
    def test_manifest_written_to_disk(self, tmp_path: Path) -> None:
        src = tmp_path / "atr"
        out = tmp_path / "out"
        manifest_path = tmp_path / "manifest.json"
        _write_atr_tree(src)

        manifest = compile_per_category(src, out)
        with open(manifest_path, "w") as fh:
            json.dump(manifest, fh)

        with open(manifest_path) as fh:
            loaded = json.load(fh)
        assert loaded["total_compiled_rules"] == 2
        assert {c["category"] for c in loaded["categories"]} == {
            "prompt-injection",
            "tool-poisoning",
        }


# ---------------------------------------------------------------------------
# CLI entry point — argument validation
# ---------------------------------------------------------------------------


def _build_cli_args(
    atr_dir: Path,
    out_dir: Path,
    *,
    watch: bool = False,
    manifest: Path | None = None,
) -> argparse.Namespace:
    """Build a Namespace matching what argparse produces for ``cmd_atr_import``."""
    return argparse.Namespace(
        atr_dir=atr_dir,
        out=out_dir,
        category=None,
        min_severity=None,
        id_prefix=None,
        strict_regex=False,
        manifest=manifest,
        watch=watch,
        watch_interval=2.0,
    )


class TestCmdAtrImportValidation:
    """CLI entry-point path validation (boundary checks before compile)."""

    def test_cli_returns_1_on_nonexistent_atr_dir(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        args = _build_cli_args(tmp_path / "does-not-exist", tmp_path / "out")
        exit_code = cmd_atr_import(args)
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "ATR rules directory does not exist" in captured.err

    def test_cli_returns_1_on_atr_dir_that_is_a_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        file_path = tmp_path / "rules.yaml"
        file_path.write_text("not a directory", encoding="utf-8")
        args = _build_cli_args(file_path, tmp_path / "out")
        exit_code = cmd_atr_import(args)
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "is not a directory" in captured.err

    def test_cli_succeeds_with_valid_paths(self, tmp_path: Path) -> None:
        src = tmp_path / "atr"
        out = tmp_path / "out"
        _write_atr_tree(src)
        args = _build_cli_args(src, out)
        assert cmd_atr_import(args) == 0
        assert (out / "prompt-injection.yaml").exists()
        assert (out / "tool-poisoning.yaml").exists()
