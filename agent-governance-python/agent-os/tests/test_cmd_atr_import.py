# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ``agentos atr-import``.

Covers per-category compilation, severity / category filters, the watch
loop's change detection, and integration with the PR #908 conversion
helpers in ``examples/atr-community-rules/sync_atr_rules.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from agent_os.cli.cmd_atr_import import (
    compile_per_category,
    watch_and_recompile,
)

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
        from agent_os.policies.schema import PolicyDocument

        src = tmp_path / "atr"
        out = tmp_path / "out"
        _write_atr_tree(src)
        compile_per_category(src, out)

        for path in out.glob("*.yaml"):
            with open(path) as fh:
                data = yaml.safe_load(fh)
            # If this raises, the emit isn't schema-compatible with AGT.
            document = PolicyDocument(**data)
            assert document.rules, f"{path.name} emitted no rules"

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
