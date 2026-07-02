# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deep-review regression tests for migration rollback and discovery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from agt.cli import migrate as migrate_mod
from agt.manifest_resolution import ResolutionError, ResolutionReason, discover_policies


def _write_governance(path: Path, rule_name: str) -> None:
    doc = {
        "rules": [
            {
                "name": rule_name,
                "condition": {
                    "field": "tool_call.name",
                    "operator": "eq",
                    "value": "rm",
                },
                "action": "deny",
                "priority": 10,
                "message": "rm is blocked",
            }
        ],
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def test_write_chain_rollback_restores_manifest_and_generated_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    chain_root = tmp_path / "service"
    first_governance = chain_root / "governance.yaml"
    second_governance = chain_root / "governance.yml"
    manifest_path = chain_root / "manifest.yaml"
    _write_governance(first_governance, "deny_first")
    _write_governance(second_governance, "deny_second")
    manifest_path.write_text("original: manifest\n", encoding="utf-8")
    first_original = first_governance.read_text(encoding="utf-8")
    second_original = second_governance.read_text(encoding="utf-8")
    manifest_original = manifest_path.read_bytes()

    def fake_resolve_manifest(
        root: Path,
        action_path: Path,
        *,
        bundle_dir: Path,
    ) -> dict[str, Any]:
        assert root == tmp_path.resolve()
        assert action_path == chain_root
        bundle_dir.mkdir(parents=True, exist_ok=True)
        (bundle_dir / "generated.rego").write_text(
            "package agt.generated\n",
            encoding="utf-8",
        )
        return {
            "agent_control_specification_version": "1.0.0-agt",
            "metadata": {
                "resolved_from": {
                    "chain": [str(first_governance), str(second_governance)],
                }
            },
            "extends": [],
            "policies": {},
            "intervention_points": {},
        }

    original_replace = Path.replace

    def flaky_replace(self: Path, target: Path) -> Path:
        if self == second_governance:
            raise OSError("simulated second move failure")
        return original_replace(self, target)

    monkeypatch.setattr(migrate_mod, "resolve_manifest", fake_resolve_manifest)
    monkeypatch.setattr(Path, "replace", flaky_replace)

    finding = migrate_mod._migrate_governance_chain(
        chain_root,
        tmp_path,
        write=True,
    )

    assert finding.error == "write failed: simulated second move failure"
    assert manifest_path.read_bytes() == manifest_original
    assert first_governance.read_text(encoding="utf-8") == first_original
    assert second_governance.read_text(encoding="utf-8") == second_original
    assert not (chain_root / ".governance.yaml.v4-backup").exists()
    assert not (chain_root / ".governance.yml.v4-backup").exists()
    assert not (chain_root / "policy").exists()


def test_discover_allows_nonexistent_leaf_with_existing_parent(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    subdir = root / "sub"
    subdir.mkdir(parents=True)
    (root / "governance.yaml").write_text("rules: []\n", encoding="utf-8")
    (subdir / "governance.yaml").write_text("rules: []\n", encoding="utf-8")

    paths = discover_policies(subdir / "newfile.txt", root)

    assert paths == [
        (root / "governance.yaml").resolve(),
        (subdir / "governance.yaml").resolve(),
    ]


def test_discover_rejects_nonexistent_leaf_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()

    with pytest.raises(ResolutionError) as exc_info:
        discover_policies(outside / "newfile.txt", root)

    assert exc_info.value.reason == ResolutionReason.PATH_TRAVERSAL
