# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for manifest_resolution.discover path inspection and fail-closed IO."""

from __future__ import annotations

from pathlib import Path
import pytest
import yaml

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


def test_discover_wraps_resolve_oserror(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path
    action = root / "main.py"
    action.write_text("# code\n", encoding="utf-8")
    original_resolve = Path.resolve

    def flaky_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self == action:
            raise OSError("simulated resolve failure")
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", flaky_resolve)

    with pytest.raises(ResolutionError) as exc_info:
        discover_policies(action, root)

    assert exc_info.value.reason == ResolutionReason.PATH_TRAVERSAL


def test_discover_rejects_nonexistent_action_path(tmp_path: Path) -> None:
    root = tmp_path
    (root / "governance.yaml").write_text("rules: []\n", encoding="utf-8")
    missing_action = root / "missing" / "action.py"

    with pytest.raises(ResolutionError) as exc_info:
        discover_policies(missing_action, root)

    assert exc_info.value.reason == ResolutionReason.PATH_TRAVERSAL


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
