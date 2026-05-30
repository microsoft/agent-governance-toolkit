# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agt.manifest_resolution.

Cover the contract documented in
``policy-engine/spec/agt/AGT-RESOLUTION-1.0.md`` and the deltas in
``policy-engine/spec/SPECIFICATION-AGT-DELTA.md`` §D6.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agt.manifest_resolution import (
    ResolutionError,
    ResolutionReason,
    discover_policies,
    filter_by_scope,
    merge_documents,
    resolve_manifest,
)
from agt.manifest_resolution.merge import merge_top_level_section


# ── discover_policies ────────────────────────────────────────────────


def test_discover_returns_root_first_order(tmp_path: Path) -> None:
    root = tmp_path
    deep = root / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (root / "governance.yaml").write_text("rules: []\n")
    (root / "a" / "governance.yaml").write_text("rules: []\n")
    (deep / "governance.yaml").write_text("rules: []\n")

    paths = discover_policies(deep, root)
    assert [p.parent.name for p in paths] == [root.name, "a", "c"]


def test_discover_skips_directories_without_governance(tmp_path: Path) -> None:
    root = tmp_path
    (root / "a" / "b").mkdir(parents=True)
    (root / "governance.yaml").write_text("rules: []\n")
    (root / "a" / "b" / "governance.yaml").write_text("rules: []\n")

    paths = discover_policies(root / "a" / "b", root)
    assert [p.parent.name for p in paths] == [root.name, "b"]


def test_discover_prefers_governance_yaml_over_yml(tmp_path: Path) -> None:
    root = tmp_path
    (root / "governance.yaml").write_text("rules: []\n")
    (root / "governance.yml").write_text("rules: []\n")

    paths = discover_policies(root, root)
    assert len(paths) == 1
    assert paths[0].name == "governance.yaml"


def test_discover_path_traversal_fails_closed(tmp_path: Path) -> None:
    """AGT-RESOLUTION §2.1: action_path outside root MUST fail closed,
    NOT silently allow."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "governance.yaml").write_text("rules: []\n")
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(ResolutionError) as exc_info:
        discover_policies(outside, root)

    assert exc_info.value.reason == ResolutionReason.PATH_TRAVERSAL


def test_discover_action_path_can_be_file(tmp_path: Path) -> None:
    root = tmp_path
    (root / "governance.yaml").write_text("rules: []\n")
    file_action = root / "main.py"
    file_action.write_text("# code\n")
    paths = discover_policies(file_action, root)
    assert len(paths) == 1


# ── filter_by_scope ──────────────────────────────────────────────────


def test_filter_no_scope_always_applies(tmp_path: Path) -> None:
    assert filter_by_scope(tmp_path / "p", None, tmp_path / "x", tmp_path) is True


def test_filter_glob_match(tmp_path: Path) -> None:
    root = tmp_path
    action = root / "src" / "payments" / "wire.py"
    action.parent.mkdir(parents=True)
    action.touch()
    assert filter_by_scope(root / "p", "src/payments/*", action, root) is True
    assert filter_by_scope(root / "p", "src/auth/*", action, root) is False


def test_filter_uses_forward_slashes(tmp_path: Path) -> None:
    root = tmp_path
    action = root / "a" / "b" / "c.py"
    action.parent.mkdir(parents=True)
    action.touch()
    assert filter_by_scope(root / "p", "a/b/*.py", action, root) is True


# ── merge_documents (deny immutability) ──────────────────────────────


def _rule(name: str, action: str, priority: int = 0, override: bool = False) -> dict:
    return {
        "name": name,
        "condition": {"field": "tool_name", "operator": "eq", "value": "x"},
        "action": action,
        "priority": priority,
        "override": override,
        "message": "",
    }


def test_merge_single_document_sorts_by_priority() -> None:
    doc = {"rules": [_rule("a", "allow", 1), _rule("b", "deny", 5)]}
    merged = merge_documents([doc])
    assert [r["name"] for r in merged] == ["b", "a"]


def test_merge_unique_names_are_concatenated() -> None:
    parent = {"rules": [_rule("p1", "allow", 1)]}
    child = {"rules": [_rule("c1", "deny", 5)]}
    merged = merge_documents([parent, child])
    assert [r["name"] for r in merged] == ["c1", "p1"]


def test_merge_child_override_replaces_non_deny_parent() -> None:
    parent = {"rules": [_rule("shared", "allow", 1)]}
    child = {"rules": [_rule("shared", "warn", 10, override=True)]}
    merged = merge_documents([parent, child])
    assert merged == [
        {
            "name": "shared",
            "condition": {"field": "tool_name", "operator": "eq", "value": "x"},
            "action": "warn",
            "priority": 10,
            "override": True,
            "message": "",
        }
    ]


def test_merge_child_override_DROPPED_when_parent_is_deny() -> None:
    """Deny-immutability invariant per AGT-RESOLUTION §2.4."""
    parent = {"rules": [_rule("shared", "deny", 1)]}
    child = {"rules": [_rule("shared", "allow", 99, override=True)]}
    merged = merge_documents([parent, child])
    # child override dropped; parent deny remains
    assert merged == [
        {
            "name": "shared",
            "condition": {"field": "tool_name", "operator": "eq", "value": "x"},
            "action": "deny",
            "priority": 1,
            "override": False,
            "message": "",
        }
    ]


def test_merge_child_without_override_DROPPED() -> None:
    parent = {"rules": [_rule("shared", "allow", 1)]}
    child = {"rules": [_rule("shared", "deny", 99, override=False)]}
    merged = merge_documents([parent, child])
    # parent allow survives because child did not declare override
    assert merged[0]["action"] == "allow"
    assert merged[0]["priority"] == 1


def test_merge_invalid_document_raises_invalid_governance() -> None:
    with pytest.raises(ResolutionError) as exc:
        merge_documents([{"rules": [{"action": "deny"}]}])  # missing name
    assert exc.value.reason == ResolutionReason.INVALID_GOVERNANCE


def test_merge_non_dict_document_raises() -> None:
    with pytest.raises(ResolutionError) as exc:
        merge_documents(["not-a-dict"])  # type: ignore[list-item]
    assert exc.value.reason == ResolutionReason.INVALID_GOVERNANCE


# ── merge_top_level_section ──────────────────────────────────────────


def test_merge_top_dicts_combine_with_later_winning() -> None:
    merged = merge_top_level_section(
        "tools",
        [
            {"tools": {"a": {"x": 1}, "b": {"y": 2}}},
            {"tools": {"a": {"x": 99}, "c": {"z": 3}}},
        ],
    )
    assert merged == {"a": {"x": 99}, "b": {"y": 2}, "c": {"z": 3}}


def test_merge_top_lists_concatenate() -> None:
    merged = merge_top_level_section(
        "tags",
        [{"tags": ["a", "b"]}, {"tags": ["c"]}],
    )
    assert merged == ["a", "b", "c"]


def test_merge_top_incompatible_types_raise() -> None:
    with pytest.raises(ResolutionError) as exc:
        merge_top_level_section("x", [{"x": {"k": 1}}, {"x": [1, 2]}])
    assert exc.value.reason == ResolutionReason.MERGE_CONFLICT


def test_merge_top_absent_section_returns_none() -> None:
    assert merge_top_level_section("missing", [{"other": 1}]) is None


# ── resolve_manifest end-to-end ──────────────────────────────────────


def _write(path: Path, doc: dict) -> None:
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")


def test_resolve_emits_flat_acs_manifest(tmp_path: Path) -> None:
    root = tmp_path
    _write(root / "governance.yaml", {
        "rules": [_rule("r1", "deny", 10)],
        "tools": {"t": {"clearance": "public"}},
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    })

    manifest = resolve_manifest(root, root)

    assert manifest["agent_control_specification_version"] == "0.3.0-alpha-agt"
    assert manifest["extends"] == []
    assert "agt_legacy_rules" in manifest["policies"]
    assert manifest["policies"]["agt_legacy_rules"]["type"] == "rego"
    assert manifest["policies"]["agt_legacy_rules"]["query"] == "data.agt.legacy.verdict"
    bundle_path = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    assert bundle_path.is_dir()
    assert (bundle_path / "agt_legacy.rego").is_file()
    assert "pre_tool_call" in manifest["intervention_points"]
    assert manifest["tools"] == {"t": {"clearance": "public"}}


def test_resolve_no_governance_file_fails_closed(tmp_path: Path) -> None:
    """Per AGT-RESOLUTION §5: no fallback empty manifest. Missing
    governance MUST fail closed in v5."""
    with pytest.raises(ResolutionError) as exc:
        resolve_manifest(tmp_path, tmp_path)
    assert exc.value.reason == ResolutionReason.INVALID_GOVERNANCE


def test_resolve_path_traversal_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    _write(root / "governance.yaml", {"rules": []})
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ResolutionError) as exc:
        resolve_manifest(root, outside)
    assert exc.value.reason == ResolutionReason.PATH_TRAVERSAL


def test_resolve_inherit_false_truncates_chain(tmp_path: Path) -> None:
    root = tmp_path
    sub = root / "a"
    sub.mkdir()
    _write(root / "governance.yaml", {"rules": [_rule("p", "deny", 5)]})
    _write(sub / "governance.yaml", {
        "inherit": False,
        "rules": [_rule("c", "allow", 1)],
    })

    manifest = resolve_manifest(root, sub)
    metadata = manifest["metadata"]["resolved_from"]
    # only the child governance file remained in the chain
    assert len(metadata["chain"]) == 2  # discovery sees both, _apply_inheritance trims later
    bundle = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    rego = (bundle / "agt_legacy.rego").read_text(encoding="utf-8")
    # Only the child's rule should be in the rendered rules; reason
    # carries the rule name in the generated verdict body.
    assert '"reason": "c"' in rego
    assert '"reason": "p"' not in rego


def test_resolve_scope_filter_drops_non_matching(tmp_path: Path) -> None:
    root = tmp_path
    sub = root / "src" / "auth"
    sub.mkdir(parents=True)
    _write(root / "governance.yaml", {
        "scope": "src/payments/*",
        "rules": [_rule("p", "deny", 5)],
    })
    _write(sub / "governance.yaml", {"rules": [_rule("c", "allow", 1)]})

    action = sub / "login.py"
    action.touch()
    manifest = resolve_manifest(root, action)
    bundle = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    rego = (bundle / "agt_legacy.rego").read_text(encoding="utf-8")
    assert '"reason": "p"' not in rego  # parent scope did not match
    assert '"reason": "c"' in rego


def test_resolve_intervention_points_union_annotations(tmp_path: Path) -> None:
    root = tmp_path
    sub = root / "a"
    sub.mkdir()
    _write(root / "governance.yaml", {
        "rules": [_rule("p", "allow", 0)],
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
                "annotations": {"parent_note": {"from": "$pi.snapshot.envelope.agent.id"}},
            }
        },
    })
    _write(sub / "governance.yaml", {
        "rules": [_rule("c", "allow", 0)],
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
                "annotations": {"child_note": {"from": "$pi.snapshot.envelope.session.id"}},
            }
        },
    })

    manifest = resolve_manifest(root, sub)
    annotations = manifest["intervention_points"]["pre_tool_call"]["annotations"]
    assert set(annotations.keys()) == {"parent_note", "child_note"}


def test_resolve_writes_bundle_under_root_by_default(tmp_path: Path) -> None:
    root = tmp_path
    _write(root / "governance.yaml", {"rules": []})
    manifest = resolve_manifest(root, root)
    bundle_path = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    # Default bundle location is root/.agt/resolved-bundle/policy
    assert str(bundle_path).startswith(str(root / ".agt"))
    sha_file = bundle_path / "agt_legacy.rego.sha256"
    assert sha_file.is_file()
    assert len(sha_file.read_text().strip()) == 64  # hex sha256


def test_resolve_explicit_bundle_dir(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    _write(root / "governance.yaml", {"rules": []})
    out_dir = tmp_path / "build"
    manifest = resolve_manifest(root, root, bundle_dir=out_dir)
    bundle_path = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    assert bundle_path == (out_dir / "policy").resolve()


# ── ResolutionError shape ────────────────────────────────────────────


def test_resolution_reason_strings_match_d6() -> None:
    """D6 reserved reasons MUST match the host-emitted strings byte-for-byte."""
    assert ResolutionReason.PATH_TRAVERSAL.value == "runtime_error:resolution_path_traversal"
    assert ResolutionReason.CYCLE.value == "runtime_error:resolution_cycle"
    assert ResolutionReason.INVALID_GOVERNANCE.value == "runtime_error:resolution_invalid_governance"
    assert ResolutionReason.MERGE_CONFLICT.value == "runtime_error:resolution_merge_conflict"


def test_resolution_error_message_includes_reason_string() -> None:
    err = ResolutionError.path_traversal("detail-x")
    assert "runtime_error:resolution_path_traversal" in str(err)
    assert "detail-x" in str(err)
