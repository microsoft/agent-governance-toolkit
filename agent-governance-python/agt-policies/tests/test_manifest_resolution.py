# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agt.manifest_resolution.

Cover the contract documented in
``policy-engine/spec/agt/AGT-RESOLUTION-1.0.md`` and the reserved
resolution reasons in ``policy-engine/spec/SPECIFICATION.md`` §16.
"""

from __future__ import annotations

import random
import re
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


def test_discover_rejects_out_of_root_governance_symlink(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "attacker.yaml").write_text("rules: []\n", encoding="utf-8")
    (root / "governance.yaml").symlink_to(outside / "attacker.yaml")

    with pytest.raises(ResolutionError) as exc:
        discover_policies(root, root)

    assert exc.value.reason == ResolutionReason.PATH_TRAVERSAL


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


def test_filter_trailing_slash_scope_matches_subtree(tmp_path: Path) -> None:
    root = tmp_path
    action = root / "src" / "secure" / "pay.py"
    action.parent.mkdir(parents=True)
    action.touch()

    assert filter_by_scope(root / "p", "src/secure/", action, root) is True


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


def _rule_with_condition(
    name: str, action: str, condition: dict, priority: int = 0
) -> dict:
    return {
        "name": name,
        "condition": condition,
        "action": action,
        "priority": priority,
        "override": False,
        "message": "",
    }


def _value_at(sample: dict, field: str) -> object:
    current: object = sample
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _condition_matches(condition: object, sample: dict) -> bool:
    if not isinstance(condition, dict):
        return False
    if "and" in condition:
        items = condition["and"]
        return isinstance(items, list) and all(
            _condition_matches(item, sample) for item in items
        )
    if "or" in condition:
        items = condition["or"]
        return isinstance(items, list) and any(
            _condition_matches(item, sample) for item in items
        )
    if "not" in condition:
        return not _condition_matches(condition["not"], sample)

    field = condition.get("field")
    operator = condition.get("operator")
    expected = condition.get("value")
    if not isinstance(field, str) or not isinstance(operator, str):
        return False
    actual = _value_at(sample, field)
    try:
        if operator == "exists":
            return actual is not None
        if actual is None:
            return False
        if operator == "eq":
            return actual == expected
        if operator == "ne":
            return actual != expected
        if operator == "gt":
            return actual > expected
        if operator == "gte":
            return actual >= expected
        if operator == "lt":
            return actual < expected
        if operator == "lte":
            return actual <= expected
        if operator == "in":
            return isinstance(expected, list) and actual in expected
        if operator == "not_in":
            return isinstance(expected, list) and actual not in expected
        if operator == "contains":
            return expected in actual
        if operator == "startswith":
            return (
                isinstance(actual, str)
                and isinstance(expected, str)
                and actual.startswith(expected)
            )
        if operator == "endswith":
            return (
                isinstance(actual, str)
                and isinstance(expected, str)
                and actual.endswith(expected)
            )
        if operator in {"matches", "regex"}:
            return (
                isinstance(actual, str)
                and isinstance(expected, str)
                and re.search(expected, actual) is not None
            )
    except (TypeError, re.error):
        return False
    return False


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


def test_merge_child_allow_with_different_name_cannot_neutralize_parent_deny() -> None:
    parent = {"rules": [_rule("org_deny", "deny", 10)]}
    child = {"rules": [_rule("child_allow", "allow", 99)]}

    merged = merge_documents([parent, child])

    assert [rule["name"] for rule in merged] == ["org_deny"]
    assert merged[0]["action"] == "deny"


def test_merge_child_allow_on_different_field_overlaps_parent_deny() -> None:
    parent = {
        "rules": [
            _rule_with_condition(
                "org_deny",
                "deny",
                {"field": "tool_name", "operator": "eq", "value": "export"},
                10,
            )
        ]
    }
    child = {
        "rules": [
            _rule_with_condition(
                "child_allow",
                "allow",
                {"field": "principal", "operator": "eq", "value": "alice"},
                99,
            )
        ]
    }

    merged = merge_documents([parent, child])

    assert [rule["name"] for rule in merged] == ["org_deny"]


def test_merge_ne_overlap_drops_child_allow() -> None:
    parent = {
        "rules": [
            _rule_with_condition(
                "org_deny",
                "deny",
                {"field": "tool_name", "operator": "eq", "value": "delete"},
                10,
            )
        ]
    }
    child = {
        "rules": [
            _rule_with_condition(
                "child_allow",
                "allow",
                {"field": "tool_name", "operator": "ne", "value": "read"},
                99,
            )
        ]
    }

    merged = merge_documents([parent, child])

    assert [rule["name"] for rule in merged] == ["org_deny"]


def test_merge_preserves_provably_disjoint_ne_child_allow() -> None:
    parent = {
        "rules": [
            _rule_with_condition(
                "org_deny",
                "deny",
                {"field": "tool_name", "operator": "eq", "value": "delete"},
                10,
            )
        ]
    }
    child = {
        "rules": [
            _rule_with_condition(
                "child_allow",
                "allow",
                {"field": "tool_name", "operator": "ne", "value": "delete"},
                99,
            )
        ]
    }

    merged = merge_documents([parent, child])

    assert [rule["name"] for rule in merged] == ["child_allow", "org_deny"]


def test_merge_contains_and_matches_overlap_drop_child_allow() -> None:
    parent = {
        "rules": [
            _rule_with_condition(
                "org_deny",
                "deny",
                {"field": "prompt", "operator": "eq", "value": "please delete all"},
                10,
            )
        ]
    }
    child = {
        "rules": [
            _rule_with_condition(
                "contains_allow",
                "allow",
                {"field": "prompt", "operator": "contains", "value": "delete"},
                99,
            ),
            _rule_with_condition(
                "matches_allow",
                "allow",
                {"field": "prompt", "operator": "matches", "value": "delete"},
                98,
            ),
        ]
    }

    merged = merge_documents([parent, child])

    assert [rule["name"] for rule in merged] == ["org_deny"]


def test_merge_preserves_provably_disjoint_contains_child_allow() -> None:
    parent = {
        "rules": [
            _rule_with_condition(
                "org_deny",
                "deny",
                {"field": "prompt", "operator": "eq", "value": "read only"},
                10,
            )
        ]
    }
    child = {
        "rules": [
            _rule_with_condition(
                "child_allow",
                "allow",
                {"field": "prompt", "operator": "contains", "value": "delete"},
                99,
            )
        ]
    }

    merged = merge_documents([parent, child])

    assert [rule["name"] for rule in merged] == ["child_allow", "org_deny"]


def test_merge_compound_conditions_drop_on_possible_overlap() -> None:
    parent = {
        "rules": [
            _rule_with_condition(
                "org_deny",
                "deny",
                {
                    "or": [
                        {"field": "tool_name", "operator": "eq", "value": "delete"},
                        {"field": "tool_name", "operator": "eq", "value": "export"},
                    ]
                },
                10,
            )
        ]
    }
    child = {
        "rules": [
            _rule_with_condition(
                "child_allow",
                "allow",
                {"field": "tool_name", "operator": "eq", "value": "export"},
                99,
            )
        ]
    }

    merged = merge_documents([parent, child])

    assert [rule["name"] for rule in merged] == ["org_deny"]


def test_merge_compound_conditions_preserve_provably_disjoint_child_allow() -> None:
    parent = {
        "rules": [
            _rule_with_condition(
                "org_deny",
                "deny",
                {
                    "and": [
                        {"field": "tool_name", "operator": "eq", "value": "delete"},
                        {"field": "environment", "operator": "eq", "value": "prod"},
                    ]
                },
                10,
            )
        ]
    }
    child = {
        "rules": [
            _rule_with_condition(
                "child_allow",
                "allow",
                {"field": "environment", "operator": "eq", "value": "dev"},
                99,
            )
        ]
    }

    merged = merge_documents([parent, child])

    assert [rule["name"] for rule in merged] == ["child_allow", "org_deny"]


def test_merge_not_condition_fails_closed_as_overlapping() -> None:
    parent = {
        "rules": [
            _rule_with_condition(
                "org_deny",
                "deny",
                {"field": "tool_name", "operator": "eq", "value": "delete"},
                10,
            )
        ]
    }
    child = {
        "rules": [
            _rule_with_condition(
                "child_allow",
                "allow",
                {"not": {"field": "principal", "operator": "eq", "value": "mallory"}},
                99,
            )
        ]
    }

    merged = merge_documents([parent, child])

    assert [rule["name"] for rule in merged] == ["org_deny"]


def _matching_scalar_condition(rng: random.Random, sample: dict) -> dict:
    field = rng.choice(["tool_name", "principal", "amount", "prompt"])
    actual = _value_at(sample, field)
    if isinstance(actual, int):
        operator = rng.choice(
            ["eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "exists"]
        )
        if operator == "eq":
            value = actual
        elif operator == "ne":
            value = actual + 1000
        elif operator == "gt":
            value = actual - 1
        elif operator == "gte":
            value = actual
        elif operator == "lt":
            value = actual + 1
        elif operator == "lte":
            value = actual
        elif operator == "in":
            value = [actual, actual + 1]
        elif operator == "not_in":
            value = [actual + 1, actual + 2]
        else:
            value = True
        return {"field": field, "operator": operator, "value": value}

    text = str(actual)
    substring = text[: max(1, min(len(text), 3))]
    operator = rng.choice(
        [
            "eq",
            "ne",
            "in",
            "not_in",
            "contains",
            "startswith",
            "endswith",
            "matches",
            "exists",
        ]
    )
    if operator == "eq":
        value = text
    elif operator == "ne":
        value = f"not-{text}"
    elif operator == "in":
        value = [text, f"other-{text}"]
    elif operator == "not_in":
        value = [f"other-{text}"]
    elif operator == "contains":
        value = substring
    elif operator == "startswith":
        value = text[:1]
    elif operator == "endswith":
        value = text[-1:]
    elif operator == "matches":
        value = re.escape(substring)
    else:
        value = True
    return {"field": field, "operator": operator, "value": value}


def _matching_condition(rng: random.Random, sample: dict, depth: int = 0) -> dict:
    if depth < 2:
        form = rng.choice(["scalar", "and", "or", "not"])
    else:
        form = "scalar"
    if form == "and":
        return {
            "and": [
                _matching_condition(rng, sample, depth + 1),
                _matching_condition(rng, sample, depth + 1),
            ]
        }
    if form == "or":
        return {
            "or": [
                _matching_condition(rng, sample, depth + 1),
                {"field": "tool_name", "operator": "eq", "value": "never-matches"},
            ]
        }
    if form == "not":
        return {
            "not": {"field": "tool_name", "operator": "eq", "value": "never-matches"}
        }
    return _matching_scalar_condition(rng, sample)


def test_merge_property_drops_allow_when_sample_matches_parent_and_child() -> None:
    rng = random.Random(1337)
    for index in range(150):
        sample = {
            "tool_name": rng.choice(["delete", "export", "read"]),
            "principal": rng.choice(["alice", "bob", "carol"]),
            "amount": rng.randint(1, 100),
            "prompt": rng.choice(
                ["delete all records", "export customer data", "read report"]
            ),
        }
        parent_condition = _matching_condition(rng, sample)
        child_condition = _matching_condition(rng, sample)
        assert _condition_matches(parent_condition, sample)
        assert _condition_matches(child_condition, sample)

        parent = {
            "rules": [_rule_with_condition("org_deny", "deny", parent_condition, 10)]
        }
        child = {
            "rules": [_rule_with_condition("child_allow", "allow", child_condition, 99)]
        }

        merged = merge_documents([parent, child])

        assert "child_allow" not in [rule["name"] for rule in merged], (
            index,
            parent_condition,
            child_condition,
        )


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


def _legacy_binding() -> dict:
    return {
        "pre_tool_call": {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "tool_name_from": "$.tool_call.name",
            "policy": {"id": "agt_legacy_rules"},
        }
    }


def test_resolve_emits_flat_acs_manifest(tmp_path: Path) -> None:
    root = tmp_path
    _write(
        root / "governance.yaml",
        {
            "rules": [_rule("r1", "deny", 10)],
            "tools": {"t": {"clearance": "public"}},
            "intervention_points": _legacy_binding(),
        },
    )

    manifest = resolve_manifest(root, root)

    assert manifest["agent_control_specification_version"] == "0.3.0-alpha-agt"
    assert manifest["extends"] == []
    assert "agt_legacy_rules" in manifest["policies"]
    assert manifest["policies"]["agt_legacy_rules"]["type"] == "rego"
    assert (
        manifest["policies"]["agt_legacy_rules"]["query"] == "data.agt.legacy.verdict"
    )
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
    _write(
        root / "governance.yaml",
        {"rules": [_rule("p", "deny", 5)], "intervention_points": _legacy_binding()},
    )
    _write(
        sub / "governance.yaml",
        {
            "inherit": False,
            "rules": [_rule("c", "allow", 1)],
            "intervention_points": _legacy_binding(),
        },
    )

    manifest = resolve_manifest(root, sub)
    metadata = manifest["metadata"]["resolved_from"]
    # only the child governance file remained in the chain
    assert (
        len(metadata["chain"]) == 2
    )  # discovery sees both, _apply_inheritance trims later
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
    _write(
        root / "governance.yaml",
        {
            "scope": "src/payments/*",
            "rules": [_rule("p", "deny", 5)],
            "intervention_points": _legacy_binding(),
        },
    )
    _write(
        sub / "governance.yaml",
        {"rules": [_rule("c", "allow", 1)], "intervention_points": _legacy_binding()},
    )

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
    _write(
        root / "governance.yaml",
        {
            "rules": [_rule("p", "allow", 0)],
            "intervention_points": {
                "pre_tool_call": {
                    "policy_target": "$.tool_call.args",
                    "policy_target_kind": "tool_args",
                    "tool_name_from": "$.tool_call.name",
                    "policy": {"id": "agt_legacy_rules"},
                    "annotations": {
                        "parent_note": {"from": "$pi.snapshot.envelope.agent.id"}
                    },
                }
            },
        },
    )
    _write(
        sub / "governance.yaml",
        {
            "rules": [_rule("c", "allow", 0)],
            "intervention_points": {
                "pre_tool_call": {
                    "policy_target": "$.tool_call.args",
                    "policy_target_kind": "tool_args",
                    "tool_name_from": "$.tool_call.name",
                    "policy": {"id": "agt_legacy_rules"},
                    "annotations": {
                        "child_note": {"from": "$pi.snapshot.envelope.session.id"}
                    },
                }
            },
        },
    )

    manifest = resolve_manifest(root, sub)
    annotations = manifest["intervention_points"]["pre_tool_call"]["annotations"]
    assert set(annotations.keys()) == {"parent_note", "child_note"}


def test_resolve_writes_default_bundle_outside_workspace(tmp_path: Path) -> None:
    root = tmp_path
    _write(root / "governance.yaml", {"rules": []})
    manifest = resolve_manifest(root, root)
    bundle_path = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    # The default bundle location is a unique temp directory outside the
    # governed workspace so agent-writable source files cannot clobber it.
    assert root not in bundle_path.parents
    sha_file = bundle_path / "agt_legacy.rego.sha256"
    assert sha_file.is_file()
    assert len(sha_file.read_text().strip()) == 64  # hex sha256


def test_resolve_invalid_field_syntax_fails_closed(tmp_path: Path) -> None:
    root = tmp_path
    _write(
        root / "governance.yaml",
        {
            "rules": [
                _rule_with_condition(
                    "bad-field",
                    "deny",
                    {"field": "tool_call.args.amount-usd", "operator": "eq", "value": 1},
                )
            ],
            "intervention_points": _legacy_binding(),
        },
    )

    manifest = resolve_manifest(root, root)
    bundle = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    rego = (bundle / "agt_legacy.rego").read_text(encoding="utf-8")

    assert "runtime_error:manifest_invalid" in rego
    assert "invalid field" in rego


def test_resolve_fails_closed_when_legacy_rules_unbound(tmp_path: Path) -> None:
    root = tmp_path
    _write(
        root / "governance.yaml",
        {
            "rules": [_rule("must-bind", "deny", 10)],
            "intervention_points": {
                "pre_tool_call": {
                    "policy_target": "$.tool_call.args",
                    "policy_target_kind": "tool_args",
                    "tool_name_from": "$.tool_call.name",
                    "policy": {"id": "other_policy"},
                }
            },
        },
    )

    with pytest.raises(ResolutionError) as exc:
        resolve_manifest(root, root)

    assert exc.value.reason == ResolutionReason.INVALID_GOVERNANCE


@pytest.mark.parametrize(
    ("operator", "value", "expected_snippet"),
    [
        ("not_in", ["secret", "token"], "not _v in"),
        ("startswith", "sec", "startswith(_v"),
        ("endswith", "ret", "endswith(_v"),
        ("exists", None, "!= null"),
        ("regex", "sec.*", "regex.match"),
    ],
)
def test_resolve_renders_operator_vocabulary(
    tmp_path: Path, operator: str, value: object, expected_snippet: str
) -> None:
    root = tmp_path
    _write(
        root / "governance.yaml",
        {
            "rules": [
                _rule_with_condition(
                    f"op-{operator}",
                    "deny",
                    {"field": "tool_call.args.q", "operator": operator, "value": value},
                )
            ],
            "intervention_points": _legacy_binding(),
        },
    )

    manifest = resolve_manifest(root, root)
    bundle = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    rego = (bundle / "agt_legacy.rego").read_text(encoding="utf-8")

    assert expected_snippet in rego
    assert "runtime_error:manifest_invalid" not in rego


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
    assert (
        ResolutionReason.PATH_TRAVERSAL.value
        == "runtime_error:resolution_path_traversal"
    )
    assert ResolutionReason.CYCLE.value == "runtime_error:resolution_cycle"
    assert (
        ResolutionReason.INVALID_GOVERNANCE.value
        == "runtime_error:resolution_invalid_governance"
    )
    assert (
        ResolutionReason.MERGE_CONFLICT.value
        == "runtime_error:resolution_merge_conflict"
    )


def test_resolution_error_message_includes_reason_string() -> None:
    err = ResolutionError.path_traversal("detail-x")
    assert "runtime_error:resolution_path_traversal" in str(err)
    assert "detail-x" in str(err)


# ── #3297: negative operators must fail closed in deny rules ──────────
#
# A field accessor resolves a missing field to `null` (object.get(..., null)),
# so the `_v != null` guard emitted before a comparison makes an absent field
# fail the match. For `ne`/`not_in` in a *deny* rule that is fail-open: the deny
# is bypassed by omitting the field. The guard must be dropped for `deny` (so an
# absent field fires the deny) and kept for `allow` (so an absent field does not
# fire an allow, which would itself be fail-open).


def _op_clause(operator: str, action: str) -> str:
    from agt.manifest_resolution.build import _rego_field_accessor, _rego_op_clause

    # Both helpers are Optional-returning: the accessor is None for a field
    # path that is not a simple identifier, and the clause is None for an
    # unsupported operator. Neither applies here, so assert rather than
    # propagate None -- a silent None would surface as an opaque TypeError
    # from the `in` checks below instead of naming what failed to render.
    accessor = _rego_field_accessor("tool_call.field")
    assert accessor is not None, "expected an accessor for 'tool_call.field'"
    clause = _rego_op_clause(operator, accessor, "X", action)
    assert clause is not None, f"expected a clause for operator {operator!r}"
    return clause


@pytest.mark.parametrize("operator", ["ne", "not_in"])
def test_negative_operator_deny_drops_null_guard(operator: str) -> None:
    # deny: missing field (null) must fire the rule -> no `_v != null` guard
    assert "_v != null" not in _op_clause(operator, "deny")


@pytest.mark.parametrize("operator", ["ne", "not_in"])
def test_negative_operator_allow_keeps_null_guard(operator: str) -> None:
    # allow: missing field must NOT fire the rule (else fail-open) -> guard kept
    assert "_v != null" in _op_clause(operator, "allow")


@pytest.mark.parametrize("operator", ["gt", "gte", "lt", "lte", "in", "contains"])
def test_positive_operators_keep_null_guard_regardless_of_action(operator: str) -> None:
    # positive operators are unaffected by #3297 and keep their guard for both actions
    assert "_v != null" in _op_clause(operator, "deny")
    assert "_v != null" in _op_clause(operator, "allow")


def test_deny_negative_operator_missing_field_fires_deny_branch() -> None:
    # end-to-end at the render level: a deny `ne` on a pinned field renders a
    # match body that an absent field (null) satisfies, so the deny branch fires.
    from agt.manifest_resolution.build import _render_rego

    rego = _render_rego(
        [
            {
                "name": "pin",
                "action": "deny",
                "condition": {
                    "field": "tool_call.content_hash",
                    "operator": "ne",
                    "value": "sha256:REGISTERED",
                },
            }
        ]
    )
    match_body = rego.split("_match_0 if {", 1)[1].split("}", 1)[0]
    assert "_v != null" not in match_body
    assert '_v != "sha256:REGISTERED"' in match_body


# ── #3297: field accessor must yield null for a missing INTERMEDIATE segment ──
#
# The former chained `object.get(object.get(snapshot, "a", null), "b", null)`
# returns *undefined* when `a` is missing (object.get on a null parent), which
# silently failed the match and left a second fail-open path for deny rules,
# reachable by omitting a parent object. The array-path accessor resolves any
# missing segment to the `null` default.


def test_field_accessor_uses_array_path() -> None:
    from agt.manifest_resolution.build import _rego_field_accessor

    acc = _rego_field_accessor("tool_call.args.region")
    # single object.get over an array path, not a chain of nested object.get calls
    assert acc == 'object.get(input.snapshot, ["tool_call", "args", "region"], null)'
    assert acc.count("object.get") == 1


def test_field_accessor_still_rejects_injection() -> None:
    from agt.manifest_resolution.build import _rego_field_accessor

    assert _rego_field_accessor("tool_call.bad-part") is None
    assert _rego_field_accessor("a.b[0]") is None


def test_field_accessor_empty_field_is_snapshot_root() -> None:
    from agt.manifest_resolution.build import _rego_field_accessor

    assert _rego_field_accessor("") == "input.snapshot"


def test_deny_negative_operator_missing_intermediate_still_fires() -> None:
    # end-to-end at render level: a deny `not_in` on a nested field renders a
    # match body whose accessor yields null when the PARENT is absent, so the
    # deny still fires (no chained-object.get undefined hole).
    from agt.manifest_resolution.build import _render_rego

    rego = _render_rego(
        [
            {
                "name": "region",
                "action": "deny",
                "condition": {
                    "field": "tool_call.args.region",
                    "operator": "not_in",
                    "value": ["US", "EU"],
                },
            }
        ]
    )
    match_body = rego.split("_match_0 if {", 1)[1].split("}", 1)[0]
    assert 'object.get(input.snapshot, ["tool_call", "args", "region"], null)' in match_body
    assert "_v != null" not in match_body
