# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for manifest_resolution.merge: parent-deny immutability and priority validation."""

from __future__ import annotations

from typing import Any
import pytest

from agt.manifest_resolution import merge_documents
from agt.manifest_resolution import ResolutionError, ResolutionReason


def _rule(name: str, priority: Any) -> dict[str, Any]:
    return {
        "name": name,
        "condition": {"field": "tool_name", "operator": "eq", "value": name},
        "action": "allow",
        "priority": priority,
        "message": "",
    }


def _documents_with_priority(priority: Any, *, multi_document: bool) -> list[dict[str, Any]]:
    bad_rule = _rule("bad-priority", priority)
    numeric_rule = _rule("numeric-priority", 1)
    if multi_document:
        return [{"rules": [bad_rule]}, {"rules": [numeric_rule]}]
    return [{"rules": [bad_rule, numeric_rule]}]


def test_parent_deny_empty_or_drops_child_allow() -> None:
    merged = merge_documents(
        [
            {
                "rules": [
                    {
                        "name": "org-deny",
                        "action": "deny",
                        "condition": {"or": []},
                        "priority": 100,
                    }
                ]
            },
            {
                "rules": [
                    {
                        "name": "child-allow",
                        "action": "allow",
                        "condition": {
                            "field": "tool",
                            "operator": "eq",
                            "value": "shell",
                        },
                        "priority": 1,
                    }
                ]
            },
        ]
    )

    assert [rule["name"] for rule in merged] == ["org-deny"]


def test_parent_deny_unrecognized_condition_shape_drops_child_allow() -> None:
    merged = merge_documents(
        [
            {
                "rules": [
                    {
                        "name": "org-deny",
                        "action": "deny",
                        "condition": {"unknown": "shape"},
                        "priority": 100,
                    }
                ]
            },
            {
                "rules": [
                    {
                        "name": "child-allow",
                        "action": "allow",
                        "condition": {
                            "field": "tool",
                            "operator": "eq",
                            "value": "shell",
                        },
                        "priority": 1,
                    }
                ]
            },
        ]
    )

    assert [rule["name"] for rule in merged] == ["org-deny"]


def test_parent_deny_provably_disjoint_from_child_allow_keeps_child() -> None:
    merged = merge_documents(
        [
            {
                "rules": [
                    {
                        "name": "org-deny",
                        "action": "deny",
                        "condition": {
                            "field": "tool",
                            "operator": "eq",
                            "value": "delete",
                        },
                        "priority": 100,
                    }
                ]
            },
            {
                "rules": [
                    {
                        "name": "child-allow",
                        "action": "allow",
                        "condition": {
                            "field": "tool",
                            "operator": "eq",
                            "value": "shell",
                        },
                        "priority": 1,
                    }
                ]
            },
        ]
    )

    assert [rule["name"] for rule in merged] == ["org-deny", "child-allow"]


@pytest.mark.parametrize("priority", [None, "high"])
@pytest.mark.parametrize("multi_document", [False, True])
def test_merge_rejects_non_numeric_priority_as_resolution_error(
    priority: Any, multi_document: bool
) -> None:
    with pytest.raises(ResolutionError) as exc:
        merge_documents(
            _documents_with_priority(priority, multi_document=multi_document)
        )

    assert exc.value.reason == ResolutionReason.INVALID_GOVERNANCE


@pytest.mark.parametrize("multi_document", [False, True])
def test_merge_keeps_numeric_priority_sorting(multi_document: bool) -> None:
    low_rule = _rule("low", 1)
    high_rule = _rule("high", 2.5)
    if multi_document:
        documents = [{"rules": [low_rule]}, {"rules": [high_rule]}]
    else:
        documents = [{"rules": [low_rule, high_rule]}]

    merged = merge_documents(documents)

    assert [rule["name"] for rule in merged] == ["high", "low"]
