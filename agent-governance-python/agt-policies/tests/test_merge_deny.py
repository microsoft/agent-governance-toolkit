# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for agt.manifest_resolution.merge robustness fixes.

Covers the non-numeric ``priority`` TypeError fix and pins the deny-immutability
(ADR-0014) behavior across the ``_conditions_disjoint`` refactor that stops the
unsatisfiability heuristic from neutralising a parent deny.
"""

from __future__ import annotations

from typing import Any

import pytest

from agt.manifest_resolution.errors import ResolutionError
from agt.manifest_resolution.merge import _conditions_overlap, merge_documents


def _doc(rules: list[dict[str, Any]]) -> dict[str, Any]:
    return {"rules": rules}


# ── priority validation (TypeError fix) ────────────────────────────────────


@pytest.mark.parametrize("bad", [None, "high", True])
def test_non_numeric_priority_raises_resolution_error(bad: Any) -> None:
    with pytest.raises(ResolutionError):
        merge_documents([_doc([{"name": "r", "action": "allow", "priority": bad}])])


def test_valid_priority_sorts_descending() -> None:
    out = merge_documents(
        [_doc([
            {"name": "lo", "action": "allow", "priority": 1},
            {"name": "hi", "action": "allow", "priority": 5},
            {"name": "mid", "action": "allow", "priority": 3.5},
        ])]
    )
    assert [r["name"] for r in out] == ["hi", "mid", "lo"]


def test_absent_priority_defaults_to_zero() -> None:
    out = merge_documents(
        [_doc([
            {"name": "explicit", "action": "allow", "priority": 2},
            {"name": "default", "action": "allow"},  # -> 0
        ])]
    )
    assert [r["name"] for r in out] == ["explicit", "default"]


# ── deny immutability (ADR-0014) ───────────────────────────────────────────


def test_child_allow_overlapping_parent_deny_is_dropped() -> None:
    parent = _doc([{
        "name": "deny-shell", "action": "deny",
        "condition": {"field": "tool", "operator": "eq", "value": "shell"},
    }])
    child = _doc([{
        "name": "allow-shell", "action": "allow", "priority": 100,
        "condition": {"field": "tool", "operator": "eq", "value": "shell"},
    }])
    names = [r["name"] for r in merge_documents([parent, child])]
    assert "deny-shell" in names
    assert "allow-shell" not in names


def test_disjoint_child_allow_survives() -> None:
    parent = _doc([{
        "name": "deny-shell", "action": "deny",
        "condition": {"field": "tool", "operator": "eq", "value": "shell"},
    }])
    child = _doc([{
        "name": "allow-python", "action": "allow", "priority": 1,
        "condition": {"field": "tool", "operator": "eq", "value": "python"},
    }])
    names = [r["name"] for r in merge_documents([parent, child])]
    assert "allow-python" in names


def test_satisfiable_compound_parent_deny_still_protects() -> None:
    # A satisfiable AND-condition parent deny must not be classified away; a
    # child allow overlapping its scope is dropped (immutability holds).
    parent = _doc([{
        "name": "deny-admin-delete", "action": "deny",
        "condition": {"and": [
            {"field": "role", "operator": "eq", "value": "admin"},
            {"field": "action", "operator": "eq", "value": "delete"},
        ]},
    }])
    child = _doc([{
        "name": "allow-admin", "action": "allow", "priority": 100,
        "condition": {"field": "role", "operator": "eq", "value": "admin"},
    }])
    names = [r["name"] for r in merge_documents([parent, child])]
    assert "allow-admin" not in names


def test_unsat_classified_parent_deny_still_protects_overlapping_child() -> None:
    # RED on main, GREEN here. The parent deny's condition is classified
    # unsatisfiable by `_condition_unsatisfiable` (the empty-`in` conjunct),
    # yet it still overlaps the child via its other conjunct (`tool == shell`).
    # On main, `_conditions_disjoint` short-circuits on the parent's
    # unsatisfiability, declares the deny disjoint, and the child allow
    # survives — neutralising the parent deny (fail-open, ADR-0014). The fix
    # ignores the parent's unsatisfiability on the deny path, so the overlap is
    # detected and the child allow is dropped.
    parent = _doc([{
        "name": "deny-shell", "action": "deny",
        "condition": {"and": [
            {"field": "x", "operator": "in", "value": []},
            {"field": "tool", "operator": "eq", "value": "shell"},
        ]},
    }])
    child = _doc([{
        "name": "allow-shell", "action": "allow", "priority": 100,
        "condition": {"field": "tool", "operator": "eq", "value": "shell"},
    }])
    names = [r["name"] for r in merge_documents([parent, child])]
    assert "deny-shell" in names
    assert "allow-shell" not in names


def test_conditions_overlap_identical_conditions() -> None:
    # Sanity guard for the `_condition_key` fast-path (non-identical-dict cases
    # are covered by the merge_documents tests above).
    cond = {"field": "tool", "operator": "eq", "value": "shell"}
    assert _conditions_overlap(dict(cond), dict(cond)) is True
