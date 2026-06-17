# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioral tests for grow-only restriction inheritance across delegation."""

from agent_os.policies.context_delegation import merge_restrictions
from agent_os.policies.context_envelope import ContextEnvelope


def _parent(restrictions) -> ContextEnvelope:
    return ContextEnvelope(
        envelope_id="p", workflow_id="w", restrictions=frozenset(restrictions)
    )


def test_child_inherits_parent_restrictions():
    out = merge_restrictions(_parent({"no_external_export"}), set())
    assert out == frozenset({"no_external_export"})


def test_child_cannot_drop_parent_restriction():
    out = merge_restrictions(_parent({"no_external_export"}), frozenset())
    assert "no_external_export" in out


def test_child_may_add_restrictions():
    out = merge_restrictions(_parent({"no_external_export"}), {"no_memory_write"})
    assert out == frozenset({"no_external_export", "no_memory_write"})


def test_effective_restrictions_union_along_chain():
    hop1 = merge_restrictions(_parent({"a"}), {"b"})
    child = ContextEnvelope(envelope_id="c", workflow_id="w", restrictions=hop1)
    hop2 = merge_restrictions(child, {"c"})
    assert hop2 == frozenset({"a", "b", "c"})
