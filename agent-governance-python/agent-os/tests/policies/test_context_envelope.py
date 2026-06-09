# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioral tests for the ContextEnvelope value type and its folds."""

import dataclasses

import pytest

from agent_os.policies.context_envelope import (
    ContextEnvelope,
    EnvelopeReference,
    apply_restrictions,
    envelope_reference,
    fold,
)
from agent_os.policies.data_classification import DataClassification as DC


def _env(**kw) -> ContextEnvelope:
    base = dict(envelope_id="env1", workflow_id="wf1")
    base.update(kw)
    return ContextEnvelope(**base)


def test_fold_joins_labels_and_raises_sensitivity():
    e = _env(labels=frozenset({"pii"}), aggregate_sensitivity=DC.INTERNAL)
    out = fold(e, {"financial"}, DC.CONFIDENTIAL)
    assert out.labels == frozenset({"pii", "financial"})
    assert out.aggregate_sensitivity == DC.CONFIDENTIAL
    assert out.version == e.version + 1
    # original is unchanged (immutability)
    assert e.labels == frozenset({"pii"})


def test_fold_is_idempotent():
    e = _env(labels=frozenset({"pii"}), aggregate_sensitivity=DC.CONFIDENTIAL)
    out = fold(e, {"pii"}, DC.INTERNAL)
    assert out.labels == e.labels
    assert out.aggregate_sensitivity == e.aggregate_sensitivity


def test_fold_is_commutative():
    e = _env()
    a = fold(fold(e, {"pii"}, DC.INTERNAL), {"financial"}, DC.CONFIDENTIAL)
    b = fold(fold(e, {"financial"}, DC.CONFIDENTIAL), {"pii"}, DC.INTERNAL)
    assert a.labels == b.labels
    assert a.aggregate_sensitivity == b.aggregate_sensitivity


def test_sensitivity_is_max_lattice():
    e = _env()
    out = fold(fold(e, {"a"}, DC.RESTRICTED), {"b"}, DC.PUBLIC)
    assert out.aggregate_sensitivity == DC.RESTRICTED


def test_restrictions_are_grow_only():
    e = _env(restrictions=frozenset({"no_external_export"}))
    out = apply_restrictions(e, set())  # attempt to omit
    assert out.restrictions == frozenset({"no_external_export"})
    out2 = apply_restrictions(out, {"no_memory_write"})
    assert out2.restrictions == frozenset({"no_external_export", "no_memory_write"})


def _loaded_env() -> ContextEnvelope:
    """An envelope carrying every content field, to prove the reference drops them."""
    return ContextEnvelope(
        envelope_id="env-abc",
        workflow_id="wf-corr-1",
        labels=frozenset({"pii", "financial"}),
        aggregate_sensitivity=DC.RESTRICTED,
        restrictions=frozenset({"no_external_export"}),
        version=7,
        parent_envelope_id="parent-xyz",
        created_at="2026-06-04T00:00:00Z",
    )


def test_envelope_reference_exposes_only_id_and_sensitivity():
    ref = envelope_reference(_loaded_env())
    assert isinstance(ref, EnvelopeReference)
    field_names = {f.name for f in dataclasses.fields(ref)}
    assert field_names == {"envelope_id", "sensitivity"}
    # The content fields of the source envelope must not be reachable on the ref.
    for leaked in ("labels", "restrictions", "version", "parent_envelope_id", "workflow_id", "created_at"):
        assert not hasattr(ref, leaked)


def test_envelope_reference_sensitivity_equals_aggregate():
    env = _loaded_env()
    ref = envelope_reference(env)
    assert ref.sensitivity is env.aggregate_sensitivity
    assert ref.sensitivity == DC.RESTRICTED


def test_envelope_reference_id_matches():
    env = _loaded_env()
    assert envelope_reference(env).envelope_id == env.envelope_id


def test_envelope_reference_is_frozen():
    ref = envelope_reference(_loaded_env())
    with pytest.raises(dataclasses.FrozenInstanceError):
        ref.sensitivity = DC.PUBLIC
