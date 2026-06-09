# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Context envelope: accumulated governance state for a workflow.

A ContextEnvelope is an immutable, versioned value object that records the
labels and sensitivity accumulated so far in a workflow. Sensitivity is a
max-lattice over ``DataClassification`` (it only ever rises); restrictions are
a grow-only set (they can be added but never dropped). Because the join (label
union) and meet (sensitivity max) are commutative and idempotent, a
single-writer can fold deltas in any order and reach the same state.

This module is part of Context Accumulation Governance (CAG). It reuses the
existing ``DataClassification`` ladder rather than introducing a parallel
sensitivity vocabulary.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Optional

from .data_classification import DataClassification


@dataclass(frozen=True)
class ContextEnvelope:
    """Immutable, versioned accumulation of workflow governance state.

    Attributes:
        envelope_id: Stable identifier for this envelope's lineage.
        workflow_id: Correlation key (a workflow may span tool calls/delegations).
        labels: Accumulated ``DataLabel`` categories (e.g. ``pii``, ``financial``).
        aggregate_sensitivity: Running max over all folded sensitivities.
        restrictions: Grow-only set of restriction tokens.
        version: Monotonic counter; each fold/application yields ``version + 1``.
        parent_envelope_id: Set on a child (delegation) envelope.
        created_at: Caller-supplied ISO-8601 timestamp (kept out of pure code).
    """

    envelope_id: str
    workflow_id: str
    labels: frozenset[str] = frozenset()
    aggregate_sensitivity: DataClassification = DataClassification.PUBLIC
    restrictions: frozenset[str] = frozenset()
    version: int = 0
    parent_envelope_id: Optional[str] = None
    created_at: str = ""


def fold(
    env: ContextEnvelope,
    new_labels: Iterable[str],
    new_sensitivity: DataClassification,
) -> ContextEnvelope:
    """Return the next version of ``env`` with ``new_labels`` and ``new_sensitivity``.

    Pure join: labels are unioned, sensitivity is the lattice max (never lowers),
    and ``version`` increments. Restrictions are left unchanged here — they are
    derived by aggregation evaluation and applied via :func:`apply_restrictions`.
    """
    joined_labels = env.labels | frozenset(new_labels)
    joined_sensitivity = max(env.aggregate_sensitivity, new_sensitivity)
    return replace(
        env,
        labels=joined_labels,
        aggregate_sensitivity=joined_sensitivity,
        version=env.version + 1,
    )


def apply_restrictions(
    env: ContextEnvelope,
    restrictions: Iterable[str],
) -> ContextEnvelope:
    """Return the next version of ``env`` with ``restrictions`` added (grow-only).

    Restrictions are unioned, so a restriction present in ``env`` is never
    dropped even if absent from ``restrictions``. ``version`` increments.
    """
    grown = env.restrictions | frozenset(restrictions)
    return replace(env, restrictions=grown, version=env.version + 1)


@dataclass(frozen=True)
class EnvelopeReference:
    """An opaque, cross-boundary handle to a :class:`ContextEnvelope`.

    This is the only envelope-derived value intended to appear in an evidence
    receipt or to cross a trust boundary. It carries the stable ``envelope_id``
    as an opaque join key plus the coarse ``sensitivity`` tier, and deliberately
    omits envelope contents (labels, restrictions, version lineage, workflow
    correlation, timestamps). A consumer treats the id as a reference to
    governance context it must resolve through the issuer, not as a portable
    schema for the envelope itself, so the in-process ``ContextEnvelope`` shape
    can evolve without changing what a receipt commits to.

    Attributes:
        envelope_id: Opaque lineage identifier; meaningful only to the issuer.
        sensitivity: Coarse aggregate-sensitivity tier — a non-sensitive routing
            hint that lets a verifier pick a resolver or policy path.
    """

    envelope_id: str
    sensitivity: DataClassification


def envelope_reference(env: ContextEnvelope) -> EnvelopeReference:
    """Project ``env`` onto its opaque cross-boundary reference.

    Returns only the opaque ``envelope_id`` and the coarse
    ``aggregate_sensitivity`` tier; envelope contents never cross the boundary.
    This is a pure projection: it performs no I/O, no signing, and does not
    mutate ``env``.
    """
    return EnvelopeReference(
        envelope_id=env.envelope_id,
        sensitivity=env.aggregate_sensitivity,
    )
