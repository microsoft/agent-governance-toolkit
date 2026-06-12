# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Restriction inheritance across a delegation boundary.

When a workflow delegates to a child agent, the child's context envelope must
inherit the parent's restrictions: a delegatee may ADD restrictions but never
DROP one. This is a pure, grow-only union, invoked by the caller that
constructs the child envelope. It composes alongside — and never modifies —
the scope attenuation performed by structural-authz's ``DelegationChain``.
"""

from __future__ import annotations

from typing import Iterable

from .context_envelope import ContextEnvelope


def merge_restrictions(
    parent: ContextEnvelope,
    child_declared: Iterable[str],
) -> frozenset[str]:
    """Return the child's effective restrictions: parent ∪ child-declared.

    Grow-only: a child can add restrictions but cannot relax any restriction
    inherited from the parent.
    """
    return parent.restrictions | frozenset(child_declared)
