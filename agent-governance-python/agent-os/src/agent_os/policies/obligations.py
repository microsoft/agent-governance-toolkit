# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Obligations carried by a ``constrain`` governance outcome.

In Context Accumulation Governance, ``constrain`` is not a new policy verdict —
it is *allow-with-obligations*: the action is permitted only if the host can
carry the accompanying restrictions/labels forward (an obligation channel), or
if every obligation is already declaratively satisfied. Where neither holds,
the decision must fail closed (see :mod:`context_accumulation`).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Obligation:
    """A single restriction the host must honor for an action to proceed."""

    key: str
    satisfied: bool


@dataclass(frozen=True)
class ObligationSet:
    """The obligations and labels a ``constrain`` outcome carries forward."""

    obligations: tuple[Obligation, ...] = ()
    result_labels: frozenset[str] = frozenset()

    @property
    def all_satisfied(self) -> bool:
        """True iff every obligation is already declaratively satisfied.

        An empty obligation set is vacuously satisfied.
        """
        return all(o.satisfied for o in self.obligations)
