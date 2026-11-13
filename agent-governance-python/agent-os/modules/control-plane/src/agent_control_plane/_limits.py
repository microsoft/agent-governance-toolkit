# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared limit handling for the control plane's history readers.

Every reader that returns "the most recent N" entries shares one
contract, kept here so the three-line guard is not pasted per call site:

* ``None`` (where the reader accepts it) returns every entry.
* ``0`` returns none.
* A positive limit returns the last ``limit`` entries.
* A negative limit raises :class:`ValueError`.

The zero case needs its own branch because ``entries[-0:]`` is the whole
list, which is the defect this module exists to prevent.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypeVar

T = TypeVar("T")


def tail(entries: Sequence[T], limit: int | None) -> list[T]:
    """Return the last ``limit`` entries of ``entries`` as a new list."""
    if limit is None:
        return list(entries)
    if limit < 0:
        raise ValueError(f"limit must be zero or positive; got {limit!r}")
    if limit == 0:
        return []
    return list(entries[-limit:])
