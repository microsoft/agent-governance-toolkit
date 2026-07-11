# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Migration-report diagnostics for the removed governance resolver.

These stable strings classify one-way migration failures. They are not ACS
runtime reasons and are never returned by the policy engine.
"""

from __future__ import annotations

from enum import Enum


class ResolutionReason(str, Enum):
    """Stable diagnostic categories emitted by ``agt migrate v4-to-v5``."""

    PATH_TRAVERSAL = "runtime_error:resolution_path_traversal"
    CYCLE = "runtime_error:resolution_cycle"
    INVALID_GOVERNANCE = "runtime_error:resolution_invalid_governance"
    MERGE_CONFLICT = "runtime_error:resolution_merge_conflict"


class ResolutionError(Exception):
    """Raised when migration refuses to produce a native manifest.

    Attributes:
        reason: One of :class:`ResolutionReason`.
        detail: Human-readable migration detail. It must not include raw
            sensitive payloads.
    """

    __slots__ = ("reason", "detail")

    def __init__(self, reason: ResolutionReason, detail: str = "") -> None:
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)
        self.reason = reason
        self.detail = detail

    @classmethod
    def path_traversal(cls, detail: str = "") -> "ResolutionError":
        return cls(ResolutionReason.PATH_TRAVERSAL, detail)

    @classmethod
    def cycle(cls, detail: str = "") -> "ResolutionError":
        return cls(ResolutionReason.CYCLE, detail)

    @classmethod
    def invalid_governance(cls, detail: str = "") -> "ResolutionError":
        return cls(ResolutionReason.INVALID_GOVERNANCE, detail)

    @classmethod
    def merge_conflict(cls, detail: str = "") -> "ResolutionError":
        return cls(ResolutionReason.MERGE_CONFLICT, detail)
