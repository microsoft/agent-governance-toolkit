# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Reserved resolution-layer errors per SPECIFICATION.md §16.

The reserved reason strings here match the Rust core's
``runtime_error:resolution_*`` codes one for one. The resolution layer
runs on the host side; it raises these errors before the engine is
called, and the host MUST translate them into a fail-closed deny when
surfacing to the agent caller.
"""

from __future__ import annotations

from enum import Enum


class ResolutionReason(str, Enum):
    """The reserved set of resolution-layer fail-closed reasons.

    Equivalent to the Rust core ``RuntimeError::Resolution*`` variants
    that the host wrapper materializes when resolution fails.
    """

    PATH_TRAVERSAL = "runtime_error:resolution_path_traversal"
    CYCLE = "runtime_error:resolution_cycle"
    INVALID_GOVERNANCE = "runtime_error:resolution_invalid_governance"
    MERGE_CONFLICT = "runtime_error:resolution_merge_conflict"


class ResolutionError(Exception):
    """Raised by the resolution layer when it refuses to produce a manifest.

    Attributes:
        reason: One of :class:`ResolutionReason`.
        detail: Free-form human-readable explanation. The host MAY surface
            this in logs; it MUST NOT include user-supplied content that
            could carry secrets.
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
