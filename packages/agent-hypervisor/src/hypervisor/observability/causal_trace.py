# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Causal trace IDs for cross-agent distributed tracing.

Unlike simple correlation IDs, causal trace IDs encode the full
spawn/delegation tree, making distributed traces genuinely readable.

Format: {trace_id}/{span_id}[/{parent_span_id}]
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CausalTraceId:
    """Encodes the full spawn/delegation tree for a trace."""

    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    span_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    parent_span_id: str | None = None
    depth: int = 0

    def child(self) -> CausalTraceId:
        """Create a child span (e.g., when spawning a sub-agent or delegating)."""
        return CausalTraceId(
            trace_id=self.trace_id,
            span_id=uuid.uuid4().hex[:8],
            parent_span_id=self.span_id,
            depth=self.depth + 1,
        )

    def sibling(self) -> CausalTraceId:
        """Create a sibling span (same parent, different operation)."""
        return CausalTraceId(
            trace_id=self.trace_id,
            span_id=uuid.uuid4().hex[:8],
            parent_span_id=self.parent_span_id,
            depth=self.depth,
        )

    @property
    def full_id(self) -> str:
        """Full trace path: trace_id/span_id[/parent_span_id]."""
        parts = [self.trace_id, self.span_id]
        if self.parent_span_id:
            parts.append(self.parent_span_id)
        return "/".join(parts)

    @classmethod
    def from_string(cls, s: str) -> CausalTraceId:
        """Parse a CausalTraceId from its string representation."""
        parts = s.split("/")
        if len(parts) < 2:
            raise ValueError(f"Invalid causal trace ID: {s}")
        return cls(
            trace_id=parts[0],
            span_id=parts[1],
            parent_span_id=parts[2] if len(parts) > 2 else None,
        )

    def is_ancestor_of(self, other: CausalTraceId) -> bool:
        """Check if this trace is an ancestor of another (same trace tree)."""
        return self.trace_id == other.trace_id and other.depth > self.depth

    def __str__(self) -> str:
        return self.full_id
