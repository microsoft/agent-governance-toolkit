# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Trace capture engine for deterministic replay."""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class SpanKind(Enum):
    """Types of spans in an agent trace."""

    AGENT_TASK = "agent_task"
    TOOL_CALL = "tool_call"
    LLM_INFERENCE = "llm_inference"
    DELEGATION = "delegation"
    POLICY_CHECK = "policy_check"
    INTERNAL = "internal"


class SpanStatus(Enum):
    """Outcome of a span."""

    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class Span:
    """A single unit of work in an agent trace.

    Captures inputs, outputs, timing, and cost for one step
    (tool call, LLM inference, delegation, etc.).
    """

    span_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_id: str | None = None
    trace_id: str = ""
    kind: SpanKind = SpanKind.INTERNAL
    name: str = ""
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    status: SpanStatus = SpanStatus.OK
    attributes: dict[str, Any] = field(default_factory=dict)
    # Captured I/O for replay
    input_data: dict[str, Any] = field(default_factory=dict)
    output_data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    cost_usd: float = 0.0

    @property
    def duration_ms(self) -> float | None:
        """Duration in milliseconds."""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000

    def finish(
        self,
        output: dict[str, Any] | None = None,
        error: str | None = None,
        cost_usd: float = 0.0,
    ) -> None:
        """Complete this span."""
        self.end_time = time.time()
        if output:
            self.output_data = output
        if error:
            self.error = error
            self.status = SpanStatus.ERROR
        self.cost_usd = cost_usd

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "trace_id": self.trace_id,
            "kind": self.kind.value,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "attributes": self.attributes,
            "input_data": self.input_data,
            "output_data": self.output_data,
            "error": self.error,
            "cost_usd": self.cost_usd,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Span:
        """Deserialize from dictionary."""
        return cls(
            span_id=data["span_id"],
            parent_id=data.get("parent_id"),
            trace_id=data.get("trace_id", ""),
            kind=SpanKind(data.get("kind", "internal")),
            name=data.get("name", ""),
            start_time=data.get("start_time", 0.0),
            end_time=data.get("end_time"),
            status=SpanStatus(data.get("status", "ok")),
            attributes=data.get("attributes", {}),
            input_data=data.get("input_data", {}),
            output_data=data.get("output_data", {}),
            error=data.get("error"),
            cost_usd=data.get("cost_usd", 0.0),
        )


# Patterns for PII/credential redaction (basic regex: passwords, emails, phones)
_REDACT_PATTERNS = [
    (re.compile(r'"(password|secret|token|api_key|apikey|authorization)":\s*"[^"]*"', re.I),
     r'"\1": "[REDACTED]"'),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
     "[EMAIL_REDACTED]"),
    (re.compile(r'\b(?:\+?1[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b'),
     "[PHONE_REDACTED]"),
]


def _redact(text: str) -> str:
    """Redact sensitive data from text."""
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


@dataclass
class Trace:
    """A complete agent execution trace.

    Contains all spans from a single task execution, forming a tree
    of operations that can be replayed deterministically.
    """

    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    agent_id: str = ""
    task_input: str = ""
    task_output: str | None = None
    spans: list[Span] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    total_cost_usd: float = 0.0
    success: bool | None = None

    @property
    def duration_ms(self) -> float | None:
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000

    @property
    def content_hash(self) -> str:
        """Content-addressable hash for deduplication."""
        content = json.dumps(
            {"agent_id": self.agent_id, "task_input": self.task_input, "trace_id": self.trace_id},
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def add_span(self, span: Span) -> None:
        """Add a span to this trace."""
        span.trace_id = self.trace_id
        self.spans.append(span)

    def finish(self, output: str | None = None, success: bool = True) -> None:
        """Complete this trace."""
        self.end_time = time.time()
        self.task_output = output
        self.success = success
        self.total_cost_usd = sum(s.cost_usd for s in self.spans)

    def root_spans(self) -> list[Span]:
        """Get top-level spans (no parent)."""
        return [s for s in self.spans if s.parent_id is None]

    def children_of(self, span_id: str) -> list[Span]:
        """Get child spans of a given span."""
        return [s for s in self.spans if s.parent_id == span_id]

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        """Serialize to dictionary, optionally redacting sensitive data."""
        data = {
            "trace_id": self.trace_id,
            "agent_id": self.agent_id,
            "task_input": self.task_input,
            "task_output": self.task_output,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
            "total_cost_usd": self.total_cost_usd,
            "success": self.success,
            "content_hash": self.content_hash,
            "span_count": len(self.spans),
            "spans": [s.to_dict() for s in self.spans],
        }
        if redact:
            return json.loads(_redact(json.dumps(data)))  # type: ignore[no-any-return]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Trace:
        """Deserialize from dictionary."""
        trace = cls(
            trace_id=data["trace_id"],
            agent_id=data.get("agent_id", ""),
            task_input=data.get("task_input", ""),
            task_output=data.get("task_output"),
            start_time=data.get("start_time", 0.0),
            end_time=data.get("end_time"),
            metadata=data.get("metadata", {}),
            total_cost_usd=data.get("total_cost_usd", 0.0),
            success=data.get("success"),
        )
        for span_data in data.get("spans", []):
            trace.spans.append(Span.from_dict(span_data))
        return trace


class TraceCapture:
    """Context manager for capturing agent execution traces.

    Usage:
        with TraceCapture(agent_id="my-agent") as capture:
            span = capture.start_span("tool_call", SpanKind.TOOL_CALL, input_data={...})
            # ... do work ...
            span.finish(output={...})
        trace = capture.trace
    """

    def __init__(self, agent_id: str, task_input: str = "", metadata: dict[str, Any] | None = None) -> None:
        self.trace = Trace(agent_id=agent_id, task_input=task_input, metadata=metadata or {})
        self._span_stack: list[Span] = []

    def __enter__(self) -> TraceCapture:
        return self

    def __exit__(self, exc_type: type | None, exc_val: Exception | None, exc_tb: Any) -> None:
        success = exc_type is None
        self.trace.finish(success=success)

    def start_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        input_data: dict[str, Any] | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Span:
        """Start a new span, automatically parented to the current span."""
        parent_id = self._span_stack[-1].span_id if self._span_stack else None
        span = Span(
            trace_id=self.trace.trace_id,
            parent_id=parent_id,
            kind=kind,
            name=name,
            input_data=input_data or {},
            attributes=attributes or {},
        )
        self.trace.add_span(span)
        self._span_stack.append(span)
        return span

    def end_span(
        self,
        output: dict[str, Any] | None = None,
        error: str | None = None,
        cost_usd: float = 0.0,
    ) -> Span | None:
        """End the current span and pop from stack."""
        if not self._span_stack:
            return None
        span = self._span_stack.pop()
        span.finish(output=output, error=error, cost_usd=cost_usd)
        return span


class TraceStore:
    """Persistent storage for traces.

    Default implementation uses local filesystem (JSON files).
    """

    def __init__(self, storage_dir: str | Path = ".agent-sre/traces") -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def save(self, trace: Trace, redact: bool = True) -> Path:
        """Save a trace to storage."""
        filename = f"{trace.trace_id}.json"
        filepath = self.storage_dir / filename
        with open(filepath, "w") as f:
            json.dump(trace.to_dict(redact=redact), f, indent=2)
        return filepath

    def load(self, trace_id: str) -> Trace | None:
        """Load a trace by ID."""
        filepath = self.storage_dir / f"{trace_id}.json"
        if not filepath.exists():
            return None
        with open(filepath) as f:
            return Trace.from_dict(json.load(f))

    def list_traces(self, agent_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """List stored traces with optional filtering."""
        traces: list[dict[str, Any]] = []
        for filepath in sorted(self.storage_dir.glob("*.json"), reverse=True):
            if len(traces) >= limit:
                break
            with open(filepath) as f:
                data = json.load(f)
            if agent_id and data.get("agent_id") != agent_id:
                continue
            traces.append({
                "trace_id": data["trace_id"],
                "agent_id": data.get("agent_id"),
                "task_input": data.get("task_input", "")[:100],
                "success": data.get("success"),
                "duration_ms": data.get("duration_ms"),
                "span_count": data.get("span_count", 0),
                "total_cost_usd": data.get("total_cost_usd", 0),
            })
        return traces

    def delete(self, trace_id: str) -> bool:
        """Delete a trace."""
        filepath = self.storage_dir / f"{trace_id}.json"
        if filepath.exists():
            filepath.unlink()
            return True
        return False
