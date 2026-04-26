# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Distributed tracing for AMB.

This module provides distributed tracing capabilities for tracking
message flow across agents and services.
"""

from typing import Any, Dict, Optional, List
from datetime import datetime, timezone
from dataclasses import dataclass, field
from uuid import uuid4
from contextvars import ContextVar
import json


# Context variable for current trace
_current_trace: ContextVar[Optional["TraceContext"]] = ContextVar(
    "current_trace", default=None
)


@dataclass
class TraceSpan:
    """
    A span within a trace representing a single operation.
    """
    span_id: str
    operation_name: str
    trace_id: str
    parent_span_id: Optional[str] = None
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "in_progress"  # in_progress, success, error
    
    def finish(self, status: str = "success") -> None:
        """Mark span as finished."""
        self.end_time = datetime.now(timezone.utc)
        self.status = status
    
    def log(self, event: str, **kwargs) -> None:
        """Add a log entry to the span."""
        self.logs.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **kwargs
        })
    
    def set_tag(self, key: str, value: Any) -> None:
        """Set a tag on the span."""
        self.tags[key] = value
    
    @property
    def duration_ms(self) -> Optional[float]:
        """Get duration in milliseconds."""
        if not self.end_time:
            return None
        delta = self.end_time - self.start_time
        return delta.total_seconds() * 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "span_id": self.span_id,
            "operation_name": self.operation_name,
            "trace_id": self.trace_id,
            "parent_span_id": self.parent_span_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "tags": self.tags,
            "logs": self.logs,
            "status": self.status
        }


@dataclass
class TraceContext:
    """
    Context for distributed tracing across message flows.
    
    TraceContext maintains trace and span IDs that propagate with messages,
    allowing you to track the full journey of a message through the system.
    
    Example:
        # Start a new trace
        with TraceContext.start("process_order") as ctx:
            await bus.publish("orders.new", payload, trace_id=ctx.trace_id)
            
        # Continue an existing trace
        with TraceContext.from_message(message) as ctx:
            ctx.log("Processing started")
            # ... process message
            ctx.log("Processing complete")
    """
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    baggage: Dict[str, str] = field(default_factory=dict)
    spans: List[TraceSpan] = field(default_factory=list)
    _current_span: Optional[TraceSpan] = field(default=None, repr=False)
    
    @classmethod
    def new(cls, operation_name: str = "root") -> "TraceContext":
        """
        Create a new trace context.
        
        Args:
            operation_name: Name of the root operation
            
        Returns:
            New TraceContext
        """
        trace_id = str(uuid4())
        span_id = str(uuid4())
        
        ctx = cls(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=None
        )
        
        # Create root span
        root_span = TraceSpan(
            span_id=span_id,
            operation_name=operation_name,
            trace_id=trace_id
        )
        ctx.spans.append(root_span)
        ctx._current_span = root_span
        
        return ctx
    
    @classmethod
    def from_headers(cls, headers: Dict[str, str]) -> "TraceContext":
        """
        Create trace context from message headers.
        
        Args:
            headers: Headers containing trace information
            
        Returns:
            TraceContext (new or continued)
        """
        trace_id = headers.get("x-trace-id")
        parent_span_id = headers.get("x-span-id")
        baggage_json = headers.get("x-trace-baggage", "{}")
        
        if not trace_id:
            return cls.new()
        
        try:
            baggage = json.loads(baggage_json)
        except json.JSONDecodeError:
            baggage = {}
        
        span_id = str(uuid4())
        
        return cls(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            baggage=baggage
        )
    
    @classmethod
    def from_message(cls, message: "Message") -> "TraceContext":  # noqa: F821
        """
        Extract trace context from a message.
        
        Args:
            message: Message with trace metadata
            
        Returns:
            TraceContext (new or continued)
        """
        trace_id = message.metadata.get("trace_id")
        parent_span_id = message.metadata.get("span_id")
        baggage = message.metadata.get("trace_baggage", {})
        
        if not trace_id:
            return cls.new()
        
        span_id = str(uuid4())
        
        return cls(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            baggage=baggage if isinstance(baggage, dict) else {}
        )
    
    @classmethod
    def current(cls) -> Optional["TraceContext"]:
        """Get current trace context from context var."""
        return _current_trace.get()
    
    @classmethod
    def start(cls, operation_name: str = "root") -> "TraceContext":
        """
        Start a new trace and set as current.
        
        Args:
            operation_name: Name of the root operation
            
        Returns:
            New TraceContext
        """
        ctx = cls.new(operation_name)
        _current_trace.set(ctx)
        return ctx
    
    def start_span(self, operation_name: str) -> TraceSpan:
        """
        Start a new child span.
        
        Args:
            operation_name: Name of the operation
            
        Returns:
            New TraceSpan
        """
        parent_id = self._current_span.span_id if self._current_span else self.span_id
        
        span = TraceSpan(
            span_id=str(uuid4()),
            operation_name=operation_name,
            trace_id=self.trace_id,
            parent_span_id=parent_id
        )
        
        self.spans.append(span)
        self._current_span = span
        return span
    
    def finish_span(self, status: str = "success") -> None:
        """Finish the current span."""
        if self._current_span:
            self._current_span.finish(status)
            
            # Find parent span
            if self._current_span.parent_span_id:
                for span in self.spans:
                    if span.span_id == self._current_span.parent_span_id:
                        self._current_span = span
                        return
            
            self._current_span = None
    
    def log(self, event: str, **kwargs) -> None:
        """Log an event to the current span."""
        if self._current_span:
            self._current_span.log(event, **kwargs)
    
    def set_tag(self, key: str, value: Any) -> None:
        """Set a tag on the current span."""
        if self._current_span:
            self._current_span.set_tag(key, value)
    
    def set_baggage(self, key: str, value: str) -> None:
        """
        Set baggage item that propagates with the trace.
        
        Baggage items are key-value pairs that travel with the trace
        across all services.
        """
        self.baggage[key] = value
    
    def get_baggage(self, key: str) -> Optional[str]:
        """Get a baggage item."""
        return self.baggage.get(key)
    
    def to_headers(self) -> Dict[str, str]:
        """
        Convert trace context to headers for propagation.
        
        Returns:
            Headers dict
        """
        return {
            "x-trace-id": self.trace_id,
            "x-span-id": self.span_id,
            "x-parent-span-id": self.parent_span_id or "",
            "x-trace-baggage": json.dumps(self.baggage)
        }
    
    def to_message_metadata(self) -> Dict[str, Any]:
        """
        Convert trace context to message metadata.
        
        Returns:
            Metadata dict to add to message
        """
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "trace_baggage": self.baggage
        }
    
    def __enter__(self) -> "TraceContext":
        """Context manager entry."""
        _current_trace.set(self)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        if exc_type:
            self.finish_span(status="error")
        else:
            self.finish_span(status="success")
        _current_trace.set(None)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "baggage": self.baggage,
            "spans": [s.to_dict() for s in self.spans]
        }


def get_current_trace() -> Optional[TraceContext]:
    """Get the current trace context."""
    return _current_trace.get()


def inject_trace(message: "Message") -> "Message":  # noqa: F821
    """
    Inject current trace context into a message.
    
    Args:
        message: Message to inject trace into
        
    Returns:
        Message with trace metadata
    """
    ctx = get_current_trace()
    if ctx:
        message.metadata.update(ctx.to_message_metadata())
    return message


def extract_trace(message: "Message") -> TraceContext:  # noqa: F821
    """
    Extract trace context from a message.
    
    Args:
        message: Message to extract trace from
        
    Returns:
        TraceContext (new or continued)
    """
    return TraceContext.from_message(message)
