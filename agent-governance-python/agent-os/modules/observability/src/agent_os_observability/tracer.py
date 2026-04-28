# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenTelemetry Tracing for Agent OS Kernel.

Every kernel operation emits traces for debugging and compliance.
"""

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace import Status, StatusCode
from functools import wraps
from typing import Any, Callable, Optional
import time


class KernelTracer:
    """
    OpenTelemetry tracer for Agent OS kernel.
    
    Usage:
        tracer = KernelTracer(service_name="agent-os")
        
        # Trace an operation
        with tracer.span("policy_check", {"agent_id": "001", "action": "query"}):
            result = policy_engine.check(action)
        
        # Or use decorator
        @tracer.trace("execute_action")
        async def execute(action, params):
            ...
    """
    
    def __init__(
        self,
        service_name: str = "agent-os-kernel",
        exporter=None,
        attributes: Optional[dict] = None
    ):
        """
        Initialize tracer.
        
        Args:
            service_name: Name of the service
            exporter: OpenTelemetry exporter (default: console)
            attributes: Additional resource attributes
        """
        resource_attrs = {
            "service.name": service_name,
            "service.version": "0.4.0",
            "deployment.environment": "production"
        }
        if attributes:
            resource_attrs.update(attributes)
        
        resource = Resource.create(resource_attrs)
        provider = TracerProvider(resource=resource)
        
        if exporter:
            provider.add_span_processor(BatchSpanProcessor(exporter))
        
        trace.set_tracer_provider(provider)
        self.tracer = trace.get_tracer(__name__)
    
    def span(self, name: str, attributes: Optional[dict] = None):
        """
        Create a span context manager.
        
        Usage:
            with tracer.span("operation", {"key": "value"}):
                do_work()
        """
        span = self.tracer.start_span(name)
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, value)
        return SpanContext(span)
    
    def trace(self, name: str, extract_attributes: Optional[Callable] = None):
        """
        Decorator to trace a function.
        
        Usage:
            @tracer.trace("my_function")
            def my_function(x, y):
                return x + y
        """
        def decorator(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                attrs = {}
                if extract_attributes:
                    attrs = extract_attributes(*args, **kwargs)
                
                with self.span(name, attrs) as span:
                    try:
                        result = await func(*args, **kwargs)
                        span.set_attribute("status", "success")
                        return result
                    except Exception as e:
                        span.record_exception(e)
                        span.set_status(Status(StatusCode.ERROR, str(e)))
                        raise
            
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                attrs = {}
                if extract_attributes:
                    attrs = extract_attributes(*args, **kwargs)
                
                with self.span(name, attrs) as span:
                    try:
                        result = func(*args, **kwargs)
                        span.set_attribute("status", "success")
                        return result
                    except Exception as e:
                        span.record_exception(e)
                        span.set_status(Status(StatusCode.ERROR, str(e)))
                        raise
            
            import asyncio
            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            return sync_wrapper
        
        return decorator
    
    # =========================================================================
    # Pre-built Kernel Traces
    # =========================================================================
    
    def trace_policy_check(self, agent_id: str, action: str, policies: list):
        """Start a policy check trace."""
        return self.span("kernel.policy_check", {
            "agent.id": agent_id,
            "action": action,
            "policies": ",".join(policies),
            "kernel.component": "policy_engine"
        })
    
    def trace_execution(self, agent_id: str, action: str):
        """Start an execution trace."""
        return self.span("kernel.execute", {
            "agent.id": agent_id,
            "action": action,
            "kernel.component": "dispatcher"
        })
    
    def trace_signal(self, agent_id: str, signal: str, reason: str):
        """Start a signal trace."""
        return self.span("kernel.signal", {
            "agent.id": agent_id,
            "signal": signal,
            "reason": reason,
            "kernel.component": "signal_dispatcher"
        })
    
    def trace_violation(self, agent_id: str, action: str, policy: str, reason: str):
        """Start a violation trace."""
        return self.span("kernel.violation", {
            "agent.id": agent_id,
            "action": action,
            "policy": policy,
            "violation.reason": reason,
            "kernel.component": "policy_engine",
            "severity": "high"
        })


class SpanContext:
    """Context manager for spans."""
    
    def __init__(self, span):
        self.span = span
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.span.set_attribute("duration_ms", duration * 1000)
        
        if exc_type:
            self.span.record_exception(exc_val)
            self.span.set_status(Status(StatusCode.ERROR, str(exc_val)))
        else:
            self.span.set_status(Status(StatusCode.OK))
        
        self.span.end()
        return False
    
    def set_attribute(self, key: str, value: Any):
        """Set an attribute on the span."""
        self.span.set_attribute(key, value)
    
    def add_event(self, name: str, attributes: Optional[dict] = None):
        """Add an event to the span."""
        self.span.add_event(name, attributes or {})
    
    def record_exception(self, exception: Exception):
        """Record an exception."""
        self.span.record_exception(exception)

    def set_status(self, status):
        """Set the span status."""
        self.span.set_status(status)


def trace_operation(
    tracer: KernelTracer,
    name: str,
    attributes: Optional[dict] = None
):
    """
    Decorator to trace an operation.
    
    Usage:
        @trace_operation(tracer, "my_operation", {"key": "value"})
        def my_function():
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with tracer.span(name, attributes):
                return func(*args, **kwargs)
        return wrapper
    return decorator
