# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenTelemetry Tracing Integration.

Provides distributed tracing for AgentMesh operations including
trust handshakes, identity verification, scope chains, and policy checks.
"""

from typing import Optional, Any, Callable, TypeVar
from functools import wraps
import inspect
import os
import time

F = TypeVar("F", bound=Callable[..., Any])

# Check if OpenTelemetry is available
_OTEL_AVAILABLE = False
try:
    from opentelemetry import trace, context
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.propagate import inject as _otel_inject, extract as _otel_extract

    _OTEL_AVAILABLE = True
except ImportError:
    pass

# Attempt to import OTLP exporter separately (may not be installed)
_OTLP_AVAILABLE = False
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    _OTLP_AVAILABLE = True
except ImportError:
    pass


def setup_tracing(
    service_name: str = "agentmesh",
    endpoint: Optional[str] = None,
    insecure: bool = False,
) -> None:
    """
    Setup OpenTelemetry tracing.

    Args:
        service_name: Service name for traces
        endpoint: OTLP endpoint (default: from OTEL_EXPORTER_OTLP_ENDPOINT env)
        insecure: Whether to use insecure connection (default: False, use TLS)
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
    except ImportError:
        # OpenTelemetry not installed, skip setup
        return

    # Get endpoint from env or parameter
    endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        # No endpoint configured, skip
        return

    # Create resource
    resource = Resource.create({
        "service.name": service_name,
        "service.namespace": "agentmesh",
        "deployment.environment": os.getenv("AGENTMESH_ENV", "development"),
    })

    # Create tracer provider
    provider = TracerProvider(resource=resource)

    # Create OTLP exporter
    otlp_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=insecure)

    # Add span processor
    provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

    # Set global tracer provider
    trace.set_tracer_provider(provider)


def get_tracer(name: str = "agentmesh"):
    """Get tracer instance."""
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        return None


def trace_operation(
    operation_name: str,
    agent_did: Optional[str] = None,
    trust_score: Optional[int] = None,
    policy_result: Optional[str] = None,
):
    """
    Decorator to trace an operation.

    Args:
        operation_name: Name of the operation
        agent_did: Optional agent DID
        trust_score: Optional trust score
        policy_result: Optional policy result (ALLOW/DENY)
    """
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            if tracer is None:
                # Tracing not available
                return await func(*args, **kwargs)

            with tracer.start_as_current_span(operation_name) as span:
                # Set attributes
                if agent_did:
                    span.set_attribute("agent.did", agent_did)
                if trust_score is not None:
                    span.set_attribute("agent.trust_score", trust_score)
                if policy_result:
                    span.set_attribute("policy.result", policy_result)

                # Set standard attributes
                span.set_attribute("operation.name", operation_name)

                try:
                    result = await func(*args, **kwargs)
                    span.set_attribute("operation.status", "success")
                    return result
                except Exception as e:
                    span.set_attribute("operation.status", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    span.record_exception(e)
                    raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            tracer = get_tracer()
            if tracer is None:
                return func(*args, **kwargs)

            with tracer.start_as_current_span(operation_name) as span:
                if agent_did:
                    span.set_attribute("agent.did", agent_did)
                if trust_score is not None:
                    span.set_attribute("agent.trust_score", trust_score)
                if policy_result:
                    span.set_attribute("policy.result", policy_result)

                span.set_attribute("operation.name", operation_name)

                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("operation.status", "success")
                    return result
                except Exception as e:
                    span.set_attribute("operation.status", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    span.record_exception(e)
                    raise

        # Return appropriate wrapper based on function type
        import inspect
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


class TraceContext:
    """Context manager for manual tracing."""

    def __init__(
        self,
        operation_name: str,
        agent_did: Optional[str] = None,
        **attributes: Any,
    ):
        self.operation_name = operation_name
        self.agent_did = agent_did
        self.attributes = attributes
        self.span = None

    def __enter__(self):
        tracer = get_tracer()
        if tracer is None:
            return self

        self.span = tracer.start_span(self.operation_name)
        self.span.__enter__()

        # Set attributes
        if self.agent_did:
            self.span.set_attribute("agent.did", self.agent_did)

        for key, value in self.attributes.items():
            self.span.set_attribute(key, value)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.span:
            if exc_type:
                self.span.set_attribute("operation.status", "error")
                self.span.set_attribute("error.type", exc_type.__name__)
                self.span.set_attribute("error.message", str(exc_val))
                self.span.record_exception(exc_val)
            else:
                self.span.set_attribute("operation.status", "success")

            self.span.__exit__(exc_type, exc_val, exc_tb)

    def set_attribute(self, key: str, value: Any):
        """Set attribute on current span."""
        if self.span:
            self.span.set_attribute(key, value)

    def add_event(self, name: str, attributes: Optional[dict] = None):
        """Add event to current span."""
        if self.span:
            self.span.add_event(name, attributes or {})


def configure_tracing(
    service_name: str = "agentmesh",
    endpoint: Optional[str] = None,
    console: bool = False,
) -> Optional[Any]:
    """Configure OpenTelemetry tracing with optional OTLP or console export.

    Args:
        service_name: Service name for traces.
        endpoint: OTLP endpoint. Falls back to OTEL_EXPORTER_OTLP_ENDPOINT env var.
        console: If True, add a ConsoleSpanExporter for local debugging.

    Returns:
        TracerProvider if OTel is available, else None.
    """
    if not _OTEL_AVAILABLE:
        return None

    endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.namespace": "agentmesh",
            "deployment.environment": os.getenv("AGENTMESH_ENV", "development"),
        }
    )

    provider = TracerProvider(resource=resource)

    if endpoint and _OTLP_AVAILABLE:
        otlp_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

    if console:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)
    return provider


class MeshTracer:
    """OpenTelemetry tracer for AgentMesh trust operations.

    Provides decorators for instrumenting handshakes, identity verification,
    scope chains, and governance policy checks with OTel spans following
    agent-sre attribute naming conventions.
    """

    def __init__(
        self,
        service_name: str = "agentmesh",
        endpoint: Optional[str] = None,
    ) -> None:
        self._service_name = service_name
        self._endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        self._tracer: Any = None

        if _OTEL_AVAILABLE:
            self._tracer = trace.get_tracer(service_name)

    @property
    def enabled(self) -> bool:
        """Return True when OpenTelemetry is available."""
        return self._tracer is not None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _wrap(self, span_name: str, attr_extractor: Callable[..., dict]) -> Callable:
        """Create a decorator that wraps a function with a span.

        Args:
            span_name: Name for the OTel span.
            attr_extractor: Callable receiving (*args, **kwargs, result=...)
                and returning a dict of span attributes.
        """

        def decorator(func: F) -> F:
            if not self.enabled:
                return func  # type: ignore[return-value]

            @wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                with self._tracer.start_as_current_span(span_name) as span:
                    start = time.perf_counter()
                    try:
                        result = await func(*args, **kwargs)
                        attrs = attr_extractor(*args, **kwargs, result=result)
                        for k, v in attrs.items():
                            if v is not None:
                                span.set_attribute(k, v)
                        elapsed = (time.perf_counter() - start) * 1000
                        span.set_attribute("mesh.operation.duration_ms", elapsed)
                        return result
                    except Exception as exc:
                        span.set_attribute("operation.status", "error")
                        span.set_attribute("error.type", type(exc).__name__)
                        span.record_exception(exc)
                        raise

            @wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                with self._tracer.start_as_current_span(span_name) as span:
                    start = time.perf_counter()
                    try:
                        result = func(*args, **kwargs)
                        attrs = attr_extractor(*args, **kwargs, result=result)
                        for k, v in attrs.items():
                            if v is not None:
                                span.set_attribute(k, v)
                        elapsed = (time.perf_counter() - start) * 1000
                        span.set_attribute("mesh.operation.duration_ms", elapsed)
                        return result
                    except Exception as exc:
                        span.set_attribute("operation.status", "error")
                        span.set_attribute("error.type", type(exc).__name__)
                        span.record_exception(exc)
                        raise

            if inspect.iscoroutinefunction(func):
                return async_wrapper  # type: ignore[return-value]
            return sync_wrapper  # type: ignore[return-value]

        return decorator

    # ------------------------------------------------------------------
    # Public decorators
    # ------------------------------------------------------------------

    def trace_handshake(self, func: F) -> F:
        """Decorator for trust handshake operations.

        Expected keyword arguments on the wrapped function:
            agent_did, peer_did.  The return value should expose a
            ``result`` attribute or be a string describing the outcome.
        """

        def _extract(*args: Any, **kwargs: Any) -> dict:
            result = kwargs.pop("result", None)
            handshake_result = (
                getattr(result, "result", None) or str(result) if result is not None else "unknown"
            )
            return {
                "agent.did": kwargs.get("agent_did") or _arg(args, 0),
                "peer.did": kwargs.get("peer_did") or _arg(args, 1),
                "mesh.handshake.result": str(handshake_result),
            }

        return self._wrap("mesh.trust.handshake", _extract)(func)  # type: ignore[return-value]

    def trace_verification(self, func: F) -> F:
        """Decorator for identity verification operations.

        Expected keyword arguments: agent_did, method.
        """

        def _extract(*args: Any, **kwargs: Any) -> dict:
            result = kwargs.pop("result", None)
            return {
                "agent.did": kwargs.get("agent_did") or _arg(args, 0),
                "mesh.verification.method": kwargs.get("method") or _arg(args, 1),
                "mesh.verification.result": str(result) if result is not None else "unknown",
            }

        return self._wrap("mesh.trust.verification", _extract)(func)  # type: ignore[return-value]

    def trace_delegation(self, func: F) -> F:
        """Decorator for scope chain operations.

        Expected keyword arguments: delegator_did, delegatee_did, chain_depth.
        """

        def _extract(*args: Any, **kwargs: Any) -> dict:
            result = kwargs.pop("result", None)
            depth = kwargs.get("chain_depth")
            if depth is None and result is not None:
                depth = getattr(result, "depth", None)
            return {
                "agent.did": kwargs.get("delegator_did") or _arg(args, 0),
                "delegator.did": kwargs.get("delegator_did") or _arg(args, 0),
                "delegatee.did": kwargs.get("delegatee_did") or _arg(args, 1),
                "mesh.delegation.depth": int(depth) if depth is not None else None,
                "mesh.scope.chain_id": (
                    getattr(result, "chain_id", None) if result is not None else None
                ),
            }

        return self._wrap("mesh.trust.delegation", _extract)(func)  # type: ignore[return-value]

    def trace_policy_check(self, func: F) -> F:
        """Decorator for governance policy evaluation.

        Expected keyword arguments: policy_name.
        """

        def _extract(*args: Any, **kwargs: Any) -> dict:
            result = kwargs.pop("result", None)
            decision = (
                getattr(result, "decision", None) or str(result) if result is not None else "unknown"
            )
            return {
                "policy.name": kwargs.get("policy_name") or _arg(args, 0),
                "policy.decision": str(decision),
            }

        return self._wrap("mesh.governance.policy_check", _extract)(func)  # type: ignore[return-value]


# ------------------------------------------------------------------
# Context propagation for distributed agent-to-agent tracing
# ------------------------------------------------------------------


def inject_context(headers: dict) -> dict:
    """Inject current trace context into *headers* for outgoing agent calls.

    Args:
        headers: Mutable dict that will receive trace propagation headers.

    Returns:
        The same *headers* dict (for convenience).
    """
    if not _OTEL_AVAILABLE:
        return headers
    _otel_inject(headers)
    return headers


def extract_context(headers: dict) -> Any:
    """Extract trace context from incoming *headers*.

    Args:
        headers: Dict containing W3C traceparent / tracestate headers.

    Returns:
        An OpenTelemetry Context token, or None when OTel is unavailable.
    """
    if not _OTEL_AVAILABLE:
        return None
    ctx = _otel_extract(headers)
    return context.attach(ctx)


# ------------------------------------------------------------------
# Private helpers
# ------------------------------------------------------------------


def _arg(args: tuple, idx: int, default: Any = None) -> Any:
    """Safely get a positional argument."""
    if len(args) > idx:
        return args[idx]
    return default
