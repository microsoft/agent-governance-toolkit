# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Centralized OpenTelemetry bootstrap for AGT.

Provides a single ``bootstrap_otel()`` call that configures TracerProvider,
MeterProvider, and standard resource attributes for all AGT components.
Reads configuration from environment variables with sensible defaults.

Usage::

    from agentmesh.telemetry import bootstrap_otel

    bootstrap_otel()  # reads config from env vars
    # or
    bootstrap_otel(service_name="my-agent", endpoint="http://collector:4317")
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_bootstrapped = False


def bootstrap_otel(
    service_name: Optional[str] = None,
    service_version: Optional[str] = None,
    agent_did: Optional[str] = None,
    sandbox_id: Optional[str] = None,
    endpoint: Optional[str] = None,
    protocol: str = "grpc",
    enable_metrics: bool = True,
    enable_tracing: bool = True,
) -> bool:
    """Configure OpenTelemetry TracerProvider and MeterProvider for AGT.

    Reads configuration from environment variables when parameters are not
    provided explicitly:

    - ``OTEL_EXPORTER_OTLP_ENDPOINT``: Collector endpoint (default: http://localhost:4317)
    - ``OTEL_SERVICE_NAME`` or ``AGT_SERVICE_NAME``: Service name (default: agt)
    - ``AGT_SERVICE_VERSION``: Version string
    - ``AGT_AGENT_DID``: Agent DID for resource attributes
    - ``SANDBOX_ID``: Sandbox identifier

    Args:
        service_name: Override service name. Falls back to env vars.
        service_version: Override version. Falls back to AGT_SERVICE_VERSION.
        agent_did: Agent DID. Falls back to AGT_AGENT_DID.
        sandbox_id: Sandbox ID. Falls back to SANDBOX_ID.
        endpoint: OTLP endpoint URL. Falls back to OTEL_EXPORTER_OTLP_ENDPOINT.
        protocol: Export protocol, "grpc" or "http" (default: grpc).
        enable_metrics: Whether to configure MeterProvider (default: True).
        enable_tracing: Whether to configure TracerProvider (default: True).

    Returns:
        True if bootstrap succeeded, False if OTel SDK not available.
    """
    global _bootstrapped

    if _bootstrapped:
        logger.debug("OTel already bootstrapped, skipping")
        return True

    try:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
    except ImportError:
        logger.warning(
            "opentelemetry-sdk not installed. Install with: "
            "pip install opentelemetry-sdk opentelemetry-api"
        )
        _bootstrapped = True
        return False

    # Resolve configuration from env vars
    _service_name = (
        service_name
        or os.environ.get("OTEL_SERVICE_NAME")
        or os.environ.get("AGT_SERVICE_NAME")
        or "agt"
    )
    _service_version = service_version or os.environ.get("AGT_SERVICE_VERSION", "0.3.0")
    _agent_did = agent_did or os.environ.get("AGT_AGENT_DID", "")
    _sandbox_id = sandbox_id or os.environ.get("SANDBOX_ID", "")
    _endpoint = (
        endpoint
        or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or "http://localhost:4317"
    )

    # Build resource attributes
    attributes: dict[str, str] = {
        "service.name": _service_name,
        "service.version": _service_version,
    }
    if _agent_did:
        attributes["agent.did"] = _agent_did
    if _sandbox_id:
        attributes["sandbox.id"] = _sandbox_id

    resource = Resource.create(attributes)

    # Configure TracerProvider
    if enable_tracing:
        tracer_provider = TracerProvider(resource=resource)
        _attach_trace_exporter(tracer_provider, _endpoint, protocol)
        trace.set_tracer_provider(tracer_provider)
        logger.info("OTel TracerProvider configured (endpoint=%s)", _endpoint)

    # Configure MeterProvider
    if enable_metrics:
        meter_provider = MeterProvider(resource=resource)
        trace_configured = enable_tracing
        metrics.set_meter_provider(meter_provider)
        logger.info("OTel MeterProvider configured (endpoint=%s)", _endpoint)

    _bootstrapped = True
    logger.info(
        "AGT OTel bootstrap complete: service=%s, version=%s",
        _service_name,
        _service_version,
    )
    return True


def _attach_trace_exporter(
    provider: object, endpoint: str, protocol: str
) -> None:
    """Attach OTLP span exporter to the tracer provider (best-effort)."""
    try:
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        if protocol == "http":
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        else:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))  # type: ignore[attr-defined]
    except ImportError:
        logger.debug("OTLP exporter not available, traces will use in-memory provider only")


def is_bootstrapped() -> bool:
    """Return whether OTel has been bootstrapped."""
    return _bootstrapped


def get_tracer(name: str = "agentmesh") -> object:
    """Get an OTel tracer (or no-op if not bootstrapped).

    Args:
        name: Tracer instrumentation scope name.

    Returns:
        An opentelemetry Tracer instance or a no-op proxy.
    """
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        return _NoOpTracer()


def get_meter(name: str = "agentmesh") -> object:
    """Get an OTel meter (or no-op if not bootstrapped).

    Args:
        name: Meter instrumentation scope name.

    Returns:
        An opentelemetry Meter instance or a no-op proxy.
    """
    try:
        from opentelemetry import metrics
        return metrics.get_meter(name)
    except ImportError:
        return _NoOpMeter()


class _NoOpTracer:
    """Fallback tracer when OTel is unavailable."""

    def start_span(self, *args, **kwargs):
        return _NoOpSpan()

    def start_as_current_span(self, *args, **kwargs):
        import contextlib
        return contextlib.nullcontext(_NoOpSpan())


class _NoOpSpan:
    """Fallback span."""

    def set_attribute(self, key, value):
        pass

    def set_status(self, status):
        pass

    def end(self):
        pass


class _NoOpMeter:
    """Fallback meter when OTel is unavailable."""

    def create_counter(self, *args, **kwargs):
        return _NoOpInstrument()

    def create_histogram(self, *args, **kwargs):
        return _NoOpInstrument()

    def create_up_down_counter(self, *args, **kwargs):
        return _NoOpInstrument()

    def create_gauge(self, *args, **kwargs):
        return _NoOpInstrument()


class _NoOpInstrument:
    """Fallback metric instrument."""

    def add(self, *args, **kwargs):
        pass

    def record(self, *args, **kwargs):
        pass

    def set(self, *args, **kwargs):
        pass


def reset() -> None:
    """Reset bootstrap state (for testing only)."""
    global _bootstrapped
    _bootstrapped = False
