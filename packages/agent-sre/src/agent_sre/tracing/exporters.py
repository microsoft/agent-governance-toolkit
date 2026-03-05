# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OTLP exporter setup helpers for agent-sre tracing.

Provides convenience functions to configure :class:`TracerProvider`
instances with BatchSpanProcessor for gRPC, HTTP, and console export.
"""

from __future__ import annotations

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)


def _build_resource(service_name: str = "agent-sre") -> Resource:
    """Build an OTel resource with the given service name."""
    return Resource.create({"service.name": service_name})


def configure_otlp_grpc(
    endpoint: str = "localhost:4317",
    headers: dict[str, str] | None = None,
    insecure: bool = True,
    service_name: str = "agent-sre",
) -> TracerProvider:
    """Configure a TracerProvider exporting via OTLP/gRPC.

    Args:
        endpoint: Collector gRPC endpoint (e.g. ``localhost:4317``).
        headers: Optional metadata headers for authentication.
        insecure: Whether to use an insecure channel.
        service_name: Service name for the OTel resource.

    Returns:
        A configured :class:`TracerProvider`.

    Raises:
        ImportError: If ``opentelemetry-exporter-otlp-proto-grpc`` is
            not installed.
    """
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter,
    )

    resource = _build_resource(service_name)
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(
        endpoint=endpoint,
        headers=tuple(headers.items()) if headers else None,
        insecure=insecure,
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    return provider


def configure_otlp_http(
    endpoint: str = "http://localhost:4318/v1/traces",
    headers: dict[str, str] | None = None,
    service_name: str = "agent-sre",
) -> TracerProvider:
    """Configure a TracerProvider exporting via OTLP/HTTP.

    Args:
        endpoint: Collector HTTP endpoint.
        headers: Optional headers for authentication.
        service_name: Service name for the OTel resource.

    Returns:
        A configured :class:`TracerProvider`.

    Raises:
        ImportError: If ``opentelemetry-exporter-otlp-proto-http`` is
            not installed.
    """
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )

    resource = _build_resource(service_name)
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(
        endpoint=endpoint,
        headers=headers or {},
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    return provider


def configure_console_exporter(
    service_name: str = "agent-sre",
) -> TracerProvider:
    """Configure a TracerProvider that prints spans to stdout.

    Intended for local development and debugging.

    Args:
        service_name: Service name for the OTel resource.

    Returns:
        A configured :class:`TracerProvider` with console output.
    """
    resource = _build_resource(service_name)
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    return provider
