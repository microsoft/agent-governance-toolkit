# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OTLP exporter setup helpers for agent-sre tracing.

Provides convenience functions to configure :class:`TracerProvider`
instances with BatchSpanProcessor for gRPC, HTTP, and console export.
"""

from __future__ import annotations

import logging

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)

from agent_sre.tracing._tls_utils import is_local_endpoint as _is_local_endpoint

_logger = logging.getLogger(__name__)


def _build_resource(service_name: str = "agent-sre") -> Resource:
    """Build an OTel resource with the given service name."""
    return Resource.create({"service.name": service_name})


def configure_otlp_grpc(
    endpoint: str = "localhost:4317",
    headers: dict[str, str] | None = None,
    insecure: bool = False,
    service_name: str = "agent-sre",
) -> TracerProvider:
    """Configure a TracerProvider exporting via OTLP/gRPC.

    Args:
        endpoint: Collector gRPC endpoint (e.g. ``localhost:4317``).
        headers: Optional metadata headers for authentication.
        insecure: Whether to use an insecure (plaintext) channel.  Only
            permitted for loopback endpoints; raises :exc:`ValueError` for
            non-local endpoints to prevent accidental plaintext export.
            Defaults to ``False`` (TLS required).
        service_name: Service name for the OTel resource.

    Returns:
        A configured :class:`TracerProvider`.

    Raises:
        ImportError: If ``opentelemetry-exporter-otlp-proto-grpc`` is
            not installed.
        ValueError: If ``insecure=True`` is requested for a non-local endpoint.
    """
    if insecure and not _is_local_endpoint(endpoint):
        raise ValueError(
            f"Insecure (plaintext) OTLP/gRPC transport is not permitted for "
            f"non-local endpoint '{endpoint}'. Set insecure=False or use a "
            f"TLS-enabled collector."
        )
    if insecure:
        _logger.warning(
            "OTLP/gRPC exporter is using an insecure (plaintext) channel to %s. "
            "This is only acceptable for local development.",
            endpoint,
        )

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
