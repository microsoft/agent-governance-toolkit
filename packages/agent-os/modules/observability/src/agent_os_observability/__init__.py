# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS Observability - Production monitoring for AI agent systems.

Provides:
- OpenTelemetry traces for kernel operations
- Prometheus metrics for safety, latency, throughput
- Pre-built Grafana dashboards
- HTTP metrics server for Prometheus scraping
"""

from agent_os_observability.tracer import KernelTracer, trace_operation
from agent_os_observability.metrics import KernelMetrics, metrics_endpoint
from agent_os_observability.dashboards import get_grafana_dashboard
from agent_os_observability.server import MetricsServer, create_fastapi_router

__version__ = "3.1.1"
__all__ = [
    "KernelTracer",
    "trace_operation",
    "KernelMetrics",
    "metrics_endpoint",
    "get_grafana_dashboard",
    "MetricsServer",
    "create_fastapi_router",
]
