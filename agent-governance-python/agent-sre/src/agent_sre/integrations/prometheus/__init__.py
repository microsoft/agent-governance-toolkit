# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Prometheus metrics endpoint for Agent-SRE.

Usage:
    from agent_sre.integrations.prometheus import PrometheusExporter
    exporter = PrometheusExporter()
    exporter.set_gauge("agent_sre_slo_budget_remaining", 0.75, {"agent_id": "a1", "slo": "latency"})
    print(exporter.render())  # Prometheus text format
"""
from agent_sre.integrations.prometheus.exporter import PrometheusExporter

__all__ = ["PrometheusExporter"]
