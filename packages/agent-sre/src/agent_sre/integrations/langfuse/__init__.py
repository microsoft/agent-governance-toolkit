# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Langfuse integration for Agent SRE.

Bridges Agent SRE reliability data to Langfuse for unified observability.
Since Langfuse v3 is built on OpenTelemetry, this integration leverages
the Agent SRE OTEL exporters and adds Langfuse-specific features:

- SLO health as Langfuse scores on traces
- Cost tracking via Langfuse usage observations
- SLI compliance as trace-level metadata

Two usage modes:
1. **OTEL bridge** (recommended): Configure Langfuse as your OTLP endpoint,
   then use Agent SRE's MetricsExporter/TraceExporter normally.
2. **Direct API**: Use LangfuseExporter for Langfuse-native features
   (scores, usage_details) that go beyond standard OTLP.

Usage:
    from agent_sre.integrations.langfuse import LangfuseExporter

    exporter = LangfuseExporter()  # Uses LANGFUSE_* env vars
    exporter.score_slo(trace_id="...", slo=my_slo)
    exporter.record_cost_observation(trace_id="...", agent_id="bot-1", cost_usd=0.35)
"""

from agent_sre.integrations.langfuse.exporter import LangfuseExporter

__all__ = ["LangfuseExporter"]
