# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end integration tests for Agent OS observability module."""

import sys
import os
import re
import json
import time
import random
import threading
import urllib.request
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from agent_os_observability.metrics import KernelMetrics
from agent_os_observability.tracer import KernelTracer
from agent_os_observability.dashboards import get_grafana_dashboard
from agent_os_observability.server import MetricsServer


class InMemorySpanExporter(SpanExporter):
    """Simple in-memory span exporter for testing."""

    def __init__(self):
        self._spans = []
        self._lock = threading.Lock()

    def export(self, spans):
        with self._lock:
            self._spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self):
        pass

    def force_flush(self, timeout_millis=0):
        return True

    def get_finished_spans(self):
        with self._lock:
            return list(self._spans)


def _unique_ns():
    return f"integ_{uuid4().hex[:8]}"


def _random_port():
    return random.randint(29000, 39000)


class TestMetricsAndServerIntegration:
    """Record metrics, start server, scrape /metrics, verify data."""

    def test_full_metrics_pipeline(self):
        port = _random_port()
        ns = _unique_ns()
        metrics = KernelMetrics(namespace=ns)

        # Record various events
        metrics.record_request("query", "success")
        metrics.record_request("write", "failure")
        metrics.record_violation("agent-1", "delete", "no_delete", "high")
        metrics.record_blocked("agent-2", "exec")
        metrics.record_signal("SIGTERM", "timeout")
        metrics.record_recovery(5.0, True)
        metrics.record_crash("agent-3", "oom")
        metrics.record_cmvk_verification("verified", 0.95, 0.05, 2.0, model_count=3)
        metrics.record_cmvk_disagreement("gpt4", "claude")
        metrics.record_agent_llm_call("agent-1", "gpt-4")
        metrics.record_agent_error("agent-1", "timeout")
        metrics.record_agent_execution("agent-1", 3.5)

        server = MetricsServer(port=port, host="127.0.0.1", metrics=metrics)
        server.start(blocking=False)
        time.sleep(0.3)

        try:
            resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5)
            body = resp.read().decode("utf-8")

            assert f"{ns}_requests_total" in body
            assert f"{ns}_violations_total" in body
            assert f"{ns}_violations_blocked_total" in body
            assert f"{ns}_sigkill_total" in body
            assert f"{ns}_signals_total" in body
            assert f"{ns}_mttr_seconds" in body
            assert f"{ns}_recovery_total" in body
            assert f"{ns}_agent_crashes_total" in body
            assert f"{ns}_cmvk_verifications_total" in body
            assert f"{ns}_cmvk_model_disagreements_total" in body
            assert f"{ns}_agent_llm_calls_total" in body
            assert f"{ns}_agent_errors_total" in body
            assert f"{ns}_agent_execution_duration_seconds" in body
        finally:
            server.stop()


class TestTracerIntegration:
    """Create KernelTracer with InMemorySpanExporter, verify spans."""

    def test_trace_operations_produce_spans(self):
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.resources import Resource

        exporter = InMemorySpanExporter()
        provider = TracerProvider(
            resource=Resource.create({"service.name": "integ-test"})
        )
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = KernelTracer.__new__(KernelTracer)
        tracer.tracer = provider.get_tracer(__name__)

        with tracer.trace_policy_check("agent-1", "query", ["pol_a"]):
            pass

        with tracer.trace_execution("agent-1", "write"):
            pass

        with tracer.trace_signal("agent-1", "SIGKILL", "violation"):
            pass

        with tracer.trace_violation("agent-1", "delete", "no_delete", "breach"):
            pass

        @tracer.trace("decorated_fn")
        def compute():
            return 42

        assert compute() == 42

        provider.force_flush()
        spans = exporter.get_finished_spans()
        names = [s.name for s in spans]

        assert "kernel.policy_check" in names
        assert "kernel.execute" in names
        assert "kernel.signal" in names
        assert "kernel.violation" in names
        assert "decorated_fn" in names
        provider.shutdown()


class TestMetricsAndTracerTogether:
    """Verify metrics and traces work together."""

    def test_record_metrics_during_traced_operations(self):
        ns = _unique_ns()
        metrics = KernelMetrics(namespace=ns)

        # Build tracer manually to avoid global provider issue
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.resources import Resource

        exporter = InMemorySpanExporter()
        provider = TracerProvider(
            resource=Resource.create({"service.name": "combined-test"})
        )
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = KernelTracer.__new__(KernelTracer)
        tracer.tracer = provider.get_tracer(__name__)

        with tracer.trace_policy_check("agent-1", "query", ["pol_a"]):
            metrics.record_request("query", "success")

        with tracer.trace_execution("agent-1", "write"):
            metrics.record_request("write", "success")

        # Verify metrics recorded
        output = metrics.export().decode("utf-8")
        assert f"{ns}_requests_total" in output

        # Verify spans recorded
        provider.force_flush()
        spans = exporter.get_finished_spans()
        names = [s.name for s in spans]
        assert "kernel.policy_check" in names
        assert "kernel.execute" in names
        provider.shutdown()


class TestDashboardMetricConsistency:
    """Verify dashboard PromQL expressions reference actual metric names."""

    def test_dashboard_promql_matches_exported_metrics(self):
        ns = "agent_os"
        metrics = KernelMetrics(namespace=ns)
        # Record one of everything to populate metric names
        metrics.record_request("q", "ok")
        metrics.record_violation("a", "act", "pol")
        metrics.record_blocked("a", "act")
        metrics.record_signal("SIGTERM", "r")
        metrics.record_recovery(1.0, True)
        metrics.record_crash("a", "r")
        metrics.record_cmvk_verification("verified", 0.9, 0.1, 1.0)
        metrics.record_cmvk_disagreement("a_model", "b_model")
        metrics.record_agent_llm_call("a", "m")
        metrics.record_agent_error("a", "e")
        metrics.record_agent_execution("a", 1.0)
        # Observe histograms so _bucket metrics appear
        with metrics.policy_check_latency("default"):
            pass
        with metrics.execution_latency("q", "ok"):
            pass
        metrics.kernel_latency.observe(0.01)
        metrics.cmvk_model_latency.labels(model="m").observe(1.0)

        exported = metrics.export().decode("utf-8")

        # Extract all metric base names from exported output
        exported_metrics = set()
        for line in exported.split("\n"):
            if line and not line.startswith("#"):
                match = re.match(r"([a-zA-Z_:][a-zA-Z0-9_:]*)", line)
                if match:
                    exported_metrics.add(match.group(1))

        # Check dashboard PromQL references valid metric base names
        dashboard_names = [
            "agent-os-overview",
            "agent-os-safety",
            "agent-os-cmvk",
        ]

        for dname in dashboard_names:
            d = get_grafana_dashboard(dname)
            panels = d["dashboard"]["panels"]
            for panel in panels:
                if "targets" not in panel:
                    continue
                for target in panel["targets"]:
                    expr = target["expr"]
                    # Extract metric names from PromQL (agent_os_...)
                    prom_metrics = re.findall(r"(agent_os_[a-zA-Z_]+)", expr)
                    for pm in prom_metrics:
                        # Strip common suffixes for matching
                        base = pm
                        for suffix in ("_bucket", "_count", "_sum", "_total", "_created", "_info"):
                            if base.endswith(suffix):
                                base = base[: -len(suffix)]
                                break
                        found = any(
                            em.startswith(base) or base.startswith(em)
                            for em in exported_metrics
                        )
                        assert found, (
                            f"Dashboard '{dname}' panel '{panel['title']}' references "
                            f"metric '{pm}' (base: '{base}') not found in exported metrics"
                        )
