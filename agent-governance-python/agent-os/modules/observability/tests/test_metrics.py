# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for KernelMetrics (metrics.py)."""

import sys
import os
import time
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_os_observability.metrics import KernelMetrics, metrics_endpoint


def _unique_ns():
    """Generate a unique namespace to avoid prometheus_client global state collisions."""
    return f"test_{uuid4().hex[:8]}"


class TestKernelMetricsInit:
    """Tests for KernelMetrics initialization."""

    def test_default_namespace(self):
        m = KernelMetrics(namespace=_unique_ns())
        assert m.namespace.startswith("test_")

    def test_creates_counter_metrics(self):
        m = KernelMetrics(namespace=_unique_ns())
        from prometheus_client import Counter
        assert isinstance(m.requests_total, Counter)
        assert isinstance(m.violations_total, Counter)
        assert isinstance(m.violations_blocked, Counter)
        assert isinstance(m.signals_sent, Counter)
        assert isinstance(m.sigkill_count, Counter)
        assert isinstance(m.recovery_success, Counter)
        assert isinstance(m.agent_crashes, Counter)
        assert isinstance(m.kernel_crashes, Counter)
        assert isinstance(m.cmvk_verifications_total, Counter)
        assert isinstance(m.cmvk_model_disagreements, Counter)
        assert isinstance(m.cmvk_claims_by_confidence, Counter)
        assert isinstance(m.agent_llm_calls, Counter)
        assert isinstance(m.agent_errors, Counter)

    def test_creates_histogram_metrics(self):
        m = KernelMetrics(namespace=_unique_ns())
        from prometheus_client import Histogram
        assert isinstance(m.policy_check_duration, Histogram)
        assert isinstance(m.execution_duration, Histogram)
        assert isinstance(m.kernel_latency, Histogram)
        assert isinstance(m.mttr_seconds, Histogram)
        assert isinstance(m.cmvk_drift_score, Histogram)
        assert isinstance(m.cmvk_verification_duration, Histogram)
        assert isinstance(m.cmvk_model_latency, Histogram)
        assert isinstance(m.agent_execution_duration, Histogram)

    def test_creates_gauge_metrics(self):
        m = KernelMetrics(namespace=_unique_ns())
        from prometheus_client import Gauge
        assert isinstance(m.violation_rate, Gauge)
        assert isinstance(m.active_agents, Gauge)
        assert isinstance(m.kernel_uptime, Gauge)
        assert isinstance(m.cmvk_consensus_ratio, Gauge)

    def test_creates_info_metric(self):
        m = KernelMetrics(namespace=_unique_ns())
        from prometheus_client import Info
        assert isinstance(m.kernel_info, Info)

    def test_creates_summary_is_not_required(self):
        # Source code doesn't use Summary, verify init completes
        m = KernelMetrics(namespace=_unique_ns())
        assert m is not None

    def test_custom_namespace_prefixes_metrics(self):
        ns = _unique_ns()
        m = KernelMetrics(namespace=ns)
        output = m.export().decode("utf-8")
        assert f"{ns}_requests_total" in output or f"{ns}_kernel_uptime" in output


class TestRecordRequest:
    def test_increments_requests_total(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_request("query", "success")
        output = m.export().decode("utf-8")
        assert 'action="query"' in output
        assert 'status="success"' in output

    def test_increments_internal_count(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_request("query", "success")
        assert m._request_count == 1
        m.record_request("write", "failure")
        assert m._request_count == 2


class TestRecordViolation:
    def test_increments_violations_total(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_violation("agent-1", "delete_file", "no_delete", "high")
        output = m.export().decode("utf-8")
        assert 'agent_id="agent-1"' in output
        assert 'policy="no_delete"' in output

    def test_updates_violation_rate(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_request("query", "success")
        m.record_violation("agent-1", "delete_file", "no_delete")
        # rate = 1/1 * 1000 = 1000
        assert m._violation_count == 1

    def test_default_severity_is_high(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_violation("a1", "act", "pol")
        output = m.export().decode("utf-8")
        assert 'severity="high"' in output


class TestRecordBlocked:
    def test_increments_violations_blocked_and_sigkill(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_blocked("agent-1", "rm_rf")
        output = m.export().decode("utf-8")
        ns = m.namespace
        assert f"{ns}_violations_blocked_total" in output
        assert f"{ns}_sigkill_total" in output
        assert f"{ns}_signals_total" in output


class TestRecordSignal:
    def test_increments_signals_sent(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_signal("SIGTERM", "timeout")
        output = m.export().decode("utf-8")
        assert 'signal="SIGTERM"' in output
        assert 'reason="timeout"' in output


class TestRecordRecovery:
    def test_observes_mttr_and_increments_recovery(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_recovery(5.0, True)
        m.record_recovery(10.0, False)
        output = m.export().decode("utf-8")
        ns = m.namespace
        assert f"{ns}_mttr_seconds" in output
        assert f"{ns}_recovery_total" in output
        assert 'status="success"' in output
        assert 'status="failed"' in output


class TestRecordCrash:
    def test_agent_crash(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_crash("agent-1", "oom")
        output = m.export().decode("utf-8")
        assert f"{m.namespace}_agent_crashes_total" in output
        assert 'agent_id="agent-1"' in output

    def test_kernel_crash(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_crash("kernel", "panic", is_kernel=True)
        output = m.export().decode("utf-8")
        assert f"{m.namespace}_kernel_crashes_total" in output


class TestRecordCMVK:
    def test_record_cmvk_verification(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_cmvk_verification("verified", 0.95, 0.05, 2.0, model_count=3)
        output = m.export().decode("utf-8")
        ns = m.namespace
        assert f"{ns}_cmvk_verifications_total" in output
        assert f"{ns}_cmvk_drift_score" in output
        assert f"{ns}_cmvk_verification_duration_seconds" in output

    def test_confidence_bucket_high(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_cmvk_verification("verified", 0.95, 0.05, 1.0)
        output = m.export().decode("utf-8")
        assert 'confidence_bucket="high"' in output

    def test_confidence_bucket_medium(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_cmvk_verification("verified", 0.75, 0.1, 1.0)
        output = m.export().decode("utf-8")
        assert 'confidence_bucket="medium"' in output

    def test_confidence_bucket_low(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_cmvk_verification("flagged", 0.5, 0.3, 1.0)
        output = m.export().decode("utf-8")
        assert 'confidence_bucket="low"' in output

    def test_confidence_boundary_09_is_high(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_cmvk_verification("verified", 0.9, 0.05, 1.0)
        output = m.export().decode("utf-8")
        assert 'confidence_bucket="high"' in output

    def test_confidence_boundary_07_is_medium(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_cmvk_verification("verified", 0.7, 0.1, 1.0)
        output = m.export().decode("utf-8")
        assert 'confidence_bucket="medium"' in output

    def test_record_cmvk_disagreement_normalizes_alphabetically(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_cmvk_disagreement("gpt4", "claude")
        output = m.export().decode("utf-8")
        assert 'model_pair="claude_gpt4"' in output

    def test_record_cmvk_disagreement_already_sorted(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_cmvk_disagreement("claude", "gpt4")
        output = m.export().decode("utf-8")
        assert 'model_pair="claude_gpt4"' in output


class TestAgentMetrics:
    def test_record_agent_llm_call(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_agent_llm_call("agent-1", "gpt-4")
        output = m.export().decode("utf-8")
        assert 'agent_id="agent-1"' in output
        assert 'model="gpt-4"' in output

    def test_record_agent_error(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_agent_error("agent-1", "timeout")
        output = m.export().decode("utf-8")
        assert 'error_type="timeout"' in output

    def test_record_agent_execution(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_agent_execution("agent-1", 3.5)
        output = m.export().decode("utf-8")
        assert f"{m.namespace}_agent_execution_duration_seconds" in output


class TestExport:
    def test_export_returns_bytes(self):
        m = KernelMetrics(namespace=_unique_ns())
        result = m.export()
        assert isinstance(result, bytes)

    def test_export_contains_help_and_type(self):
        m = KernelMetrics(namespace=_unique_ns())
        output = m.export().decode("utf-8")
        assert "# HELP" in output
        assert "# TYPE" in output

    def test_export_parseable_prometheus_format(self):
        m = KernelMetrics(namespace=_unique_ns())
        m.record_request("query", "success")
        output = m.export().decode("utf-8")
        lines = output.strip().split("\n")
        for line in lines:
            if line.startswith("#"):
                assert line.startswith("# HELP") or line.startswith("# TYPE")
            elif line.strip():
                # metric lines have name{labels} value or name value
                parts = line.split()
                assert len(parts) >= 2

    def test_content_type_returns_string(self):
        m = KernelMetrics(namespace=_unique_ns())
        ct = m.content_type()
        assert isinstance(ct, str)
        assert "text/plain" in ct or "text/openmetrics" in ct or "text" in ct


class TestContextManagers:
    def test_policy_check_latency(self):
        m = KernelMetrics(namespace=_unique_ns())
        with m.policy_check_latency("my_policy"):
            time.sleep(0.01)
        output = m.export().decode("utf-8")
        assert f"{m.namespace}_policy_check_duration_seconds" in output
        assert 'policy="my_policy"' in output

    def test_execution_latency(self):
        m = KernelMetrics(namespace=_unique_ns())
        with m.execution_latency("query", "success"):
            time.sleep(0.01)
        output = m.export().decode("utf-8")
        assert f"{m.namespace}_execution_duration_seconds" in output


class TestUpdateUptime:
    def test_update_uptime_sets_gauge(self):
        m = KernelMetrics(namespace=_unique_ns())
        time.sleep(0.05)
        m.update_uptime()
        output = m.export().decode("utf-8")
        assert f"{m.namespace}_kernel_uptime_seconds" in output


class TestMetricsEndpoint:
    def test_returns_callable(self):
        m = KernelMetrics(namespace=_unique_ns())
        handler = metrics_endpoint(m)
        assert callable(handler)

    def test_handler_returns_bytes_and_content_type(self):
        m = KernelMetrics(namespace=_unique_ns())
        handler = metrics_endpoint(m)
        body, ct = handler()
        assert isinstance(body, bytes)
        assert isinstance(ct, str)
