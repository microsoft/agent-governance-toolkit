# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for governance-specific OpenTelemetry and Prometheus integration.

Covers:
* ``GovernanceTracer`` span creation and attribute correctness
* ``GovernanceMetrics`` counter/gauge/histogram recording
* Graceful degradation when optional dependencies are absent
* Prometheus text exposition format output
"""

from __future__ import annotations

import importlib
import sys
from unittest.mock import patch

import pytest

from agentmesh.observability.otel_governance import GovernanceTracer, _OTEL_AVAILABLE
from agentmesh.observability.prometheus_governance import GovernanceMetrics, _PROMETHEUS_AVAILABLE


# ---------------------------------------------------------------------------
# Helpers — in-memory OTEL exporter
# ---------------------------------------------------------------------------


def _make_governance_tracer():
    """Return a ``GovernanceTracer`` backed by an in-memory span exporter."""
    if not _OTEL_AVAILABLE:
        pytest.skip("opentelemetry not installed")

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        SimpleSpanProcessor,
        SpanExporter,
        SpanExportResult,
    )
    from opentelemetry import trace

    class _InMemoryExporter(SpanExporter):
        """Minimal in-memory exporter for testing."""

        def __init__(self):
            self._spans = []

        def export(self, spans):
            self._spans.extend(spans)
            return SpanExportResult.SUCCESS

        def shutdown(self):
            pass

        def get_finished_spans(self):
            return list(self._spans)

    exporter = _InMemoryExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # Force-set the global provider (bypass the "already set" guard)
    trace._TRACER_PROVIDER = None
    trace._TRACER_PROVIDER_SET_ONCE._done = False
    trace.set_tracer_provider(provider)

    tracer = GovernanceTracer(
        service_name="governance-test",
        tracer_provider=provider,
    )
    return tracer, exporter


# ---------------------------------------------------------------------------
# Helpers — isolated Prometheus registry
# ---------------------------------------------------------------------------


@pytest.fixture()
def _clean_prometheus_registry():
    """Reset the default Prometheus registry between tests."""
    try:
        from prometheus_client import REGISTRY

        collectors = list(REGISTRY._names_to_collectors.values())
        for collector in collectors:
            try:
                REGISTRY.unregister(collector)
            except Exception:
                pass
    except ImportError:
        pass
    yield


def _make_governance_metrics():
    """Return ``GovernanceMetrics`` bound to a fresh isolated registry."""
    if not _PROMETHEUS_AVAILABLE:
        pytest.skip("prometheus-client not installed")

    from prometheus_client import CollectorRegistry

    registry = CollectorRegistry()
    return GovernanceMetrics(registry=registry), registry


# =========================================================================
# GovernanceTracer tests
# =========================================================================


class TestTracePolicyDecision:
    """Tests for GovernanceTracer.trace_policy_decision."""

    def test_creates_span_with_correct_name(self):
        tracer, exporter = _make_governance_tracer()
        tracer.trace_policy_decision(
            policy_name="max-delegation-depth",
            decision={"action": "DENY", "reason": "depth exceeded"},
            context={"agent_did": "did:mesh:aaa"},
        )
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "mesh.governance.policy_decision"

    def test_sets_correct_attributes(self):
        tracer, exporter = _make_governance_tracer()
        tracer.trace_policy_decision(
            policy_name="namespace-isolation",
            decision={"action": "ALLOW"},
            context={"agent_did": "did:mesh:bbb", "namespace": "finance"},
        )
        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["policy.name"] == "namespace-isolation"
        assert attrs["policy.decision"] == "ALLOW"
        assert attrs["governance.agent_did"] == "did:mesh:bbb"
        assert attrs["governance.namespace"] == "finance"
        assert "mesh.operation.duration_ms" in attrs


class TestTraceTrustEvaluation:
    """Tests for GovernanceTracer.trace_trust_evaluation."""

    def test_creates_span_with_correct_name(self):
        tracer, exporter = _make_governance_tracer()
        tracer.trace_trust_evaluation(
            agent_did="did:mesh:ccc",
            trust_score=0.87,
            decision="trusted",
        )
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "mesh.governance.trust_evaluation"

    def test_sets_correct_attributes(self):
        tracer, exporter = _make_governance_tracer()
        tracer.trace_trust_evaluation(
            agent_did="did:mesh:ddd",
            trust_score=0.42,
            decision="untrusted",
        )
        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["agent.did"] == "did:mesh:ddd"
        assert attrs["agent.trust_score"] == 0.42
        assert attrs["governance.trust.decision"] == "untrusted"


class TestTraceSignalDelivery:
    """Tests for GovernanceTracer.trace_signal_delivery."""

    def test_creates_span_and_attributes(self):
        tracer, exporter = _make_governance_tracer()
        tracer.trace_signal_delivery(
            agent_id="agent-007",
            signal_name="SIGPOLICY",
            reason="policy violation detected",
        )
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "mesh.governance.signal_delivery"

        attrs = dict(spans[0].attributes)
        assert attrs["agent.id"] == "agent-007"
        assert attrs["governance.signal.name"] == "SIGPOLICY"
        assert attrs["governance.signal.reason"] == "policy violation detected"


class TestTraceAuditEvent:
    """Tests for GovernanceTracer.trace_audit_event."""

    def test_creates_span_and_attributes(self):
        tracer, exporter = _make_governance_tracer()
        tracer.trace_audit_event(
            entry_id="audit-001",
            event_type="trust_update",
            agent_did="did:mesh:eee",
        )
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "mesh.governance.audit_event"

        attrs = dict(spans[0].attributes)
        assert attrs["audit.entry_id"] == "audit-001"
        assert attrs["audit.event_type"] == "trust_update"
        assert attrs["agent.did"] == "did:mesh:eee"


# =========================================================================
# GovernanceTracer — graceful degradation
# =========================================================================


class TestTracerGracefulDegradation:
    """GovernanceTracer must be a safe no-op when OpenTelemetry is absent."""

    def test_tracer_disabled_without_otel(self):
        with patch("agentmesh.observability.otel_governance._OTEL_AVAILABLE", False):
            tracer = GovernanceTracer.__new__(GovernanceTracer)
            tracer._service_name = "governance"
            tracer._tracer = None
            assert not tracer.enabled

    def test_methods_are_noop_without_otel(self):
        with patch("agentmesh.observability.otel_governance._OTEL_AVAILABLE", False):
            tracer = GovernanceTracer.__new__(GovernanceTracer)
            tracer._service_name = "governance"
            tracer._tracer = None

            # All methods must complete without error
            tracer.trace_policy_decision("p", {"action": "ALLOW"}, {})
            tracer.trace_trust_evaluation("did:mesh:x", 0.5, "trusted")
            tracer.trace_signal_delivery("a", "SIGKILL", "test")
            tracer.trace_audit_event("e1", "test", "did:mesh:y")


# =========================================================================
# GovernanceMetrics tests
# =========================================================================


class TestGovernanceMetricsRecording:
    """Tests for GovernanceMetrics recording methods."""

    def test_record_policy_evaluation(self):
        metrics, _ = _make_governance_metrics()
        metrics.record_policy_evaluation("max-tokens", "DENY", 3.5)

        assert (
            metrics.policy_evaluations_total.labels(
                policy_name="max-tokens", action="DENY"
            )._value.get()
            == 1.0
        )
        assert (
            metrics.policy_evaluation_duration_ms.labels(
                policy_name="max-tokens"
            )._sum.get()
            == 3.5
        )

    def test_record_trust_score(self):
        metrics, _ = _make_governance_metrics()
        metrics.record_trust_score("did:mesh:abc", 0.91)

        assert (
            metrics.trust_score.labels(agent_did="did:mesh:abc")._value.get()
            == 0.91
        )

    def test_record_signal(self):
        metrics, _ = _make_governance_metrics()
        metrics.record_signal("SIGKILL", "agent-001")
        metrics.record_signal("SIGKILL", "agent-002")

        assert (
            metrics.signals_total.labels(signal_name="SIGKILL")._value.get()
            == 2.0
        )

    def test_record_violation(self):
        metrics, _ = _make_governance_metrics()
        metrics.record_violation("scope_exceeded", "high")
        metrics.record_violation("scope_exceeded", "high")
        metrics.record_violation("token_abuse", "critical")

        assert (
            metrics.violations_total.labels(
                violation_type="scope_exceeded", severity="high"
            )._value.get()
            == 2.0
        )
        assert (
            metrics.violations_total.labels(
                violation_type="token_abuse", severity="critical"
            )._value.get()
            == 1.0
        )

    def test_record_audit_event(self):
        metrics, _ = _make_governance_metrics()
        metrics.record_audit_event("trust_update")
        metrics.record_audit_event("policy_check")
        metrics.record_audit_event("trust_update")

        assert (
            metrics.audit_events_total.labels(
                event_type="trust_update"
            )._value.get()
            == 2.0
        )
        assert (
            metrics.audit_events_total.labels(
                event_type="policy_check"
            )._value.get()
            == 1.0
        )


# =========================================================================
# GovernanceMetrics — text exposition
# =========================================================================


class TestGovernanceMetricsExposition:
    """Tests for get_metrics_text output."""

    def test_metrics_text_contains_expected_families(self):
        metrics, _ = _make_governance_metrics()
        metrics.record_policy_evaluation("p1", "ALLOW", 1.0)
        metrics.record_violation("v1", "low")

        text = metrics.get_metrics_text()
        assert "agentmesh_governance_policy_evaluations_total" in text
        assert "agentmesh_governance_violations_total" in text

    def test_metrics_text_empty_when_disabled(self):
        with patch(
            "agentmesh.observability.prometheus_governance._PROMETHEUS_AVAILABLE",
            False,
        ):
            m = GovernanceMetrics.__new__(GovernanceMetrics)
            m._enabled = False
            assert m.get_metrics_text() == ""


# =========================================================================
# GovernanceMetrics — graceful degradation
# =========================================================================


class TestMetricsGracefulDegradation:
    """GovernanceMetrics must degrade gracefully without prometheus-client."""

    def test_disabled_when_import_fails(self):
        with patch.dict(sys.modules, {"prometheus_client": None}):
            mod = importlib.import_module(
                "agentmesh.observability.prometheus_governance"
            )
            importlib.reload(mod)
            m = mod.GovernanceMetrics()

            assert m.enabled is False

            # All recording methods must be no-ops
            m.record_policy_evaluation("p", "ALLOW", 1.0)
            m.record_trust_score("did:mesh:x", 0.5)
            m.record_signal("SIGKILL", "a")
            m.record_violation("v", "low")
            m.record_audit_event("test")
            assert m.get_metrics_text() == ""
