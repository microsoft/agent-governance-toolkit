# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the cross-SDK OpenTelemetry instrumentation module.

Covers:
* ``GovernanceInstrumentor`` span creation and metric recording
* Context-manager tracing for policy evaluation
* Graceful no-op degradation when ``opentelemetry`` is absent
"""

from __future__ import annotations

import importlib
import sys
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agentmesh.observability.otel_sdk import GovernanceInstrumentor, _HAS_OTEL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_instrumentor():
    """Return a ``GovernanceInstrumentor`` wired to mock OTel primitives."""
    if not _HAS_OTEL:
        pytest.skip("opentelemetry not installed")

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        SimpleSpanProcessor,
        SpanExporter,
        SpanExportResult,
    )
    from opentelemetry import trace

    class _InMemoryExporter(SpanExporter):
        def __init__(self):
            self._spans: list = []

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

    # Force-set global provider
    trace._TRACER_PROVIDER = None
    trace._TRACER_PROVIDER_SET_ONCE._done = False
    trace.set_tracer_provider(provider)

    inst = GovernanceInstrumentor(service_name="test-otel-sdk")
    return inst, exporter


# =========================================================================
# GovernanceInstrumentor — with OTel available
# =========================================================================


class TestTracePolicyEvaluation:
    """Tests for the trace_policy_evaluation context manager."""

    def test_creates_span(self):
        inst, exporter = _make_instrumentor()
        with inst.trace_policy_evaluation("read_data", "agent-1"):
            pass
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "agt.policy.evaluate"

    def test_sets_action_and_agent_attributes(self):
        inst, exporter = _make_instrumentor()
        with inst.trace_policy_evaluation("write_data", "agent-2"):
            pass
        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["agt.action"] == "write_data"
        assert attrs["agt.agent_id"] == "agent-2"


class TestTraceTrustUpdate:
    """Tests for trace_trust_update."""

    def test_creates_span_with_scores(self):
        inst, exporter = _make_instrumentor()
        with inst.trace_trust_update("agent-3", 0.5, 0.8):
            pass
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "agt.trust.update"
        attrs = dict(spans[0].attributes)
        assert attrs["agt.agent_id"] == "agent-3"
        assert attrs["agt.old_score"] == 0.5
        assert attrs["agt.new_score"] == 0.8


class TestTraceAuditAppend:
    """Tests for trace_audit_append."""

    def test_creates_span_with_seq(self):
        inst, exporter = _make_instrumentor()
        with inst.trace_audit_append(42):
            pass
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "agt.audit.append"
        attrs = dict(spans[0].attributes)
        assert attrs["agt.seq"] == 42


class TestTraceIdentityOperation:
    """Tests for trace_identity_operation."""

    def test_creates_span_with_op_and_did(self):
        inst, exporter = _make_instrumentor()
        with inst.trace_identity_operation("verify", "did:mesh:abc"):
            pass
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "agt.identity.verify"
        attrs = dict(spans[0].attributes)
        assert attrs["agt.did"] == "did:mesh:abc"


class TestMetricRecording:
    """Tests for record_* metric helpers."""

    def test_record_policy_decision_does_not_raise(self):
        inst, _ = _make_instrumentor()
        inst.record_policy_decision("allow", 1.5)

    def test_record_trust_score_does_not_raise(self):
        inst, _ = _make_instrumentor()
        inst.record_trust_score("agent-1", 0.95)

    def test_record_audit_chain_length_does_not_raise(self):
        inst, _ = _make_instrumentor()
        inst.record_audit_chain_length(100)


# =========================================================================
# GovernanceInstrumentor — graceful degradation (OTel absent)
# =========================================================================


class TestGracefulDegradation:
    """GovernanceInstrumentor must be a safe no-op without opentelemetry."""

    def test_disabled_when_otel_missing(self):
        """Instrumentor reports disabled when OTel is absent."""
        with patch.dict(sys.modules, {"opentelemetry": None, "opentelemetry.trace": None, "opentelemetry.metrics": None}):
            mod = importlib.import_module("agentmesh.observability.otel_sdk")
            importlib.reload(mod)
            inst = mod.GovernanceInstrumentor()
            assert not inst.enabled

    def test_trace_policy_evaluation_noop(self):
        """Context manager yields without error when OTel is absent."""
        with patch.dict(sys.modules, {"opentelemetry": None, "opentelemetry.trace": None, "opentelemetry.metrics": None}):
            mod = importlib.import_module("agentmesh.observability.otel_sdk")
            importlib.reload(mod)
            inst = mod.GovernanceInstrumentor()
            with inst.trace_policy_evaluation("act", "a1"):
                pass

    def test_trace_methods_noop(self):
        """All trace methods complete without error when OTel is absent."""
        with patch.dict(sys.modules, {"opentelemetry": None, "opentelemetry.trace": None, "opentelemetry.metrics": None}):
            mod = importlib.import_module("agentmesh.observability.otel_sdk")
            importlib.reload(mod)
            inst = mod.GovernanceInstrumentor()
            with inst.trace_trust_update("a1", 0.5, 0.8):
                pass
            with inst.trace_audit_append(1):
                pass
            with inst.trace_identity_operation("create", "did:mesh:x"):
                pass

    def test_record_methods_noop(self):
        """All record methods complete without error when OTel is absent."""
        with patch.dict(sys.modules, {"opentelemetry": None, "opentelemetry.trace": None, "opentelemetry.metrics": None}):
            mod = importlib.import_module("agentmesh.observability.otel_sdk")
            importlib.reload(mod)
            inst = mod.GovernanceInstrumentor()
            inst.record_policy_decision("deny", 2.0)
            inst.record_trust_score("a1", 0.5)
            inst.record_audit_chain_length(10)

    def test_explicit_disabled_flag(self):
        """Instrumentor respects enabled=False even when OTel is available."""
        inst = GovernanceInstrumentor(enabled=False)
        assert not inst.enabled
        with inst.trace_policy_evaluation("act", "a1"):
            pass
        with inst.trace_trust_update("a1", 0.5, 0.8):
            pass
        with inst.trace_audit_append(1):
            pass
        with inst.trace_identity_operation("create", "did:mesh:x"):
            pass
        inst.record_policy_decision("deny", 2.0)
        inst.record_trust_score("a1", 0.5)
        inst.record_audit_chain_length(10)


# =========================================================================
# GovernanceInstrumentor — thread safety (#1504)
# =========================================================================


class TestGovernanceInstrumentorThreadSafety:
    """Concurrent use of GovernanceInstrumentor must not corrupt state."""

    def test_concurrent_trace_and_record(self):
        """Multiple threads calling trace and record concurrently must not raise."""
        import threading

        inst, _exporter = _make_instrumentor()
        errors: list[Exception] = []

        def worker(idx: int) -> None:
            try:
                for _ in range(20):
                    with inst.trace_policy_evaluation(f"action-{idx}", f"agent-{idx}"):
                        pass
                    inst.record_policy_decision("allow", float(idx))
                    inst.record_trust_score(f"agent-{idx}", 0.9)
                    with inst.trace_trust_update(f"agent-{idx}", 0.5, 0.8):
                        pass
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Primary assertion: no thread raised an exception.
        assert not errors, f"Thread-safety errors: {errors}"

    def test_concurrent_disabled_noop(self):
        """Disabled instrumentor must be safe under concurrent use."""
        import threading

        inst = GovernanceInstrumentor(enabled=False)
        errors: list[Exception] = []

        def worker(idx: int) -> None:
            try:
                for _ in range(20):
                    with inst.trace_policy_evaluation(f"act-{idx}", f"a-{idx}"):
                        pass
                    inst.record_policy_decision("deny", 1.0)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread-safety errors: {errors}"
