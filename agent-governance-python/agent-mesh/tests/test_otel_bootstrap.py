# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for centralized OTEL bootstrap and /metrics endpoint."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest


class TestBootstrapOtel:
    """Tests for agentmesh.telemetry.bootstrap_otel."""

    def setup_method(self):
        """Reset bootstrap state before each test."""
        from agentmesh.telemetry import reset
        reset()

    def teardown_method(self):
        from agentmesh.telemetry import reset
        reset()

    def test_bootstrap_returns_true_with_otel_installed(self):
        from agentmesh.telemetry import bootstrap_otel
        result = bootstrap_otel(service_name="test-svc")
        assert result is True

    def test_bootstrap_idempotent(self):
        from agentmesh.telemetry import bootstrap_otel
        assert bootstrap_otel(service_name="test-svc") is True
        assert bootstrap_otel(service_name="other") is True  # no-op, still True

    def test_is_bootstrapped(self):
        from agentmesh.telemetry import bootstrap_otel, is_bootstrapped
        assert is_bootstrapped() is False
        bootstrap_otel(service_name="test")
        assert is_bootstrapped() is True

    def test_env_var_service_name(self):
        from agentmesh.telemetry import bootstrap_otel
        with patch.dict(os.environ, {"AGT_SERVICE_NAME": "env-svc"}):
            result = bootstrap_otel()
            assert result is True

    def test_env_var_otel_service_name_priority(self):
        from agentmesh.telemetry import bootstrap_otel
        with patch.dict(os.environ, {
            "OTEL_SERVICE_NAME": "otel-svc",
            "AGT_SERVICE_NAME": "agt-svc",
        }):
            result = bootstrap_otel()
            assert result is True

    def test_explicit_param_overrides_env(self):
        from agentmesh.telemetry import bootstrap_otel
        with patch.dict(os.environ, {"AGT_SERVICE_NAME": "env-svc"}):
            result = bootstrap_otel(service_name="explicit-svc")
            assert result is True

    def test_resource_attributes_include_agent_did(self):
        from agentmesh.telemetry import bootstrap_otel
        with patch.dict(os.environ, {"AGT_AGENT_DID": "did:mesh:test123"}):
            result = bootstrap_otel()
            assert result is True

    def test_resource_attributes_include_sandbox_id(self):
        from agentmesh.telemetry import bootstrap_otel
        with patch.dict(os.environ, {"SANDBOX_ID": "sandbox-abc"}):
            result = bootstrap_otel()
            assert result is True

    def test_get_tracer_returns_tracer(self):
        from agentmesh.telemetry import bootstrap_otel, get_tracer
        bootstrap_otel(service_name="test")
        tracer = get_tracer("test-scope")
        assert tracer is not None

    def test_get_meter_returns_meter(self):
        from agentmesh.telemetry import bootstrap_otel, get_meter
        bootstrap_otel(service_name="test")
        meter = get_meter("test-scope")
        assert meter is not None

    def test_get_tracer_without_bootstrap_returns_noop(self):
        """If OTel is installed but not bootstrapped, still returns a tracer."""
        from agentmesh.telemetry import get_tracer
        tracer = get_tracer()
        assert tracer is not None

    def test_get_meter_without_bootstrap_returns_noop(self):
        from agentmesh.telemetry import get_meter
        meter = get_meter()
        assert meter is not None

    def test_bootstrap_with_http_protocol(self):
        from agentmesh.telemetry import bootstrap_otel
        # Should not raise even if http exporter is not installed
        result = bootstrap_otel(service_name="test", protocol="http")
        assert result is True

    def test_disable_tracing(self):
        from agentmesh.telemetry import bootstrap_otel
        result = bootstrap_otel(service_name="test", enable_tracing=False)
        assert result is True

    def test_disable_metrics(self):
        from agentmesh.telemetry import bootstrap_otel
        result = bootstrap_otel(service_name="test", enable_metrics=False)
        assert result is True


class TestNoOpFallbacks:
    """Tests for no-op fallback classes."""

    def test_noop_tracer_start_span(self):
        from agentmesh.telemetry import _NoOpTracer
        tracer = _NoOpTracer()
        span = tracer.start_span("test")
        span.set_attribute("key", "value")
        span.end()

    def test_noop_tracer_context_manager(self):
        from agentmesh.telemetry import _NoOpTracer
        tracer = _NoOpTracer()
        with tracer.start_as_current_span("test") as span:
            span.set_attribute("key", "value")

    def test_noop_meter_create_counter(self):
        from agentmesh.telemetry import _NoOpMeter
        meter = _NoOpMeter()
        counter = meter.create_counter("test_counter")
        counter.add(1)

    def test_noop_meter_create_histogram(self):
        from agentmesh.telemetry import _NoOpMeter
        meter = _NoOpMeter()
        hist = meter.create_histogram("test_hist")
        hist.record(42.0)

    def test_noop_meter_create_gauge(self):
        from agentmesh.telemetry import _NoOpMeter
        meter = _NoOpMeter()
        gauge = meter.create_gauge("test_gauge")
        gauge.set(100)


class TestMetricsEndpoint:
    """Tests for the /metrics Prometheus endpoint."""

    @pytest.fixture
    def client(self):
        """Create a test client for the base app."""
        from fastapi.testclient import TestClient
        from agentmesh.server import create_base_app
        app = create_base_app("test-component", "Test server")
        return TestClient(app)

    def test_metrics_returns_200(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200

    def test_metrics_content_type_prometheus(self, client):
        response = client.get("/metrics")
        assert "text/plain" in response.headers["content-type"]

    def test_metrics_contains_uptime(self, client):
        response = client.get("/metrics")
        assert "agt_uptime_seconds" in response.text

    def test_metrics_contains_component_label(self, client):
        response = client.get("/metrics")
        assert 'component="test-component"' in response.text

    def test_metrics_valid_prometheus_format(self, client):
        """Verify output has HELP and TYPE lines."""
        response = client.get("/metrics")
        text = response.text
        assert "# HELP" in text
        assert "# TYPE" in text

    def test_healthz(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_readyz(self, client):
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"


class TestMetricsWithGovernance:
    """Test that governance metrics appear in /metrics output."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from agentmesh.server import create_base_app
        app = create_base_app("governance", "Governance server")
        return TestClient(app)

    def test_governance_metrics_visible(self, client):
        """When GovernanceMetrics records data, it appears in /metrics."""
        from agentmesh.observability import GovernanceMetrics
        gm = GovernanceMetrics()
        if gm.enabled:
            gm.record_policy_evaluation("test-policy", "ALLOW", 1.5)
            response = client.get("/metrics")
            assert "agentmesh_governance_policy_evaluations_total" in response.text

    def test_mesh_metrics_visible(self, client):
        """MeshMetrics data appears in /metrics endpoint."""
        from agentmesh.observability import MeshMetrics
        mm = MeshMetrics()
        if mm.enabled:
            mm.record_handshake(0.05, "success")
            response = client.get("/metrics")
            assert "agentmesh_handshake_duration_seconds" in response.text
