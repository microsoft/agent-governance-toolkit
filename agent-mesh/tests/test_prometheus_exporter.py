# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MeshMetricsExporter Prometheus integration."""

import importlib
import sys
from unittest.mock import patch

import pytest

from agentmesh.observability.prometheus_exporter import MeshMetricsExporter, start_http_server


@pytest.fixture(autouse=True)
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


class TestExporterCreation:
    """Verify metrics are created with correct names and types."""

    def test_enabled_when_prometheus_available(self):
        e = MeshMetricsExporter()
        assert e.enabled is True

    def test_trust_handshakes_total_is_counter(self):
        from prometheus_client import Counter

        e = MeshMetricsExporter()
        assert isinstance(e.trust_handshakes_total, Counter)

    def test_trust_score_is_gauge(self):
        from prometheus_client import Gauge

        e = MeshMetricsExporter()
        assert isinstance(e.trust_score, Gauge)

    def test_policy_violations_total_is_counter(self):
        from prometheus_client import Counter

        e = MeshMetricsExporter()
        assert isinstance(e.policy_violations_total, Counter)

    def test_active_agents_is_gauge(self):
        from prometheus_client import Gauge

        e = MeshMetricsExporter()
        assert isinstance(e.active_agents, Gauge)

    def test_handshake_latency_is_histogram(self):
        from prometheus_client import Histogram

        e = MeshMetricsExporter()
        assert isinstance(e.handshake_latency_seconds, Histogram)

    def test_delegation_depth_is_histogram(self):
        from prometheus_client import Histogram

        e = MeshMetricsExporter()
        assert isinstance(e.delegation_depth, Histogram)

    def test_audit_entries_total_is_counter(self):
        from prometheus_client import Counter

        e = MeshMetricsExporter()
        assert isinstance(e.audit_entries_total, Counter)


class TestRecordHandshake:
    """Verify record_handshake updates histogram and counter."""

    def test_record_handshake_success(self):
        e = MeshMetricsExporter()
        e.record_handshake(0.25, "success")

        assert e.handshake_latency_seconds._sum.get() == 0.25
        assert e.trust_handshakes_total.labels(result="success")._value.get() == 1.0

    def test_record_handshake_failure(self):
        e = MeshMetricsExporter()
        e.record_handshake(1.5, "failure")

        assert e.trust_handshakes_total.labels(result="failure")._value.get() == 1.0


class TestTrustScoreGauge:
    """Verify update_trust_score sets gauge correctly."""

    def test_set_trust_score(self):
        e = MeshMetricsExporter()
        e.update_trust_score("did:mesh:abc123", 0.85)

        assert e.trust_score.labels(agent_did="did:mesh:abc123")._value.get() == 0.85

    def test_update_trust_score_overwrites(self):
        e = MeshMetricsExporter()
        e.update_trust_score("did:mesh:abc123", 0.5)
        e.update_trust_score("did:mesh:abc123", 0.9)

        assert e.trust_score.labels(agent_did="did:mesh:abc123")._value.get() == 0.9


class TestPolicyViolations:
    """Verify record_policy_violation increments counter."""

    def test_increment_violation(self):
        e = MeshMetricsExporter()
        e.record_policy_violation("no-external-calls")
        e.record_policy_violation("no-external-calls")

        assert (
            e.policy_violations_total.labels(policy_id="no-external-calls")._value.get() == 2.0
        )

    def test_separate_policies(self):
        e = MeshMetricsExporter()
        e.record_policy_violation("no-external-calls")
        e.record_policy_violation("max-delegation-depth")

        assert (
            e.policy_violations_total.labels(policy_id="no-external-calls")._value.get() == 1.0
        )
        assert (
            e.policy_violations_total.labels(policy_id="max-delegation-depth")._value.get() == 1.0
        )


class TestActiveAgents:
    """Verify set_active_agents sets gauge."""

    def test_set_active_agents(self):
        e = MeshMetricsExporter()
        e.set_active_agents(42)

        assert e.active_agents._value.get() == 42.0


class TestDelegationAndAudit:
    """Verify delegation and audit recording."""

    def test_record_delegation(self):
        e = MeshMetricsExporter()
        e.record_delegation(3)

        assert e.delegation_depth._sum.get() == 3.0

    def test_record_audit_entry(self):
        e = MeshMetricsExporter()
        e.record_audit_entry("handshake")
        e.record_audit_entry("handshake")
        e.record_audit_entry("policy_check")

        assert e.audit_entries_total.labels(event_type="handshake")._value.get() == 2.0
        assert e.audit_entries_total.labels(event_type="policy_check")._value.get() == 1.0


class TestGracefulWithoutPrometheus:
    """Verify MeshMetricsExporter degrades gracefully without prometheus_client."""

    def test_disabled_when_import_fails(self):
        with patch.dict(sys.modules, {"prometheus_client": None}):
            mod = importlib.import_module("agentmesh.observability.prometheus_exporter")
            importlib.reload(mod)
            e = mod.MeshMetricsExporter()

            assert e.enabled is False
            # All recording methods should be no-ops
            e.record_handshake(0.1, "success")
            e.update_trust_score("did:mesh:x", 0.5)
            e.record_policy_violation("p1")
            e.set_active_agents(10)
            e.record_delegation(2)
            e.record_audit_entry("test")

    def test_start_http_server_noop_without_prometheus(self):
        with patch.dict(sys.modules, {"prometheus_client": None}):
            mod = importlib.import_module("agentmesh.observability.prometheus_exporter")
            importlib.reload(mod)
            # Should not raise
            mod.start_http_server(port=19090)
