# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MeshMetrics Prometheus integration."""

import importlib
import sys
from unittest.mock import patch

import pytest

from agentmesh.observability.metrics import MeshMetrics


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


class TestMeshMetricsCreation:
    """Verify metrics are created with correct names and types."""

    def test_metrics_enabled_when_prometheus_available(self):
        m = MeshMetrics()
        assert m.enabled is True

    def test_handshake_duration_is_histogram(self):
        from prometheus_client import Histogram

        m = MeshMetrics()
        assert isinstance(m.handshake_duration, Histogram)

    def test_trust_score_is_gauge(self):
        from prometheus_client import Gauge

        m = MeshMetrics()
        assert isinstance(m.trust_score, Gauge)

    def test_active_agents_is_gauge(self):
        from prometheus_client import Gauge

        m = MeshMetrics()
        assert isinstance(m.active_agents, Gauge)

    def test_scope_chain_depth_is_histogram(self):
        from prometheus_client import Histogram

        m = MeshMetrics()
        assert isinstance(m.scope_chain_depth, Histogram)

    def test_failed_verifications_is_counter(self):
        from prometheus_client import Counter

        m = MeshMetrics()
        assert isinstance(m.failed_verifications, Counter)

    def test_handshakes_total_is_counter(self):
        from prometheus_client import Counter

        m = MeshMetrics()
        assert isinstance(m.handshakes_total, Counter)

    def test_policy_evaluations_is_counter(self):
        from prometheus_client import Counter

        m = MeshMetrics()
        assert isinstance(m.policy_evaluations, Counter)


class TestRecordHandshake:
    """Verify record_handshake updates histogram and counter."""

    def test_record_handshake_success(self):
        m = MeshMetrics()
        m.record_handshake(0.25, "success")

        assert m.handshake_duration._sum.get() == 0.25
        assert m.handshakes_total.labels(result="success")._value.get() == 1.0

    def test_record_handshake_failure(self):
        m = MeshMetrics()
        m.record_handshake(1.5, "failure")

        assert m.handshakes_total.labels(result="failure")._value.get() == 1.0


class TestTrustScoreGauge:
    """Verify update_trust_score sets gauge correctly."""

    def test_set_trust_score(self):
        m = MeshMetrics()
        m.update_trust_score("did:mesh:abc123", 0.85)

        assert m.trust_score.labels(agent_did="did:mesh:abc123")._value.get() == 0.85

    def test_update_trust_score_overwrites(self):
        m = MeshMetrics()
        m.update_trust_score("did:mesh:abc123", 0.5)
        m.update_trust_score("did:mesh:abc123", 0.9)

        assert m.trust_score.labels(agent_did="did:mesh:abc123")._value.get() == 0.9


class TestFailureCounter:
    """Verify record_verification_failure increments counter."""

    def test_increment_failure(self):
        m = MeshMetrics()
        m.record_verification_failure("expired_cert")
        m.record_verification_failure("expired_cert")

        assert m.failed_verifications.labels(reason="expired_cert")._value.get() == 2.0

    def test_separate_reasons(self):
        m = MeshMetrics()
        m.record_verification_failure("expired_cert")
        m.record_verification_failure("bad_signature")

        assert m.failed_verifications.labels(reason="expired_cert")._value.get() == 1.0
        assert m.failed_verifications.labels(reason="bad_signature")._value.get() == 1.0


class TestDelegationAndPolicy:
    """Verify delegation and policy recording."""

    def test_record_delegation(self):
        m = MeshMetrics()
        m.record_delegation(3)

        assert m.scope_chain_depth._sum.get() == 3.0

    def test_record_policy_evaluation(self):
        m = MeshMetrics()
        m.record_policy_evaluation("allow")
        m.record_policy_evaluation("deny")
        m.record_policy_evaluation("allow")

        assert m.policy_evaluations.labels(decision="allow")._value.get() == 2.0
        assert m.policy_evaluations.labels(decision="deny")._value.get() == 1.0

    def test_set_active_agents(self):
        m = MeshMetrics()
        m.set_active_agents(42)

        assert m.active_agents._value.get() == 42.0


class TestGracefulWithoutPrometheus:
    """Verify MeshMetrics degrades gracefully without prometheus_client."""

    def test_disabled_when_import_fails(self):
        with patch.dict(sys.modules, {"prometheus_client": None}):
            # Re-import to trigger ImportError path
            mod = importlib.import_module("agentmesh.observability.metrics")
            importlib.reload(mod)
            m = mod.MeshMetrics()

            assert m.enabled is False
            # All recording methods should be no-ops
            m.record_handshake(0.1, "success")
            m.update_trust_score("did:mesh:x", 0.5)
            m.record_verification_failure("reason")
            m.record_delegation(2)
            m.record_policy_evaluation("allow")
            m.set_active_agents(10)
