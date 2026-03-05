# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for HealthChecker.

Run with: python -m pytest tests/test_health.py -v --tb=short
"""

import json
import threading
import time

import pytest

from agent_os.integrations.health import (
    ComponentHealth,
    HealthChecker,
    HealthReport,
    HealthStatus,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def checker():
    return HealthChecker(version="1.3.1")


@pytest.fixture
def checker_with_checks(checker):
    checker.register_check("policy_engine", checker._check_policy_engine)
    checker.register_check("audit_backend", checker._check_audit_backend)
    return checker


# =============================================================================
# HealthStatus enum
# =============================================================================


class TestHealthStatus:
    def test_values(self):
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"


# =============================================================================
# ComponentHealth
# =============================================================================


class TestComponentHealth:
    def test_frozen(self):
        comp = ComponentHealth(name="db", status=HealthStatus.HEALTHY)
        with pytest.raises(AttributeError):
            comp.name = "other"

    def test_defaults(self):
        comp = ComponentHealth(name="db", status=HealthStatus.HEALTHY)
        assert comp.message == ""
        assert comp.latency_ms == 0.0


# =============================================================================
# HealthReport
# =============================================================================


class TestHealthReport:
    def _make_report(self, status=HealthStatus.HEALTHY):
        return HealthReport(
            status=status,
            components={
                "a": ComponentHealth(
                    name="a", status=HealthStatus.HEALTHY, message="ok", latency_ms=1.5
                )
            },
            timestamp="2025-01-01T00:00:00Z",
            version="1.0.0",
            uptime_seconds=42.0,
        )

    def test_to_dict_is_json_serializable(self):
        report = self._make_report()
        d = report.to_dict()
        serialized = json.dumps(d)
        assert isinstance(serialized, str)

    def test_to_dict_fields(self):
        report = self._make_report()
        d = report.to_dict()
        assert d["status"] == "healthy"
        assert d["version"] == "1.0.0"
        assert d["uptime_seconds"] == 42.0
        assert "a" in d["components"]
        assert d["components"]["a"]["latency_ms"] == 1.5

    def test_is_healthy(self):
        assert self._make_report(HealthStatus.HEALTHY).is_healthy() is True
        assert self._make_report(HealthStatus.DEGRADED).is_healthy() is False
        assert self._make_report(HealthStatus.UNHEALTHY).is_healthy() is False

    def test_is_ready(self):
        assert self._make_report(HealthStatus.HEALTHY).is_ready() is True
        assert self._make_report(HealthStatus.DEGRADED).is_ready() is True
        assert self._make_report(HealthStatus.UNHEALTHY).is_ready() is False


# =============================================================================
# HealthChecker — registration
# =============================================================================


class TestRegisterCheck:
    def test_register_and_run(self, checker):
        checker.register_check(
            "dummy",
            lambda: ComponentHealth(name="dummy", status=HealthStatus.HEALTHY),
        )
        report = checker.check_health()
        assert "dummy" in report.components
        assert report.is_healthy()

    def test_overwrite_check(self, checker):
        checker.register_check(
            "x",
            lambda: ComponentHealth(name="x", status=HealthStatus.HEALTHY),
        )
        checker.register_check(
            "x",
            lambda: ComponentHealth(name="x", status=HealthStatus.DEGRADED),
        )
        report = checker.check_health()
        assert report.components["x"].status == HealthStatus.DEGRADED


# =============================================================================
# HealthChecker — probes
# =============================================================================


class TestCheckHealth:
    def test_no_checks_is_healthy(self, checker):
        report = checker.check_health()
        assert report.is_healthy()
        assert report.components == {}

    def test_all_healthy(self, checker_with_checks):
        report = checker_with_checks.check_health()
        assert report.is_healthy()
        assert len(report.components) == 2

    def test_degraded_aggregation(self, checker):
        checker.register_check(
            "ok",
            lambda: ComponentHealth(name="ok", status=HealthStatus.HEALTHY),
        )
        checker.register_check(
            "slow",
            lambda: ComponentHealth(
                name="slow", status=HealthStatus.DEGRADED, message="high latency"
            ),
        )
        report = checker.check_health()
        assert report.status == HealthStatus.DEGRADED
        assert report.is_ready()

    def test_unhealthy_aggregation(self, checker):
        checker.register_check(
            "ok",
            lambda: ComponentHealth(name="ok", status=HealthStatus.HEALTHY),
        )
        checker.register_check(
            "broken",
            lambda: ComponentHealth(
                name="broken", status=HealthStatus.UNHEALTHY, message="down"
            ),
        )
        report = checker.check_health()
        assert report.status == HealthStatus.UNHEALTHY
        assert not report.is_ready()

    def test_exception_becomes_unhealthy(self, checker):
        def boom():
            raise RuntimeError("kaboom")

        checker.register_check("bad", boom)
        report = checker.check_health()
        assert report.status == HealthStatus.UNHEALTHY
        assert "kaboom" in report.components["bad"].message

    def test_report_contains_version(self, checker):
        report = checker.check_health()
        assert report.version == "1.3.1"

    def test_uptime_positive(self, checker):
        report = checker.check_health()
        assert report.uptime_seconds >= 0.0

    def test_timestamp_format(self, checker):
        report = checker.check_health()
        assert report.timestamp.endswith("Z")


class TestCheckReady:
    def test_ready_delegates_to_check_health(self, checker_with_checks):
        report = checker_with_checks.check_ready()
        assert report.is_ready()
        assert len(report.components) == 2


class TestCheckLive:
    def test_liveness_always_healthy(self, checker):
        report = checker.check_live()
        assert report.is_healthy()
        assert "process" in report.components


# =============================================================================
# Built-in checks
# =============================================================================


class TestBuiltInChecks:
    def test_policy_engine_check(self, checker):
        result = checker._check_policy_engine()
        assert result.status == HealthStatus.HEALTHY
        assert result.name == "policy_engine"

    def test_audit_backend_check(self, checker):
        result = checker._check_audit_backend()
        assert result.status == HealthStatus.HEALTHY


# =============================================================================
# Thread safety
# =============================================================================


class TestThreadSafety:
    def test_concurrent_registration_and_check(self, checker):
        errors = []

        def register_many(start):
            try:
                for i in range(50):
                    name = f"comp-{start}-{i}"
                    checker.register_check(
                        name,
                        lambda n=name: ComponentHealth(
                            name=n, status=HealthStatus.HEALTHY
                        ),
                    )
            except Exception as exc:
                errors.append(exc)

        def check_many():
            try:
                for _ in range(20):
                    checker.check_health()
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=register_many, args=(0,)),
            threading.Thread(target=register_many, args=(1,)),
            threading.Thread(target=check_many),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# =============================================================================
# Latency measurement
# =============================================================================


class TestLatency:
    def test_latency_measured_for_check(self, checker):
        def slow_check():
            time.sleep(0.05)
            return ComponentHealth(name="slow", status=HealthStatus.HEALTHY)

        checker.register_check("slow", slow_check)
        report = checker.check_health()
        assert report.components["slow"].latency_ms >= 40.0

    def test_explicit_latency_preserved(self, checker):
        checker.register_check(
            "fast",
            lambda: ComponentHealth(
                name="fast", status=HealthStatus.HEALTHY, latency_ms=99.0
            ),
        )
        report = checker.check_health()
        assert report.components["fast"].latency_ms == 99.0
