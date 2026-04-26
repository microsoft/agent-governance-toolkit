# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the governance metrics collector."""

import threading

import pytest

from agent_os.metrics import GovernanceMetrics


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def m() -> GovernanceMetrics:
    return GovernanceMetrics()


# ── 1. Initial state ─────────────────────────────────────────


def test_initial_state(m: GovernanceMetrics) -> None:
    assert m.total_checks == 0
    assert m.violations == 0
    assert m.approvals == 0
    assert m.blocked == 0
    assert m.avg_latency_ms == 0.0


# ── 2. record_check increments totals ────────────────────────


def test_record_check_approved(m: GovernanceMetrics) -> None:
    m.record_check("langchain", latency_ms=1.0, approved=True)
    assert m.total_checks == 1
    assert m.approvals == 1
    assert m.violations == 0


def test_record_check_denied(m: GovernanceMetrics) -> None:
    m.record_check("crewai", latency_ms=2.0, approved=False)
    assert m.total_checks == 1
    assert m.approvals == 0
    assert m.violations == 1


# ── 3. record_violation increments violations ────────────────


def test_record_violation(m: GovernanceMetrics) -> None:
    m.record_violation("langchain")
    assert m.violations == 1
    m.record_violation("langchain")
    assert m.violations == 2


# ── 4. record_blocked increments blocked ─────────────────────


def test_record_blocked(m: GovernanceMetrics) -> None:
    m.record_blocked("crewai")
    assert m.blocked == 1
    m.record_blocked("crewai")
    assert m.blocked == 2


# ── 5. Average latency calculation ───────────────────────────


def test_avg_latency(m: GovernanceMetrics) -> None:
    m.record_check("a", latency_ms=2.0, approved=True)
    m.record_check("a", latency_ms=4.0, approved=True)
    m.record_check("a", latency_ms=6.0, approved=True)
    assert m.avg_latency_ms == pytest.approx(4.0)


# ── 6. Per-adapter tracking ──────────────────────────────────


def test_per_adapter_tracking(m: GovernanceMetrics) -> None:
    m.record_check("langchain", latency_ms=1.0, approved=True)
    m.record_check("crewai", latency_ms=2.0, approved=False)
    m.record_violation("crewai")
    m.record_blocked("langchain")

    snap = m.snapshot()
    assert snap["adapters"]["langchain"]["checks"] == 1
    assert snap["adapters"]["langchain"]["violations"] == 0
    assert snap["adapters"]["langchain"]["blocked"] == 1
    assert snap["adapters"]["crewai"]["checks"] == 1
    assert snap["adapters"]["crewai"]["violations"] == 2
    assert snap["adapters"]["crewai"]["blocked"] == 0


# ── 7. snapshot returns correct dict ─────────────────────────


def test_snapshot(m: GovernanceMetrics) -> None:
    m.record_check("langchain", latency_ms=3.0, approved=True)
    m.record_check("langchain", latency_ms=5.0, approved=False)
    m.record_blocked("langchain")

    snap = m.snapshot()
    assert snap["total_checks"] == 2
    assert snap["approvals"] == 1
    assert snap["violations"] == 1
    assert snap["blocked"] == 1
    assert snap["avg_latency_ms"] == pytest.approx(4.0)
    assert "langchain" in snap["adapters"]


# ── 8. reset clears all counters ─────────────────────────────


def test_reset(m: GovernanceMetrics) -> None:
    m.record_check("langchain", latency_ms=5.0, approved=True)
    m.record_violation("crewai")
    m.record_blocked("crewai")
    m.reset()

    assert m.total_checks == 0
    assert m.violations == 0
    assert m.approvals == 0
    assert m.blocked == 0
    assert m.avg_latency_ms == 0.0
    assert m.snapshot()["adapters"] == {}


# ── 9. Thread safety ─────────────────────────────────────────


def test_thread_safety(m: GovernanceMetrics) -> None:
    n = 1000
    errors: list = []

    def worker() -> None:
        try:
            for _ in range(n):
                m.record_check("adapter", latency_ms=1.0, approved=True)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert m.total_checks == 4 * n
    assert m.approvals == 4 * n


# ── 10. Multiple adapters tracked independently ──────────────


def test_multiple_adapters_independent(m: GovernanceMetrics) -> None:
    m.record_check("langchain", latency_ms=1.0, approved=True)
    m.record_check("langchain", latency_ms=1.0, approved=True)
    m.record_check("crewai", latency_ms=2.0, approved=False)
    m.record_violation("autogen")
    m.record_blocked("crewai")

    snap = m.snapshot()
    assert snap["adapters"]["langchain"] == {"checks": 2, "violations": 0, "blocked": 0}
    assert snap["adapters"]["crewai"] == {"checks": 1, "violations": 1, "blocked": 1}
    assert snap["adapters"]["autogen"] == {"checks": 0, "violations": 1, "blocked": 0}
    assert m.total_checks == 3
    assert m.approvals == 2
    assert m.violations == 2
    assert m.blocked == 1
