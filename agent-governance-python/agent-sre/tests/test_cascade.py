# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for cascading failure circuit breakers (OWASP ASI08)."""

from __future__ import annotations

import asyncio
import time

import pytest

from agent_sre.cascade import (
    CascadeDetector,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitOpenError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _succeed() -> str:
    return "ok"


def _fail() -> str:
    raise RuntimeError("boom")


# ---------------------------------------------------------------------------
# CircuitBreaker — state transitions
# ---------------------------------------------------------------------------


class TestCircuitBreakerStates:
    def test_initial_state_is_closed(self) -> None:
        cb = CircuitBreaker("agent-a")
        assert cb.state == "CLOSED"

    def test_transitions_to_open_after_threshold(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("agent-a", cfg)

        for _ in range(3):
            cb.record_failure()

        assert cb.state == "OPEN"

    def test_stays_closed_below_threshold(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=5)
        cb = CircuitBreaker("agent-a", cfg)

        for _ in range(4):
            cb.record_failure()

        assert cb.state == "CLOSED"

    def test_transitions_to_half_open_after_timeout(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=0.1)
        cb = CircuitBreaker("agent-a", cfg)

        cb.record_failure()
        cb.record_failure()
        assert cb.state == "OPEN"

        time.sleep(0.15)
        assert cb.state == "HALF_OPEN"

    def test_half_open_success_closes_circuit(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=0.1)
        cb = CircuitBreaker("agent-a", cfg)

        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        assert cb.state == "HALF_OPEN"

        cb.record_success()
        assert cb.state == "CLOSED"

    def test_half_open_failure_reopens_circuit(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=0.1)
        cb = CircuitBreaker("agent-a", cfg)

        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        assert cb.state == "HALF_OPEN"

        cb.record_failure()
        assert cb.state == "OPEN"


# ---------------------------------------------------------------------------
# CircuitBreaker — call wrapping
# ---------------------------------------------------------------------------


class TestCircuitBreakerCall:
    def test_successful_call(self) -> None:
        cb = CircuitBreaker("agent-a")
        result = cb.call(_succeed)
        assert result == "ok"

    def test_failed_call_counts_failure(self) -> None:
        cb = CircuitBreaker("agent-a")
        with pytest.raises(RuntimeError):
            cb.call(_fail)
        assert cb.failure_count == 1

    def test_open_circuit_raises(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker("agent-a", cfg)
        cb.record_failure()
        cb.record_failure()

        with pytest.raises(CircuitOpenError) as exc_info:
            cb.call(_succeed)
        assert exc_info.value.agent_id == "agent-a"

    def test_open_circuit_returns_fallback(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker("agent-a", cfg)
        cb.record_failure()
        cb.record_failure()

        result = cb.call(_succeed, fallback={"status": "degraded"})
        assert result == {"status": "degraded"}

    def test_half_open_limits_calls(self) -> None:
        cfg = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout_seconds=0.1,
            half_open_max_calls=1,
        )
        cb = CircuitBreaker("agent-a", cfg)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)

        # First call in HALF_OPEN should go through.
        result = cb.call(_succeed)
        assert result == "ok"

        # Circuit should now be CLOSED after success.
        assert cb.state == "CLOSED"

    def test_cancelled_half_open_probe_frees_its_slot(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=1, recovery_timeout_seconds=0.0)
        cb = CircuitBreaker("agent-a", cfg)
        cb.record_failure()
        assert cb.state == "HALF_OPEN"

        async def _hang() -> None:
            await asyncio.sleep(10)

        async def _ok() -> str:
            return "ok"

        async def scenario() -> str:
            probe = asyncio.ensure_future(cb.call(_hang))
            await asyncio.sleep(0)
            probe.cancel()
            with pytest.raises(asyncio.CancelledError):
                await probe
            # Cancellation is neither a success nor a failure.
            assert cb.state == "HALF_OPEN"
            return await cb.call(_ok)

        assert asyncio.run(scenario()) == "ok"
        assert cb.state == "CLOSED"

    def test_interrupted_sync_half_open_probe_frees_its_slot(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=1, recovery_timeout_seconds=0.0)
        cb = CircuitBreaker("agent-a", cfg)
        cb.record_failure()

        def _interrupt() -> None:
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            cb.call(_interrupt)
        assert cb.state == "HALF_OPEN"
        assert cb.call(_succeed) == "ok"
        assert cb.state == "CLOSED"

    def test_stale_probe_does_not_free_a_later_half_open_slot(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=1, recovery_timeout_seconds=0.0)
        cb = CircuitBreaker("agent-a", cfg)
        cb.record_failure()

        async def _hang() -> None:
            await asyncio.sleep(10)

        async def scenario() -> None:
            stale = asyncio.ensure_future(cb.call(_hang))
            await asyncio.sleep(0)
            # Another caller reports a failure, and the next HALF_OPEN period
            # hands its only slot to a new probe.
            cb.record_failure()
            current = asyncio.ensure_future(cb.call(_hang))
            await asyncio.sleep(0)
            stale.cancel()
            with pytest.raises(asyncio.CancelledError):
                await stale
            # The slot belongs to the in-flight probe, so a third call is rejected.
            with pytest.raises(CircuitOpenError):
                cb.call(_succeed)
            current.cancel()
            with pytest.raises(asyncio.CancelledError):
                await current

        asyncio.run(scenario())


# ---------------------------------------------------------------------------
# CircuitBreaker — reset
# ---------------------------------------------------------------------------


class TestCircuitBreakerReset:
    def test_reset_clears_state(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker("agent-a", cfg)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "OPEN"

        cb.reset()
        assert cb.state == "CLOSED"
        assert cb.failure_count == 0

    def test_reset_allows_calls_again(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker("agent-a", cfg)
        cb.record_failure()
        cb.record_failure()

        cb.reset()
        result = cb.call(_succeed)
        assert result == "ok"


# ---------------------------------------------------------------------------
# CascadeDetector
# ---------------------------------------------------------------------------


class TestCascadeDetector:
    def test_no_cascade_when_all_healthy(self) -> None:
        detector = CascadeDetector(["a", "b", "c", "d"], cascade_threshold=3)
        assert detector.check_cascade() is False
        assert detector.get_affected_agents() == []

    def test_cascade_detected_when_threshold_met(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2)
        detector = CascadeDetector(["a", "b", "c", "d"], cascade_threshold=3, config=cfg)

        for agent_id in ["a", "b", "c"]:
            breaker = detector.get_breaker(agent_id)
            breaker.record_failure()
            breaker.record_failure()

        assert detector.check_cascade() is True
        assert sorted(detector.get_affected_agents()) == ["a", "b", "c"]

    def test_no_cascade_below_threshold(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2)
        detector = CascadeDetector(["a", "b", "c", "d"], cascade_threshold=3, config=cfg)

        for agent_id in ["a", "b"]:
            breaker = detector.get_breaker(agent_id)
            breaker.record_failure()
            breaker.record_failure()

        assert detector.check_cascade() is False
        assert sorted(detector.get_affected_agents()) == ["a", "b"]

    def test_reset_all_clears_cascade(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2)
        detector = CascadeDetector(["a", "b", "c"], cascade_threshold=2, config=cfg)

        for agent_id in ["a", "b"]:
            breaker = detector.get_breaker(agent_id)
            breaker.record_failure()
            breaker.record_failure()

        assert detector.check_cascade() is True

        detector.reset_all()
        assert detector.check_cascade() is False
        assert detector.get_affected_agents() == []

    def test_recovery_removes_agent_from_affected(self) -> None:
        cfg = CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=0.1)
        detector = CascadeDetector(["a", "b", "c"], cascade_threshold=2, config=cfg)

        for agent_id in ["a", "b"]:
            breaker = detector.get_breaker(agent_id)
            breaker.record_failure()
            breaker.record_failure()

        assert detector.check_cascade() is True

        # Wait for recovery timeout, then succeed on agent "a".
        time.sleep(0.15)
        detector.get_breaker("a").record_success()

        assert "a" not in detector.get_affected_agents()
