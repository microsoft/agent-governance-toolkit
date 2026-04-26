# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for CircuitBreaker state transitions and call protection."""

import pytest
from unittest.mock import AsyncMock

from agent_os.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpen,
    CircuitState,
)


class TestCircuitBreakerStates:
    """Test circuit breaker state transitions."""

    def test_initial_state_is_closed(self):
        cb = CircuitBreaker()
        assert cb.get_state() is CircuitState.CLOSED

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))
        cb.record_failure()
        cb.record_failure()
        assert cb.get_state() is CircuitState.CLOSED

    def test_opens_at_threshold(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))
        for _ in range(3):
            cb.record_failure()
        assert cb.get_state() is CircuitState.OPEN

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb._failure_count == 0
        assert cb.get_state() is CircuitState.CLOSED

    def test_half_open_on_timeout(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1, reset_timeout_seconds=0))
        cb.record_failure()
        # With reset_timeout_seconds=0, get_state() transitions immediately to HALF_OPEN
        assert cb.get_state() is CircuitState.HALF_OPEN

    def test_half_open_success_closes(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1, reset_timeout_seconds=0))
        cb.record_failure()
        # Force transition to HALF_OPEN
        _ = cb.get_state()
        cb.record_success()
        assert cb.get_state() is CircuitState.CLOSED

    def test_half_open_failure_reopens(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1, reset_timeout_seconds=0))
        cb.record_failure()
        _ = cb.get_state()  # HALF_OPEN
        cb.record_failure()
        assert cb._state is CircuitState.OPEN

    def test_reset(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1))
        cb.record_failure()
        assert cb.get_state() is CircuitState.OPEN
        cb.reset()
        assert cb.get_state() is CircuitState.CLOSED


class TestCircuitBreakerCall:
    """Test the async call() wrapper."""

    @pytest.mark.asyncio
    async def test_call_success(self):
        cb = CircuitBreaker()
        func = AsyncMock(return_value="ok")
        result = await cb.call(func, "arg1", key="val")
        func.assert_awaited_once_with("arg1", key="val")
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_call_propagates_exception_and_records_failure(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=2))
        func = AsyncMock(side_effect=RuntimeError("boom"))

        with pytest.raises(RuntimeError, match="boom"):
            await cb.call(func)
        assert cb._failure_count == 1

    @pytest.mark.asyncio
    async def test_call_rejects_when_open(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1, reset_timeout_seconds=60))
        cb.record_failure()
        assert cb.get_state() is CircuitState.OPEN

        with pytest.raises(CircuitBreakerOpen):
            await cb.call(AsyncMock())

    @pytest.mark.asyncio
    async def test_call_allows_half_open_then_closes(self):
        cb = CircuitBreaker(
            CircuitBreakerConfig(
                failure_threshold=1, reset_timeout_seconds=0, half_open_max_calls=1
            )
        )
        cb.record_failure()
        # Transitions to HALF_OPEN because timeout is 0
        assert cb.get_state() is CircuitState.HALF_OPEN

        func = AsyncMock(return_value="recovered")
        result = await cb.call(func)
        assert result == "recovered"
        assert cb.get_state() is CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_half_open_rejects_excess_calls(self):
        cb = CircuitBreaker(
            CircuitBreakerConfig(
                failure_threshold=1, reset_timeout_seconds=0, half_open_max_calls=1
            )
        )
        cb.record_failure()
        _ = cb.get_state()  # HALF_OPEN
        cb._half_open_calls = 1  # simulate one call already made

        with pytest.raises(CircuitBreakerOpen):
            await cb.call(AsyncMock())
