# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the shared retry decorator."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_os.retry import retry


# ============================================================================
# Sync tests
# ============================================================================


class TestSyncRetry:
    """Tests for retry with synchronous functions."""

    def test_succeeds_first_try(self):
        """Function that succeeds immediately is called once."""
        call_count = 0

        @retry(max_attempts=3)
        def succeed():
            nonlocal call_count
            call_count += 1
            return "ok"

        assert succeed() == "ok"
        assert call_count == 1

    @patch("agent_os.retry.time.sleep")
    def test_succeeds_on_retry(self, mock_sleep):
        """Function that fails then succeeds is retried."""
        call_count = 0

        @retry(max_attempts=3, backoff_base=1.0, exceptions=(ValueError,))
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("boom")
            return "recovered"

        assert flaky() == "recovered"
        assert call_count == 3
        # Two retries → two sleeps
        assert mock_sleep.call_count == 2

    @patch("agent_os.retry.time.sleep")
    def test_exhausts_retries_and_raises(self, mock_sleep):
        """Function that always fails raises after max_attempts."""
        @retry(max_attempts=3, backoff_base=0.1, exceptions=(RuntimeError,))
        def always_fail():
            raise RuntimeError("permanent")

        with pytest.raises(RuntimeError, match="permanent"):
            always_fail()

        assert mock_sleep.call_count == 2  # 3 attempts → 2 sleeps

    def test_does_not_catch_unspecified_exceptions(self):
        """Exceptions not listed in *exceptions* propagate immediately."""
        call_count = 0

        @retry(max_attempts=3, exceptions=(ValueError,))
        def wrong_error():
            nonlocal call_count
            call_count += 1
            raise TypeError("not retried")

        with pytest.raises(TypeError, match="not retried"):
            wrong_error()

        assert call_count == 1  # no retry

    @patch("agent_os.retry.time.sleep")
    def test_on_retry_callback_called(self, mock_sleep):
        """The on_retry callback is invoked before each retry."""
        cb = MagicMock()
        call_count = 0

        @retry(max_attempts=3, exceptions=(ValueError,), on_retry=cb)
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("oops")
            return "ok"

        flaky()
        assert cb.call_count == 2
        # First callback: attempt=1, exc is ValueError
        assert cb.call_args_list[0][0][0] == 1
        assert isinstance(cb.call_args_list[0][0][1], ValueError)

    @patch("agent_os.retry.time.sleep")
    def test_backoff_increases_exponentially(self, mock_sleep):
        """Sleep durations double each retry with backoff_base=1.0."""
        @retry(max_attempts=4, backoff_base=1.0, exceptions=(IOError,))
        def always_fail():
            raise IOError("fail")

        with pytest.raises(IOError):
            always_fail()

        # 3 sleeps for 4 attempts: 1.0, 2.0, 4.0
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0, 4.0]

    @patch("agent_os.retry.time.sleep")
    def test_custom_backoff_base(self, mock_sleep):
        """Custom backoff_base scales the delay series."""
        @retry(max_attempts=3, backoff_base=0.5, exceptions=(IOError,))
        def always_fail():
            raise IOError("fail")

        with pytest.raises(IOError):
            always_fail()

        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [0.5, 1.0]

    def test_preserves_return_value(self):
        """Return value is passed through unchanged."""
        @retry(max_attempts=2)
        def returns_dict():
            return {"key": [1, 2, 3]}

        assert returns_dict() == {"key": [1, 2, 3]}

    def test_preserves_function_metadata(self):
        """functools.wraps preserves __name__ and __doc__."""
        @retry(max_attempts=2)
        def documented_func():
            """Important docstring."""
            return True

        assert documented_func.__name__ == "documented_func"
        assert documented_func.__doc__ == "Important docstring."


# ============================================================================
# Async tests
# ============================================================================


class TestAsyncRetry:
    """Tests for retry with async functions."""

    @pytest.mark.asyncio
    async def test_async_succeeds_first_try(self):
        """Async function that succeeds immediately is called once."""
        call_count = 0

        @retry(max_attempts=3)
        async def succeed():
            nonlocal call_count
            call_count += 1
            return "async_ok"

        result = await succeed()
        assert result == "async_ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_async_succeeds_on_retry(self):
        """Async function that fails then succeeds is retried."""
        call_count = 0

        @retry(max_attempts=3, backoff_base=0.01, exceptions=(ConnectionError,))
        async def flaky_async():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("transient")
            return "recovered"

        with patch("agent_os.retry.asyncio.sleep", new_callable=AsyncMock):
            result = await flaky_async()

        assert result == "recovered"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_async_exhausts_retries(self):
        """Async function that always fails raises after max_attempts."""
        @retry(max_attempts=2, backoff_base=0.01, exceptions=(TimeoutError,))
        async def always_fail_async():
            raise TimeoutError("timeout")

        with patch("agent_os.retry.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(TimeoutError, match="timeout"):
                await always_fail_async()

    @pytest.mark.asyncio
    async def test_async_preserves_metadata(self):
        """functools.wraps preserves __name__ for async functions."""
        @retry(max_attempts=2)
        async def async_documented():
            """Async docstring."""
            return True

        assert async_documented.__name__ == "async_documented"
        assert async_documented.__doc__ == "Async docstring."
