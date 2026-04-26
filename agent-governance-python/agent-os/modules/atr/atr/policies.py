# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy definitions for tool execution control.

Provides retry policies, rate limiting, and other execution policies.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, TypeVar, Union


class BackoffStrategy(str, Enum):
    """Backoff strategies for retry policies."""

    CONSTANT = "constant"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    FIBONACCI = "fibonacci"


@dataclass
class RetryPolicy:
    """Configuration for retry behavior.

    Attributes:
        max_attempts: Maximum number of retry attempts (including initial).
        backoff: Backoff strategy between retries.
        initial_delay: Initial delay in seconds before first retry.
        max_delay: Maximum delay in seconds between retries.
        jitter: Whether to add random jitter to delays.
        retry_on: Exception types to retry on. None means retry on all exceptions.
        on_retry: Optional callback called on each retry with (attempt, exception, delay).

    Example:
        >>> policy = RetryPolicy(
        ...     max_attempts=3,
        ...     backoff=BackoffStrategy.EXPONENTIAL,
        ...     initial_delay=1.0,
        ...     max_delay=30.0
        ... )
    """

    max_attempts: int = 3
    backoff: Union[BackoffStrategy, str] = BackoffStrategy.EXPONENTIAL
    initial_delay: float = 1.0
    max_delay: float = 60.0
    jitter: bool = True
    retry_on: Optional[tuple] = None
    on_retry: Optional[Callable[[int, Exception, float], None]] = None

    def __post_init__(self):
        """Convert string backoff to enum."""
        if isinstance(self.backoff, str):
            self.backoff = BackoffStrategy(self.backoff.lower())

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay before the given attempt.

        Args:
            attempt: The attempt number (1-indexed).

        Returns:
            Delay in seconds.
        """
        if attempt <= 1:
            return 0

        retry_number = attempt - 1  # 0-indexed for calculation

        if self.backoff == BackoffStrategy.CONSTANT:
            delay = self.initial_delay
        elif self.backoff == BackoffStrategy.LINEAR:
            delay = self.initial_delay * retry_number
        elif self.backoff == BackoffStrategy.EXPONENTIAL:
            delay = self.initial_delay * (2 ** (retry_number - 1))
        elif self.backoff == BackoffStrategy.FIBONACCI:
            delay = self.initial_delay * self._fibonacci(retry_number)
        else:
            delay = self.initial_delay

        # Apply max delay cap
        delay = min(delay, self.max_delay)

        # Add jitter if enabled (±25%)
        if self.jitter:
            import random

            jitter_range = delay * 0.25
            delay += random.uniform(-jitter_range, jitter_range)
            delay = max(0, delay)

        return delay

    @staticmethod
    def _fibonacci(n: int) -> int:
        """Calculate nth Fibonacci number."""
        if n <= 1:
            return 1
        a, b = 1, 1
        for _ in range(n - 1):
            a, b = b, a + b
        return b

    def should_retry(self, exception: Exception) -> bool:
        """Check if we should retry on this exception.

        Args:
            exception: The exception that occurred.

        Returns:
            True if should retry, False otherwise.
        """
        if self.retry_on is None:
            return True
        return isinstance(exception, self.retry_on)


@dataclass
class RateLimitPolicy:
    """Configuration for rate limiting.

    Supports various rate limiting formats:
    - "10/minute" - 10 calls per minute
    - "100/hour" - 100 calls per hour
    - "5/second" - 5 calls per second

    Attributes:
        limit: Maximum number of calls allowed.
        period: Time period in seconds.
        burst: Optional burst allowance above the limit.
        on_limited: Optional callback when rate limited.

    Example:
        >>> policy = RateLimitPolicy.from_string("10/minute")
        >>> # or
        >>> policy = RateLimitPolicy(limit=10, period=60)
    """

    limit: int
    period: float  # in seconds
    burst: Optional[int] = None
    on_limited: Optional[Callable[[], None]] = None

    _calls: deque = field(default_factory=deque, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def from_string(cls, rate_string: str) -> "RateLimitPolicy":
        """Parse a rate limit string like '10/minute'.

        Args:
            rate_string: String in format 'N/period' where period is
                        'second', 'minute', 'hour', or 'day'.

        Returns:
            RateLimitPolicy instance.

        Raises:
            ValueError: If format is invalid.
        """
        if "/" not in rate_string:
            raise ValueError(f"Invalid rate limit format: {rate_string}. Expected 'N/period'")

        parts = rate_string.split("/")
        if len(parts) != 2:
            raise ValueError(f"Invalid rate limit format: {rate_string}")

        try:
            limit = int(parts[0])
        except ValueError as err:
            raise ValueError(f"Invalid limit value: {parts[0]}") from err

        period_map = {
            "second": 1,
            "sec": 1,
            "s": 1,
            "minute": 60,
            "min": 60,
            "m": 60,
            "hour": 3600,
            "hr": 3600,
            "h": 3600,
            "day": 86400,
            "d": 86400,
        }

        period_str = parts[1].lower().strip()
        if period_str not in period_map:
            raise ValueError(f"Unknown period: {period_str}. Valid: {list(period_map.keys())}")

        return cls(limit=limit, period=period_map[period_str])

    def acquire(self, blocking: bool = True, timeout: Optional[float] = None) -> bool:
        """Attempt to acquire a rate limit slot.

        Args:
            blocking: If True, wait until a slot is available.
            timeout: Maximum time to wait if blocking (None = forever).

        Returns:
            True if acquired, False if rate limited (non-blocking mode).
        """
        start_time = time.monotonic()

        while True:
            with self._lock:
                now = time.monotonic()

                # Remove expired calls
                cutoff = now - self.period
                while self._calls and self._calls[0] < cutoff:
                    self._calls.popleft()

                # Check if we can make a call
                effective_limit = self.limit + (self.burst or 0)
                if len(self._calls) < effective_limit:
                    self._calls.append(now)
                    return True

                if not blocking:
                    if self.on_limited:
                        self.on_limited()
                    return False

                # Calculate wait time
                wait_time = self._calls[0] + self.period - now if self._calls else 0.1

            # Check timeout
            if timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed >= timeout:
                    if self.on_limited:
                        self.on_limited()
                    return False
                wait_time = min(wait_time, timeout - elapsed)

            time.sleep(min(wait_time, 0.1))  # Sleep in small increments

    async def acquire_async(self, blocking: bool = True, timeout: Optional[float] = None) -> bool:
        """Async version of acquire.

        Args:
            blocking: If True, wait until a slot is available.
            timeout: Maximum time to wait if blocking (None = forever).

        Returns:
            True if acquired, False if rate limited.
        """
        start_time = asyncio.get_event_loop().time()

        while True:
            with self._lock:
                now = time.monotonic()

                # Remove expired calls
                cutoff = now - self.period
                while self._calls and self._calls[0] < cutoff:
                    self._calls.popleft()

                # Check if we can make a call
                effective_limit = self.limit + (self.burst or 0)
                if len(self._calls) < effective_limit:
                    self._calls.append(now)
                    return True

                if not blocking:
                    if self.on_limited:
                        self.on_limited()
                    return False

                # Calculate wait time
                wait_time = self._calls[0] + self.period - now if self._calls else 0.1

            # Check timeout
            if timeout is not None:
                elapsed = asyncio.get_event_loop().time() - start_time
                if elapsed >= timeout:
                    if self.on_limited:
                        self.on_limited()
                    return False
                wait_time = min(wait_time, timeout - elapsed)

            await asyncio.sleep(min(wait_time, 0.1))

    def reset(self) -> None:
        """Reset the rate limiter state."""
        with self._lock:
            self._calls.clear()


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded in non-blocking mode."""

    pass


class RetryExhausted(Exception):
    """Raised when all retry attempts have been exhausted."""

    def __init__(self, message: str, last_exception: Exception, attempts: int):
        super().__init__(message)
        self.last_exception = last_exception
        self.attempts = attempts


T = TypeVar("T")


def with_retry(policy: RetryPolicy, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Execute a function with retry policy.

    Args:
        policy: The retry policy to use.
        func: The function to execute.
        *args: Positional arguments to pass to func.
        **kwargs: Keyword arguments to pass to func.

    Returns:
        The result of the function.

    Raises:
        RetryExhausted: If all attempts fail.
    """
    last_exception = None

    for attempt in range(1, policy.max_attempts + 1):
        try:
            # Calculate and apply delay
            delay = policy.calculate_delay(attempt)
            if delay > 0:
                time.sleep(delay)

            return func(*args, **kwargs)

        except Exception as e:
            last_exception = e

            if not policy.should_retry(e):
                raise

            if attempt < policy.max_attempts:
                next_delay = policy.calculate_delay(attempt + 1)
                if policy.on_retry:
                    policy.on_retry(attempt, e, next_delay)

    raise RetryExhausted(
        f"All {policy.max_attempts} attempts failed", last_exception, policy.max_attempts
    )


async def with_retry_async(
    policy: RetryPolicy, func: Callable[..., T], *args: Any, **kwargs: Any
) -> T:
    """Execute an async function with retry policy.

    Args:
        policy: The retry policy to use.
        func: The async function to execute.
        *args: Positional arguments to pass to func.
        **kwargs: Keyword arguments to pass to func.

    Returns:
        The result of the function.

    Raises:
        RetryExhausted: If all attempts fail.
    """
    last_exception = None

    for attempt in range(1, policy.max_attempts + 1):
        try:
            # Calculate and apply delay
            delay = policy.calculate_delay(attempt)
            if delay > 0:
                await asyncio.sleep(delay)

            result = func(*args, **kwargs)
            if asyncio.iscoroutine(result):
                result = await result
            return result

        except Exception as e:
            last_exception = e

            if not policy.should_retry(e):
                raise

            if attempt < policy.max_attempts:
                next_delay = policy.calculate_delay(attempt + 1)
                if policy.on_retry:
                    policy.on_retry(attempt, e, next_delay)

    raise RetryExhausted(
        f"All {policy.max_attempts} attempts failed", last_exception, policy.max_attempts
    )
