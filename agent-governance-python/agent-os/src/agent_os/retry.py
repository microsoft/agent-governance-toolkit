# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared retry utilities for governance toolkit components."""
from __future__ import annotations

import asyncio
import functools
import logging
import random
import time
from typing import Any, Callable, Sequence, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _compute_delay(backoff_base: float, attempt: int, jitter: bool) -> float:
    """Return the sleep duration before the next retry attempt.

    Without jitter, returns the classic exponential ``backoff_base * 2^(n-1)``.

    With jitter, multiplies the exponential by a uniform sample from
    ``[0.5, 1.5)`` so concurrent retriers reacting to the same upstream
    incident do not all wake at the same instant ("thundering herd"). This
    keeps the *expected* wait equal to the un-jittered value but spreads the
    actual wakes across a 1x-window centred on it.
    """
    delay = backoff_base * (2 ** (attempt - 1))
    if jitter:
        delay *= 0.5 + random.random()
    return delay


def retry(
    max_attempts: int = 3,
    backoff_base: float = 1.0,
    exceptions: Sequence[type[BaseException]] = (Exception,),
    on_retry: Callable[[int, BaseException], None] | None = None,
    jitter: bool = True,
) -> Callable:
    """Decorator for retrying functions with exponential backoff.

    Works with both sync and async functions.

    Args:
        max_attempts: Maximum number of attempts (including first try).
        backoff_base: Base delay in seconds (doubled each retry).
        exceptions: Tuple of exception types to catch and retry.
        on_retry: Optional callback(attempt, exception) called before each retry.
        jitter: When True (default), multiply each delay by a uniform sample
            from ``[0.5, 1.5)`` to avoid thundering-herd retries against a
            shared upstream. Disable only for deterministic tests; production
            callers should leave this on.

    Example:
        @retry(max_attempts=3, exceptions=(ConnectionError, TimeoutError))
        async def fetch_data(url: str) -> dict:
            ...
    """
    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                last_exc: BaseException | None = None
                for attempt in range(1, max_attempts + 1):
                    try:
                        return await func(*args, **kwargs)
                    except tuple(exceptions) as exc:
                        last_exc = exc
                        if attempt == max_attempts:
                            raise
                        delay = _compute_delay(backoff_base, attempt, jitter)
                        if on_retry:
                            on_retry(attempt, exc)
                        logger.warning(
                            "Retry %d/%d for %s after %s: %s",
                            attempt, max_attempts, func.__name__, type(exc).__name__, exc,
                        )
                        await asyncio.sleep(delay)
                raise last_exc  # unreachable but satisfies type checker
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                last_exc: BaseException | None = None
                for attempt in range(1, max_attempts + 1):
                    try:
                        return func(*args, **kwargs)
                    except tuple(exceptions) as exc:
                        last_exc = exc
                        if attempt == max_attempts:
                            raise
                        delay = _compute_delay(backoff_base, attempt, jitter)
                        if on_retry:
                            on_retry(attempt, exc)
                        logger.warning(
                            "Retry %d/%d for %s after %s: %s",
                            attempt, max_attempts, func.__name__, type(exc).__name__, exc,
                        )
                        time.sleep(delay)
                raise last_exc  # unreachable but satisfies type checker
            return sync_wrapper
    return decorator
