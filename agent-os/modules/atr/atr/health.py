# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Health check functionality for ATR tools.

Provides mechanisms to verify external tools and APIs are available
before execution.
"""

from __future__ import annotations

import asyncio
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, Optional, Union


class HealthStatus(str, Enum):
    """Health check status values."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check.

    Attributes:
        status: Overall health status.
        message: Human-readable status message.
        latency_ms: Check latency in milliseconds.
        timestamp: When the check was performed.
        details: Additional details about the check.
    """

    status: HealthStatus
    message: str = ""
    latency_ms: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_healthy(self) -> bool:
        """Check if status indicates tool is usable."""
        return self.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "message": self.message,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


class HealthCheck(ABC):
    """Abstract base class for health checks.

    Subclass this to create custom health checks for your tools.
    """

    @abstractmethod
    def check(self) -> HealthCheckResult:
        """Perform the health check synchronously.

        Returns:
            HealthCheckResult with status and details.
        """
        pass

    async def check_async(self) -> HealthCheckResult:
        """Perform the health check asynchronously.

        Default implementation runs sync check in executor.
        Override for true async checks.

        Returns:
            HealthCheckResult with status and details.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.check)


class HttpHealthCheck(HealthCheck):
    """Health check that verifies an HTTP endpoint is responding.

    Example:
        >>> check = HttpHealthCheck(
        ...     url="https://api.example.com/health",
        ...     timeout=5.0,
        ...     expected_status=200
        ... )
        >>> result = check.check()
        >>> print(result.status)
    """

    def __init__(
        self,
        url: str,
        timeout: float = 5.0,
        expected_status: int = 200,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ):
        """Initialize HTTP health check.

        Args:
            url: The URL to check.
            timeout: Request timeout in seconds.
            expected_status: Expected HTTP status code.
            method: HTTP method to use.
            headers: Optional headers to include.
        """
        self.url = url
        self.timeout = timeout
        self.expected_status = expected_status
        self.method = method
        self.headers = headers or {}

    def check(self) -> HealthCheckResult:
        """Perform HTTP health check."""
        import urllib.error
        import urllib.request

        start_time = time.perf_counter()

        try:
            request = urllib.request.Request(self.url, method=self.method, headers=self.headers)

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                latency_ms = (time.perf_counter() - start_time) * 1000
                status_code = response.status

                if status_code == self.expected_status:
                    return HealthCheckResult(
                        status=HealthStatus.HEALTHY,
                        message=f"HTTP {status_code} OK",
                        latency_ms=latency_ms,
                        details={"url": self.url, "status_code": status_code},
                    )
                else:
                    return HealthCheckResult(
                        status=HealthStatus.DEGRADED,
                        message=f"Unexpected status: {status_code}",
                        latency_ms=latency_ms,
                        details={"url": self.url, "status_code": status_code},
                    )

        except urllib.error.URLError as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"Connection failed: {e.reason}",
                latency_ms=latency_ms,
                details={"url": self.url, "error": str(e)},
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"Check failed: {str(e)}",
                latency_ms=latency_ms,
                details={"url": self.url, "error": str(e)},
            )


class TcpHealthCheck(HealthCheck):
    """Health check that verifies a TCP port is accepting connections.

    Example:
        >>> check = TcpHealthCheck(host="localhost", port=5432)
        >>> result = check.check()
    """

    def __init__(self, host: str, port: int, timeout: float = 5.0):
        """Initialize TCP health check.

        Args:
            host: The host to connect to.
            port: The port to check.
            timeout: Connection timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    def check(self) -> HealthCheckResult:
        """Perform TCP health check."""
        import socket

        start_time = time.perf_counter()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, self.port))
            sock.close()

            latency_ms = (time.perf_counter() - start_time) * 1000

            if result == 0:
                return HealthCheckResult(
                    status=HealthStatus.HEALTHY,
                    message=f"Port {self.port} is open",
                    latency_ms=latency_ms,
                    details={"host": self.host, "port": self.port},
                )
            else:
                return HealthCheckResult(
                    status=HealthStatus.UNHEALTHY,
                    message=f"Port {self.port} is closed",
                    latency_ms=latency_ms,
                    details={"host": self.host, "port": self.port, "error_code": result},
                )

        except socket.timeout:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message="Connection timed out",
                latency_ms=latency_ms,
                details={"host": self.host, "port": self.port},
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"Check failed: {str(e)}",
                latency_ms=latency_ms,
                details={"host": self.host, "port": self.port, "error": str(e)},
            )


class CallableHealthCheck(HealthCheck):
    """Health check using a custom callable.

    Example:
        >>> def check_database():
        ...     # Custom check logic
        ...     return True, "Database OK"
        >>>
        >>> check = CallableHealthCheck(check_database)
    """

    def __init__(self, func: Callable[[], Union[bool, tuple]], name: str = "custom"):
        """Initialize callable health check.

        Args:
            func: Callable that returns bool or (bool, message) tuple.
            name: Name for this check.
        """
        self.func = func
        self.name = name

    def check(self) -> HealthCheckResult:
        """Perform the custom health check."""
        start_time = time.perf_counter()

        try:
            result = self.func()
            latency_ms = (time.perf_counter() - start_time) * 1000

            if isinstance(result, bool):
                healthy = result
                message = "Check passed" if healthy else "Check failed"
            elif isinstance(result, tuple) and len(result) >= 2:
                healthy = result[0]
                message = result[1]
            else:
                healthy = bool(result)
                message = str(result)

            return HealthCheckResult(
                status=HealthStatus.HEALTHY if healthy else HealthStatus.UNHEALTHY,
                message=message,
                latency_ms=latency_ms,
                details={"check_name": self.name},
            )

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"Check raised exception: {str(e)}",
                latency_ms=latency_ms,
                details={"check_name": self.name, "error": str(e)},
            )


@dataclass
class CachedHealthResult:
    """Cached health check result with TTL."""

    result: HealthCheckResult
    expires_at: datetime


class HealthCheckRegistry:
    """Registry for managing tool health checks.

    Provides caching, background checking, and aggregated health status.

    Example:
        >>> registry = HealthCheckRegistry()
        >>> registry.register("api_tool", HttpHealthCheck("https://api.example.com/health"))
        >>>
        >>> # Check all tools
        >>> status = registry.check_all()
        >>> for name, result in status.items():
        ...     print(f"{name}: {result.status}")
    """

    def __init__(self, cache_ttl: timedelta = timedelta(seconds=30), check_timeout: float = 10.0):
        """Initialize health check registry.

        Args:
            cache_ttl: How long to cache health check results.
            check_timeout: Default timeout for health checks.
        """
        self._checks: Dict[str, HealthCheck] = {}
        self._cache: Dict[str, CachedHealthResult] = {}
        self._cache_ttl = cache_ttl
        self._check_timeout = check_timeout
        self._lock = threading.RLock()
        self._background_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def register(self, tool_name: str, check: Union[HealthCheck, Callable[[], bool], str]) -> None:
        """Register a health check for a tool.

        Args:
            tool_name: Name of the tool.
            check: HealthCheck instance, callable, or URL string.
        """
        with self._lock:
            if isinstance(check, str):
                # Assume it's a URL for HTTP check
                check = HttpHealthCheck(check)
            elif callable(check) and not isinstance(check, HealthCheck):
                check = CallableHealthCheck(check, name=tool_name)

            self._checks[tool_name] = check

    def unregister(self, tool_name: str) -> bool:
        """Unregister a health check.

        Args:
            tool_name: Name of the tool.

        Returns:
            True if was registered, False otherwise.
        """
        with self._lock:
            if tool_name in self._checks:
                del self._checks[tool_name]
                self._cache.pop(tool_name, None)
                return True
            return False

    def check(self, tool_name: str, use_cache: bool = True) -> HealthCheckResult:
        """Check health of a specific tool.

        Args:
            tool_name: Name of the tool.
            use_cache: Whether to use cached result if available.

        Returns:
            HealthCheckResult.
        """
        with self._lock:
            if tool_name not in self._checks:
                return HealthCheckResult(
                    status=HealthStatus.UNKNOWN,
                    message=f"No health check registered for '{tool_name}'",
                )

            # Check cache
            if use_cache and tool_name in self._cache:
                cached = self._cache[tool_name]
                if datetime.now() < cached.expires_at:
                    return cached.result

            # Perform check
            check = self._checks[tool_name]

        result = check.check()

        # Update cache
        with self._lock:
            self._cache[tool_name] = CachedHealthResult(
                result=result, expires_at=datetime.now() + self._cache_ttl
            )

        return result

    async def check_async(self, tool_name: str, use_cache: bool = True) -> HealthCheckResult:
        """Check health of a specific tool asynchronously.

        Args:
            tool_name: Name of the tool.
            use_cache: Whether to use cached result if available.

        Returns:
            HealthCheckResult.
        """
        with self._lock:
            if tool_name not in self._checks:
                return HealthCheckResult(
                    status=HealthStatus.UNKNOWN,
                    message=f"No health check registered for '{tool_name}'",
                )

            # Check cache
            if use_cache and tool_name in self._cache:
                cached = self._cache[tool_name]
                if datetime.now() < cached.expires_at:
                    return cached.result

            check = self._checks[tool_name]

        result = await check.check_async()

        # Update cache
        with self._lock:
            self._cache[tool_name] = CachedHealthResult(
                result=result, expires_at=datetime.now() + self._cache_ttl
            )

        return result

    def check_all(self, use_cache: bool = True) -> Dict[str, HealthCheckResult]:
        """Check health of all registered tools.

        Args:
            use_cache: Whether to use cached results.

        Returns:
            Dictionary mapping tool names to results.
        """
        with self._lock:
            tool_names = list(self._checks.keys())

        return {name: self.check(name, use_cache) for name in tool_names}

    async def check_all_async(self, use_cache: bool = True) -> Dict[str, HealthCheckResult]:
        """Check health of all registered tools asynchronously.

        Args:
            use_cache: Whether to use cached results.

        Returns:
            Dictionary mapping tool names to results.
        """
        with self._lock:
            tool_names = list(self._checks.keys())

        tasks = [self.check_async(name, use_cache) for name in tool_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        health_results = {}
        for name, result in zip(tool_names, results):
            if isinstance(result, Exception):
                health_results[name] = HealthCheckResult(
                    status=HealthStatus.UNHEALTHY, message=f"Check failed: {str(result)}"
                )
            else:
                health_results[name] = result

        return health_results

    def get_overall_status(self) -> HealthStatus:
        """Get overall health status across all tools.

        Returns:
            HEALTHY if all healthy, DEGRADED if any degraded, UNHEALTHY if any unhealthy.
        """
        results = self.check_all()

        if not results:
            return HealthStatus.UNKNOWN

        statuses = [r.status for r in results.values()]

        if all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            return HealthStatus.UNHEALTHY
        elif any(s == HealthStatus.DEGRADED for s in statuses):
            return HealthStatus.DEGRADED
        else:
            return HealthStatus.UNKNOWN

    def start_background_checks(self, interval: timedelta = timedelta(seconds=30)) -> None:
        """Start background health checks.

        Args:
            interval: How often to run checks.
        """
        if self._background_thread is not None and self._background_thread.is_alive():
            return

        self._stop_event.clear()

        def check_loop():
            import contextlib

            while not self._stop_event.is_set():
                with contextlib.suppress(Exception):
                    self.check_all(use_cache=False)
                self._stop_event.wait(interval.total_seconds())

        self._background_thread = threading.Thread(target=check_loop, daemon=True)
        self._background_thread.start()

    def stop_background_checks(self) -> None:
        """Stop background health checks."""
        self._stop_event.set()
        if self._background_thread is not None:
            self._background_thread.join(timeout=5.0)
            self._background_thread = None

    def clear_cache(self) -> None:
        """Clear the health check cache."""
        with self._lock:
            self._cache.clear()


# Global health check registry
_global_health_registry: HealthCheckRegistry = HealthCheckRegistry()


def get_health_registry() -> HealthCheckRegistry:
    """Get the global health check registry.

    Returns:
        The global HealthCheckRegistry instance.
    """
    return _global_health_registry


def set_health_registry(registry: HealthCheckRegistry) -> None:
    """Set the global health check registry.

    Args:
        registry: The registry to use globally.
    """
    global _global_health_registry
    _global_health_registry = registry
