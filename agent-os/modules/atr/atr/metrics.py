# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Metrics collection for ATR tools.

Provides latency tracking, error rate monitoring, and usage statistics.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


class MetricType(str, Enum):
    """Types of metrics collected."""

    CALL_COUNT = "call_count"
    SUCCESS_COUNT = "success_count"
    ERROR_COUNT = "error_count"
    LATENCY = "latency"
    RATE_LIMITED = "rate_limited"


@dataclass
class ToolMetrics:
    """Metrics for a single tool.

    Attributes:
        name: Tool name.
        total_calls: Total number of calls.
        successful_calls: Number of successful calls.
        failed_calls: Number of failed calls.
        rate_limited_calls: Number of rate-limited calls.
        total_latency_ms: Total latency in milliseconds.
        min_latency_ms: Minimum latency.
        max_latency_ms: Maximum latency.
        last_called: Timestamp of last call.
        last_error: Last error message if any.
        error_types: Count of each error type.
    """

    name: str
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rate_limited_calls: int = 0
    total_latency_ms: float = 0.0
    min_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None
    last_called: Optional[datetime] = None
    last_error: Optional[str] = None
    error_types: Dict[str, int] = field(default_factory=dict)

    @property
    def avg_latency_ms(self) -> Optional[float]:
        """Average latency in milliseconds."""
        if self.total_calls == 0:
            return None
        return self.total_latency_ms / self.total_calls

    @property
    def success_rate(self) -> Optional[float]:
        """Success rate as a percentage (0-100)."""
        if self.total_calls == 0:
            return None
        return (self.successful_calls / self.total_calls) * 100

    @property
    def error_rate(self) -> Optional[float]:
        """Error rate as a percentage (0-100)."""
        if self.total_calls == 0:
            return None
        return (self.failed_calls / self.total_calls) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "rate_limited_calls": self.rate_limited_calls,
            "avg_latency_ms": self.avg_latency_ms,
            "min_latency_ms": self.min_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "success_rate": self.success_rate,
            "error_rate": self.error_rate,
            "last_called": self.last_called.isoformat() if self.last_called else None,
            "last_error": self.last_error,
            "error_types": dict(self.error_types),
        }


@dataclass
class TimeWindowMetrics:
    """Metrics within a specific time window."""

    window_start: datetime
    window_end: datetime
    call_count: int = 0
    success_count: int = 0
    error_count: int = 0
    total_latency_ms: float = 0.0

    @property
    def avg_latency_ms(self) -> Optional[float]:
        if self.call_count == 0:
            return None
        return self.total_latency_ms / self.call_count


class MetricsCollector:
    """Collects and aggregates tool metrics.

    Thread-safe collector that tracks tool execution metrics
    including call counts, latencies, and error rates.

    Example:
        >>> collector = MetricsCollector()
        >>>
        >>> # Record a successful call
        >>> collector.record_call("my_tool", latency_ms=150.0, success=True)
        >>>
        >>> # Get metrics
        >>> metrics = collector.get_metrics("my_tool")
        >>> print(f"Average latency: {metrics.avg_latency_ms}ms")
    """

    def __init__(self, retention_period: timedelta = timedelta(hours=24)):
        """Initialize collector.

        Args:
            retention_period: How long to retain detailed time-series data.
        """
        self._metrics: Dict[str, ToolMetrics] = {}
        self._time_series: Dict[str, List[Tuple[datetime, Dict[str, Any]]]] = defaultdict(list)
        self._retention_period = retention_period
        self._lock = threading.RLock()
        self._callbacks: List[Callable[[str, Dict[str, Any]], None]] = []

    def record_call(
        self,
        tool_name: str,
        latency_ms: float,
        success: bool,
        error: Optional[Exception] = None,
        rate_limited: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a tool call.

        Args:
            tool_name: Name of the tool.
            latency_ms: Call latency in milliseconds.
            success: Whether the call succeeded.
            error: Exception if call failed.
            rate_limited: Whether call was rate limited.
            metadata: Additional metadata to record.
        """
        now = datetime.now()

        with self._lock:
            # Get or create metrics for this tool
            if tool_name not in self._metrics:
                self._metrics[tool_name] = ToolMetrics(name=tool_name)

            metrics = self._metrics[tool_name]

            # Update counts
            metrics.total_calls += 1
            metrics.last_called = now

            if rate_limited:
                metrics.rate_limited_calls += 1
            elif success:
                metrics.successful_calls += 1
            else:
                metrics.failed_calls += 1
                if error:
                    error_type = type(error).__name__
                    metrics.error_types[error_type] = metrics.error_types.get(error_type, 0) + 1
                    metrics.last_error = str(error)

            # Update latency
            metrics.total_latency_ms += latency_ms
            if metrics.min_latency_ms is None or latency_ms < metrics.min_latency_ms:
                metrics.min_latency_ms = latency_ms
            if metrics.max_latency_ms is None or latency_ms > metrics.max_latency_ms:
                metrics.max_latency_ms = latency_ms

            # Store time series data
            event = {
                "timestamp": now,
                "latency_ms": latency_ms,
                "success": success,
                "rate_limited": rate_limited,
                "error_type": type(error).__name__ if error else None,
                "metadata": metadata,
            }
            self._time_series[tool_name].append((now, event))

            # Cleanup old data
            self._cleanup_old_data(tool_name)

        # Notify callbacks
        import contextlib

        for callback in self._callbacks:
            with contextlib.suppress(Exception):
                callback(tool_name, event)

    def _cleanup_old_data(self, tool_name: str) -> None:
        """Remove data older than retention period."""
        cutoff = datetime.now() - self._retention_period
        self._time_series[tool_name] = [
            (ts, event) for ts, event in self._time_series[tool_name] if ts > cutoff
        ]

    def get_metrics(self, tool_name: str) -> Optional[ToolMetrics]:
        """Get metrics for a specific tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            ToolMetrics instance or None if tool not tracked.
        """
        with self._lock:
            return self._metrics.get(tool_name)

    def get_all_metrics(self) -> Dict[str, ToolMetrics]:
        """Get metrics for all tools.

        Returns:
            Dictionary mapping tool names to metrics.
        """
        with self._lock:
            return dict(self._metrics)

    def get_time_window_metrics(
        self, tool_name: str, window: timedelta
    ) -> Optional[TimeWindowMetrics]:
        """Get metrics for a specific time window.

        Args:
            tool_name: Name of the tool.
            window: Time window to aggregate over.

        Returns:
            TimeWindowMetrics or None if no data.
        """
        now = datetime.now()
        cutoff = now - window

        with self._lock:
            if tool_name not in self._time_series:
                return None

            events = [event for ts, event in self._time_series[tool_name] if ts > cutoff]

            if not events:
                return None

            metrics = TimeWindowMetrics(window_start=cutoff, window_end=now)

            for event in events:
                metrics.call_count += 1
                metrics.total_latency_ms += event["latency_ms"]
                if event["success"]:
                    metrics.success_count += 1
                else:
                    metrics.error_count += 1

            return metrics

    def get_error_breakdown(
        self, tool_name: str, window: Optional[timedelta] = None
    ) -> Dict[str, int]:
        """Get breakdown of error types.

        Args:
            tool_name: Name of the tool.
            window: Optional time window (None = all time).

        Returns:
            Dictionary mapping error types to counts.
        """
        with self._lock:
            if window is None:
                metrics = self._metrics.get(tool_name)
                return dict(metrics.error_types) if metrics else {}

            cutoff = datetime.now() - window
            error_counts: Dict[str, int] = {}

            for ts, event in self._time_series.get(tool_name, []):
                if ts > cutoff and event.get("error_type"):
                    error_type = event["error_type"]
                    error_counts[error_type] = error_counts.get(error_type, 0) + 1

            return error_counts

    def add_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """Add a callback to be notified of new metrics.

        Args:
            callback: Function called with (tool_name, event_data).
        """
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """Remove a callback.

        Args:
            callback: The callback to remove.
        """
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def reset(self, tool_name: Optional[str] = None) -> None:
        """Reset metrics.

        Args:
            tool_name: Specific tool to reset, or None for all.
        """
        with self._lock:
            if tool_name is None:
                self._metrics.clear()
                self._time_series.clear()
            else:
                self._metrics.pop(tool_name, None)
                self._time_series.pop(tool_name, None)

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format.

        Returns:
            Prometheus-compatible metrics string.
        """
        lines = []

        with self._lock:
            for name, metrics in self._metrics.items():
                safe_name = name.replace("-", "_").replace(".", "_")

                lines.append("# HELP atr_tool_calls_total Total calls to tool")
                lines.append("# TYPE atr_tool_calls_total counter")
                lines.append(f'atr_tool_calls_total{{tool="{safe_name}"}} {metrics.total_calls}')

                lines.append("# HELP atr_tool_successes_total Successful calls")
                lines.append("# TYPE atr_tool_successes_total counter")
                lines.append(
                    f'atr_tool_successes_total{{tool="{safe_name}"}} {metrics.successful_calls}'
                )

                lines.append("# HELP atr_tool_errors_total Failed calls")
                lines.append("# TYPE atr_tool_errors_total counter")
                lines.append(f'atr_tool_errors_total{{tool="{safe_name}"}} {metrics.failed_calls}')

                if metrics.avg_latency_ms is not None:
                    lines.append("# HELP atr_tool_latency_avg_ms Average latency")
                    lines.append("# TYPE atr_tool_latency_avg_ms gauge")
                    lines.append(
                        f'atr_tool_latency_avg_ms{{tool="{safe_name}"}} {metrics.avg_latency_ms:.2f}'
                    )

        return "\n".join(lines)


class MetricsContext:
    """Context manager for measuring tool execution.

    Example:
        >>> with MetricsContext(collector, "my_tool") as ctx:
        ...     result = my_tool()
        ...     ctx.success = True
    """

    def __init__(
        self, collector: MetricsCollector, tool_name: str, metadata: Optional[Dict[str, Any]] = None
    ):
        self.collector = collector
        self.tool_name = tool_name
        self.metadata = metadata
        self.success = False
        self.error: Optional[Exception] = None
        self.rate_limited = False
        self._start_time: Optional[float] = None

    def __enter__(self) -> "MetricsContext":
        self._start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._start_time is None:
            return

        latency_ms = (time.perf_counter() - self._start_time) * 1000

        if exc_val is not None:
            self.error = exc_val
            self.success = False

        self.collector.record_call(
            tool_name=self.tool_name,
            latency_ms=latency_ms,
            success=self.success,
            error=self.error,
            rate_limited=self.rate_limited,
            metadata=self.metadata,
        )


# Global metrics collector
_global_collector: MetricsCollector = MetricsCollector()


def get_collector() -> MetricsCollector:
    """Get the global metrics collector.

    Returns:
        The global MetricsCollector instance.
    """
    return _global_collector


def set_collector(collector: MetricsCollector) -> None:
    """Set the global metrics collector.

    Args:
        collector: The collector to use globally.
    """
    global _global_collector
    _global_collector = collector
