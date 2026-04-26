# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Performance profiling for governance checks and adapter operations.

Provides a decorator and context manager for measuring execution time,
call counts, and memory usage of adapter methods.
"""

import functools
import time
import tracemalloc
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class MethodStats:
    """Statistics for a single profiled method."""
    name: str
    call_count: int = 0
    total_time_ms: float = 0.0
    min_time_ms: float = float("inf")
    max_time_ms: float = 0.0
    total_memory_delta: int = 0

    @property
    def avg_time_ms(self) -> float:
        return self.total_time_ms / self.call_count if self.call_count else 0.0


@dataclass
class ProfilingReport:
    """Aggregated profiling results."""
    methods: dict[str, MethodStats] = field(default_factory=dict)

    @property
    def total_calls(self) -> int:
        return sum(m.call_count for m in self.methods.values())

    @property
    def total_time_ms(self) -> float:
        return sum(m.total_time_ms for m in self.methods.values())

    def format_report(self) -> str:
        """Return a human-readable table of profiling results."""
        if not self.methods:
            return "No profiling data collected."
        header = f"{'Method':<30} {'Calls':>6} {'Total ms':>10} {'Avg ms':>10} {'Min ms':>10} {'Max ms':>10}"
        sep = "-" * len(header)
        lines = [header, sep]
        for stats in sorted(self.methods.values(), key=lambda s: s.total_time_ms, reverse=True):
            lines.append(
                f"{stats.name:<30} {stats.call_count:>6} "
                f"{stats.total_time_ms:>10.2f} {stats.avg_time_ms:>10.2f} "
                f"{stats.min_time_ms:>10.2f} {stats.max_time_ms:>10.2f}"
            )
        lines.append(sep)
        lines.append(f"{'TOTAL':<30} {self.total_calls:>6} {self.total_time_ms:>10.2f}")
        return "\n".join(lines)


# Global report used by the decorator
_global_report = ProfilingReport()


def get_report() -> ProfilingReport:
    """Retrieve the global profiling report."""
    return _global_report


def reset_report() -> None:
    """Reset the global profiling report."""
    _global_report.methods.clear()


def profile_governance(func: Optional[Callable] = None, *, track_memory: bool = False):
    """Decorator that profiles execution time (and optionally memory) of a method.

    Usage:
        @profile_governance
        def my_method(self, ...): ...

        @profile_governance(track_memory=True)
        def my_method(self, ...): ...
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = fn.__name__
            if key not in _global_report.methods:
                _global_report.methods[key] = MethodStats(name=key)
            stats = _global_report.methods[key]

            mem_before = 0
            if track_memory:
                if not tracemalloc.is_tracing():
                    tracemalloc.start()
                _, mem_before = tracemalloc.get_traced_memory()

            start = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                elapsed_ms = (time.perf_counter() - start) * 1000
                stats.call_count += 1
                stats.total_time_ms += elapsed_ms
                stats.min_time_ms = min(stats.min_time_ms, elapsed_ms)
                stats.max_time_ms = max(stats.max_time_ms, elapsed_ms)

                if track_memory:
                    _, mem_after = tracemalloc.get_traced_memory()
                    stats.total_memory_delta += mem_after - mem_before

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator


class ProfileGovernanceContext:
    """Context manager for scoped profiling.

    Usage:
        with ProfileGovernanceContext() as report:
            # run profiled code
        print(report.format_report())
    """

    def __init__(self, track_memory: bool = False):
        self.track_memory = track_memory
        self.report = ProfilingReport()
        self._previous_report: Optional[ProfilingReport] = None

    def __enter__(self) -> ProfilingReport:
        global _global_report
        self._previous_report = _global_report
        _global_report = self.report
        return self.report

    def __exit__(self, *exc: Any) -> None:
        global _global_report
        _global_report = self._previous_report  # type: ignore
