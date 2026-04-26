# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance Metrics Collector — Tracks policy enforcement statistics.

Thread-safe singleton that records policy checks, violations, approvals,
and blocked tool calls across all governance adapters.

Example:
    >>> from agent_os.metrics import metrics
    >>>
    >>> metrics.record_check("langchain", latency_ms=1.2, approved=True)
    >>> metrics.record_violation("crewai")
    >>> metrics.record_blocked("crewai")
    >>> snap = metrics.snapshot()
    >>> snap["total_checks"]  # 1
    >>> snap["violations"]    # 1
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class GovernanceMetrics:
    """Collects governance enforcement metrics across adapters.

    All public methods are thread-safe via an internal lock.
    """

    total_checks: int = 0
    violations: int = 0
    approvals: int = 0
    blocked: int = 0
    avg_latency_ms: float = 0.0

    _adapter_checks: dict[str, int] = field(default_factory=dict)
    _adapter_violations: dict[str, int] = field(default_factory=dict)
    _adapter_blocked: dict[str, int] = field(default_factory=dict)
    _total_latency_ms: float = field(default=0.0, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_check(self, adapter: str, latency_ms: float, approved: bool) -> None:
        """Record a policy check result.

        Args:
            adapter: Adapter name (e.g. ``"langchain"``).
            latency_ms: Time taken for the check in milliseconds.
            approved: Whether the action was approved.
        """
        with self._lock:
            self.total_checks += 1
            self._total_latency_ms += latency_ms
            self.avg_latency_ms = self._total_latency_ms / self.total_checks
            self._adapter_checks[adapter] = self._adapter_checks.get(adapter, 0) + 1
            if approved:
                self.approvals += 1
            else:
                self.violations += 1
                self._adapter_violations[adapter] = (
                    self._adapter_violations.get(adapter, 0) + 1
                )

    def record_violation(self, adapter: str) -> None:
        """Record a standalone policy violation.

        Args:
            adapter: Adapter name.
        """
        with self._lock:
            self.violations += 1
            self._adapter_violations[adapter] = (
                self._adapter_violations.get(adapter, 0) + 1
            )

    def record_blocked(self, adapter: str) -> None:
        """Record a blocked tool call.

        Args:
            adapter: Adapter name.
        """
        with self._lock:
            self.blocked += 1
            self._adapter_blocked[adapter] = (
                self._adapter_blocked.get(adapter, 0) + 1
            )

    def snapshot(self) -> dict:
        """Return a JSON-serializable snapshot of all metrics.

        Returns:
            Dictionary containing global and per-adapter metrics.
        """
        with self._lock:
            return {
                "total_checks": self.total_checks,
                "violations": self.violations,
                "approvals": self.approvals,
                "blocked": self.blocked,
                "avg_latency_ms": round(self.avg_latency_ms, 4),
                "adapters": {
                    adapter: {
                        "checks": self._adapter_checks.get(adapter, 0),
                        "violations": self._adapter_violations.get(adapter, 0),
                        "blocked": self._adapter_blocked.get(adapter, 0),
                    }
                    for adapter in sorted(
                        set(self._adapter_checks)
                        | set(self._adapter_violations)
                        | set(self._adapter_blocked)
                    )
                },
            }

    def reset(self) -> None:
        """Reset all counters to zero (useful for test isolation)."""
        with self._lock:
            self.total_checks = 0
            self.violations = 0
            self.approvals = 0
            self.blocked = 0
            self.avg_latency_ms = 0.0
            self._total_latency_ms = 0.0
            self._adapter_checks.clear()
            self._adapter_violations.clear()
            self._adapter_blocked.clear()


# Module-level singleton
metrics = GovernanceMetrics()

__all__ = ["GovernanceMetrics", "metrics"]
