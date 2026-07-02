# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Health Check Endpoints for K8s Readiness/Liveness Probes

Thread-safe health checker with configurable component checks,
JSON-serializable reports, and aggregate status computation.
"""

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable


class HealthStatus(Enum):
    """Possible health states for a component or the overall system."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True)
class ComponentHealth:
    """Health result for a single component."""
    name: str
    status: HealthStatus
    message: str = ""
    latency_ms: float = 0.0


@dataclass
class HealthReport:
    """Aggregate health report for all registered components."""
    status: HealthStatus
    components: dict[str, ComponentHealth]
    timestamp: str
    version: str
    uptime_seconds: float

    def to_dict(self) -> dict:
        """Return a JSON-serializable dictionary."""
        return {
            "status": self.status.value,
            "components": {
                name: {
                    "name": comp.name,
                    "status": comp.status.value,
                    "message": comp.message,
                    "latency_ms": comp.latency_ms,
                }
                for name, comp in self.components.items()
            },
            "timestamp": self.timestamp,
            "version": self.version,
            "uptime_seconds": self.uptime_seconds,
        }

    def is_healthy(self) -> bool:
        """True when aggregate status is HEALTHY."""
        return self.status == HealthStatus.HEALTHY

    def is_ready(self) -> bool:
        """True when the system is ready to serve (not UNHEALTHY)."""
        return self.status != HealthStatus.UNHEALTHY


class HealthChecker:
    """Thread-safe health checker with pluggable component checks.

    Fails closed: a checker with no registered checks aggregates to UNHEALTHY
    (an empty report never claims HEALTHY), and the built-in audit-backend probe
    reports DEGRADED when no backend is configured rather than a bare HEALTHY.

    Args:
        version: Application version string included in reports.
        register_builtins: When True (default) the ``policy_engine`` and
            ``audit_backend`` built-in checks are registered so a fresh checker
            verifies real components instead of returning an empty HEALTHY report.
        policy_engine: Optional policy-engine reference (reserved for probes).
        audit_backend: Optional audit backend probed by the built-in
            ``audit_backend`` check. When ``None`` that check reports DEGRADED.
    """

    def __init__(
        self,
        version: str = "1.0.0",
        *,
        register_builtins: bool = True,
        policy_engine: object | None = None,
        audit_backend: object | None = None,
    ) -> None:
        self._checks: dict[str, Callable[[], ComponentHealth]] = {}
        self._start_time = datetime.now(timezone.utc)
        self._version = version
        self._lock = threading.Lock()
        self._policy_engine = policy_engine
        self._audit_backend = audit_backend
        if register_builtins:
            self.register_check("policy_engine", self._check_policy_engine)
            self.register_check("audit_backend", self._check_audit_backend)

    # -- registration ------------------------------------------------------

    def register_check(
        self, name: str, check_fn: Callable[[], ComponentHealth]
    ) -> None:
        """Register a named health check function (thread-safe)."""
        with self._lock:
            self._checks[name] = check_fn

    # -- probes ------------------------------------------------------------

    def check_health(self) -> HealthReport:
        """Run **all** registered checks and return a full report."""
        with self._lock:
            checks = dict(self._checks)

        components: dict[str, ComponentHealth] = {}
        for name, fn in checks.items():
            start = time.monotonic()
            try:
                result = fn()
            except Exception as exc:
                result = ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=str(exc),
                )
            elapsed_ms = (time.monotonic() - start) * 1000.0
            # Preserve check-reported latency if non-zero, else use measured.
            latency = result.latency_ms if result.latency_ms else elapsed_ms
            components[name] = ComponentHealth(
                name=result.name,
                status=result.status,
                message=result.message,
                latency_ms=latency,
            )

        return self._build_report(components)

    def check_ready(self) -> HealthReport:
        """Readiness probe — same as full health check."""
        return self.check_health()

    def check_live(self) -> HealthReport:
        """Liveness probe — lightweight; returns HEALTHY if the process is up."""
        components: dict[str, ComponentHealth] = {
            "process": ComponentHealth(
                name="process",
                status=HealthStatus.HEALTHY,
                message="alive",
            )
        }
        return self._build_report(components)

    # -- built-in checks ---------------------------------------------------

    def _check_policy_engine(self) -> ComponentHealth:
        """Built-in check that validates the policy engine can create a policy."""
        from .base import GovernancePolicy

        start = time.monotonic()
        try:
            GovernancePolicy(name="health-probe")
            elapsed = (time.monotonic() - start) * 1000.0
            return ComponentHealth(
                name="policy_engine",
                status=HealthStatus.HEALTHY,
                message="policy engine operational",
                latency_ms=elapsed,
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000.0
            return ComponentHealth(
                name="policy_engine",
                status=HealthStatus.UNHEALTHY,
                message=str(exc),
                latency_ms=elapsed,
            )

    def _check_audit_backend(self) -> ComponentHealth:
        """Built-in check for the configured audit backend.

        Reports DEGRADED (not HEALTHY) when no audit backend is configured — a
        governance probe must not claim the audit path is healthy when nothing
        is wired up. When a backend is present, verifies it exposes the expected
        write/flush (or emit) interface without mutating the audit log.
        """
        start = time.monotonic()
        backend = self._audit_backend
        if backend is None:
            return ComponentHealth(
                name="audit_backend",
                status=HealthStatus.DEGRADED,
                message="no audit backend configured",
                latency_ms=(time.monotonic() - start) * 1000.0,
            )
        has_write_flush = callable(getattr(backend, "write", None)) and callable(
            getattr(backend, "flush", None)
        )
        has_emit = callable(getattr(backend, "emit", None))
        elapsed = (time.monotonic() - start) * 1000.0
        if has_write_flush or has_emit:
            return ComponentHealth(
                name="audit_backend",
                status=HealthStatus.HEALTHY,
                message="audit backend configured (write/flush interface available)",
                latency_ms=elapsed,
            )
        return ComponentHealth(
            name="audit_backend",
            status=HealthStatus.UNHEALTHY,
            message="audit backend missing write/flush or emit interface",
            latency_ms=elapsed,
        )

    # -- helpers -----------------------------------------------------------

    def _build_report(
        self, components: dict[str, ComponentHealth]
    ) -> HealthReport:
        status = self._aggregate_status(components)
        now = datetime.now(timezone.utc)
        uptime = (now - self._start_time).total_seconds()
        return HealthReport(
            status=status,
            components=components,
            timestamp=now.isoformat() + "Z",
            version=self._version,
            uptime_seconds=uptime,
        )

    @staticmethod
    def _aggregate_status(
        components: dict[str, ComponentHealth],
    ) -> HealthStatus:
        if not components:
            # Fail closed: an empty report verifies nothing, so it must not
            # claim HEALTHY (a probe wired to this would report a false-healthy).
            return HealthStatus.UNHEALTHY
        statuses = {c.status for c in components.values()}
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY
