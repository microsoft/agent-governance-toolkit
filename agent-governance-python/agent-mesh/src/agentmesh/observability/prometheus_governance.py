# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Prometheus metrics for governance observability.

Provides counters, histograms, and gauges for policy evaluation rates
and latency, trust score distributions, signal/termination event counts,
audit event rates, and violation rates by type.

All recording methods are safe no-ops when ``prometheus-client`` is not
installed.
"""

from __future__ import annotations

from typing import Optional

# ---------------------------------------------------------------------------
# Conditional Prometheus import
# ---------------------------------------------------------------------------

_PROMETHEUS_AVAILABLE = False
try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        CollectorRegistry,  # noqa: F401
        generate_latest,
    )

    _PROMETHEUS_AVAILABLE = True
except ImportError:
    pass


class GovernanceMetrics:
    """Prometheus metrics for governance observability.

    Provides counters, histograms, and gauges for:

    * Policy evaluation rates and latency
    * Trust score distributions
    * Signal / termination event counts
    * Audit event rates
    * Violation rates by type

    All methods are safe no-ops when ``prometheus-client`` is not
    installed, so the class can always be imported and instantiated.

    Args:
        prefix: Metric name prefix.  Defaults to
            ``"agentmesh_governance"``.
        registry: An optional ``CollectorRegistry``.  When *None* the
            default global registry is used.

    Example::

        metrics = GovernanceMetrics()
        metrics.record_policy_evaluation("max-tokens", "DENY", 1.23)
        metrics.record_violation("scope_exceeded", "high")
        print(metrics.get_metrics_text())
    """

    def __init__(
        self,
        prefix: str = "agentmesh_governance",
        registry: Optional[object] = None,
    ) -> None:
        if not _PROMETHEUS_AVAILABLE:
            self._enabled = False
            return

        reg_kwargs = {}
        if registry is not None:
            reg_kwargs["registry"] = registry
        self._registry = registry

        # -- Counters -------------------------------------------------------
        self.policy_evaluations_total = Counter(
            f"{prefix}_policy_evaluations_total",
            "Total number of governance policy evaluations",
            ["policy_name", "action"],
            **reg_kwargs,
        )
        self.violations_total = Counter(
            f"{prefix}_violations_total",
            "Total governance violations by type and severity",
            ["violation_type", "severity"],
            **reg_kwargs,
        )
        self.signals_total = Counter(
            f"{prefix}_signals_total",
            "Total agent signals delivered (SIGKILL, SIGPOLICY, etc.)",
            ["signal_name"],
            **reg_kwargs,
        )
        self.audit_events_total = Counter(
            f"{prefix}_audit_events_total",
            "Total audit events recorded",
            ["event_type"],
            **reg_kwargs,
        )

        # -- Histogram ------------------------------------------------------
        self.policy_evaluation_duration_ms = Histogram(
            f"{prefix}_policy_evaluation_duration_ms",
            "Policy evaluation latency in milliseconds",
            ["policy_name"],
            buckets=(0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500),
            **reg_kwargs,
        )

        # -- Gauges ---------------------------------------------------------
        self.trust_score = Gauge(
            f"{prefix}_trust_score",
            "Current trust score per agent",
            ["agent_did"],
            **reg_kwargs,
        )

        self._enabled = True

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Return whether ``prometheus-client`` is available."""
        return self._enabled

    # ------------------------------------------------------------------
    # Recording methods
    # ------------------------------------------------------------------

    def record_policy_evaluation(
        self,
        policy_name: str,
        action: str,
        duration_ms: float,
    ) -> None:
        """Record a policy evaluation.

        Args:
            policy_name: Identifier of the evaluated policy.
            action: Decision outcome (e.g. ``"ALLOW"`` / ``"DENY"``).
            duration_ms: Evaluation latency in milliseconds.
        """
        if not self._enabled:
            return
        self.policy_evaluations_total.labels(
            policy_name=policy_name, action=action
        ).inc()
        self.policy_evaluation_duration_ms.labels(
            policy_name=policy_name
        ).observe(duration_ms)

    def record_trust_score(self, agent_did: str, score: float) -> None:
        """Set the trust-score gauge for *agent_did*.

        Args:
            agent_did: DID of the agent.
            score: Current trust score value.
        """
        if not self._enabled:
            return
        self.trust_score.labels(agent_did=agent_did).set(score)

    def record_signal(self, signal_name: str, agent_id: str) -> None:
        """Increment the signal-delivery counter.

        Args:
            signal_name: Signal name (e.g. ``"SIGKILL"``).
            agent_id: Identifier of the target agent (used for logging
                context only; not a label to avoid high cardinality).
        """
        if not self._enabled:
            return
        self.signals_total.labels(signal_name=signal_name).inc()

    def record_violation(self, violation_type: str, severity: str) -> None:
        """Increment the violation counter.

        Args:
            violation_type: Type of violation (e.g.
                ``"scope_exceeded"``).
            severity: Severity level (e.g. ``"low"`` / ``"medium"`` /
                ``"high"`` / ``"critical"``).
        """
        if not self._enabled:
            return
        self.violations_total.labels(
            violation_type=violation_type, severity=severity
        ).inc()

    def record_audit_event(self, event_type: str) -> None:
        """Increment the audit-events counter.

        Args:
            event_type: Type of audit event (e.g.
                ``"trust_update"``).
        """
        if not self._enabled:
            return
        self.audit_events_total.labels(event_type=event_type).inc()

    # ------------------------------------------------------------------
    # Exposition
    # ------------------------------------------------------------------

    def get_metrics_text(self) -> str:
        """Return Prometheus text exposition format.

        When a custom registry was supplied at construction time,
        only metrics in that registry are returned.  Otherwise the
        default global registry is used.

        Returns:
            Multiline string in Prometheus text exposition format.
        """
        if not self._enabled:
            return ""
        if self._registry is not None:
            return generate_latest(self._registry).decode("utf-8")
        return generate_latest().decode("utf-8")
