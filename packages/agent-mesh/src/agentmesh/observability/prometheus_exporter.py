# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Prometheus Metrics Exporter for AgentMesh.

Provides ``MeshMetricsExporter`` — a high-level facade that exposes
trust, policy, latency, and agent-activity metrics for Prometheus scraping.
"""

from __future__ import annotations



try:
    from prometheus_client import Counter, Gauge, Histogram
    from prometheus_client import start_http_server as _start_http_server

    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False


class MeshMetricsExporter:
    """Prometheus exporter for AgentMesh observability.

    Metrics exposed:

    * ``trust_handshakes_total`` — counter of completed handshakes
    * ``trust_score`` — gauge per agent (labelled by ``agent_did``)
    * ``policy_violations_total`` — counter of policy violations
    * ``active_agents`` — gauge of currently active agents
    * ``handshake_latency_seconds`` — histogram of handshake durations
    * ``delegation_depth`` — histogram of scope chain depths
    * ``audit_entries_total`` — counter of audit log entries

    All recording methods are safe no-ops when *prometheus_client* is not
    installed.

    Args:
        prefix: Metric name prefix.  Defaults to ``agentmesh``.
    """

    def __init__(self, prefix: str = "agentmesh") -> None:
        if not _PROMETHEUS_AVAILABLE:
            self._enabled = False
            return

        self.trust_handshakes_total = Counter(
            f"{prefix}_trust_handshakes_total",
            "Total trust handshakes completed",
            ["result"],
        )
        self.trust_score = Gauge(
            f"{prefix}_trust_score",
            "Current trust score per agent",
            ["agent_did"],
        )
        self.policy_violations_total = Counter(
            f"{prefix}_policy_violations_total",
            "Total policy violations",
            ["policy_id"],
        )
        self.active_agents = Gauge(
            f"{prefix}_active_agents",
            "Number of active agents in the mesh",
        )
        self.handshake_latency_seconds = Histogram(
            f"{prefix}_handshake_latency_seconds",
            "Handshake latency in seconds",
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )
        self.delegation_depth = Histogram(
            f"{prefix}_delegation_depth",
            "Scope chain depth",
            buckets=(1, 2, 3, 4, 5, 7, 10, 15),
        )
        self.audit_entries_total = Counter(
            f"{prefix}_audit_entries_total",
            "Total audit log entries",
            ["event_type"],
        )
        self._enabled = True

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Return whether prometheus_client is available."""
        return self._enabled

    def record_handshake(self, duration_seconds: float, result: str) -> None:
        """Record a trust handshake.

        Args:
            duration_seconds: Handshake latency in seconds.
            result: Outcome label, e.g. ``success`` or ``failure``.
        """
        if not self._enabled:
            return
        self.handshake_latency_seconds.observe(duration_seconds)
        self.trust_handshakes_total.labels(result=result).inc()

    def update_trust_score(self, agent_did: str, score: float) -> None:
        """Set the trust-score gauge for *agent_did*.

        Args:
            agent_did: DID of the agent.
            score: Current trust score value.
        """
        if not self._enabled:
            return
        self.trust_score.labels(agent_did=agent_did).set(score)

    def record_policy_violation(self, policy_id: str) -> None:
        """Increment the policy-violation counter.

        Args:
            policy_id: Identifier of the violated policy.
        """
        if not self._enabled:
            return
        self.policy_violations_total.labels(policy_id=policy_id).inc()

    def set_active_agents(self, count: int) -> None:
        """Set the active-agents gauge.

        Args:
            count: Number of currently active agents.
        """
        if not self._enabled:
            return
        self.active_agents.set(count)

    def record_delegation(self, depth: int) -> None:
        """Observe a scope chain depth.

        Args:
            depth: Depth of the scope chain.
        """
        if not self._enabled:
            return
        self.delegation_depth.observe(depth)

    def record_audit_entry(self, event_type: str) -> None:
        """Increment the audit-entries counter.

        Args:
            event_type: Type of audit event.
        """
        if not self._enabled:
            return
        self.audit_entries_total.labels(event_type=event_type).inc()


def start_http_server(port: int = 9090) -> None:
    """Start the Prometheus HTTP metrics server.

    Args:
        port: TCP port to listen on.  Defaults to ``9090``.
    """
    if _PROMETHEUS_AVAILABLE:
        _start_http_server(port)
