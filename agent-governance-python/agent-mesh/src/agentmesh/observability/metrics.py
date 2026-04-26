# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Prometheus Metrics Integration.

Provides metrics collection and export for AgentMesh.
"""

from typing import Optional


class MetricsCollector:
    """
    Prometheus metrics collector for AgentMesh.

    Exposes metrics:
    - agentmesh_handshake_total{status="success|fail"}
    - agentmesh_policy_violation_count{policy_id="..."}
    - agentmesh_trust_score_gauge{agent_did="..."}
    - agentmesh_registry_size
    - agentmesh_api_request_duration_seconds
    """

    def __init__(self):
        """Initialize metrics collector."""
        try:
            from prometheus_client import Counter, Gauge, Histogram

            # Handshake metrics
            self.handshake_total = Counter(
                "agentmesh_handshake_total",
                "Total number of trust handshakes",
                ["status"],
            )

            # Policy violation metrics
            self.policy_violation_count = Counter(
                "agentmesh_policy_violation_count",
                "Number of policy violations",
                ["policy_id", "agent_did"],
            )

            # Trust score metrics
            self.trust_score_gauge = Gauge(
                "agentmesh_trust_score_gauge",
                "Current trust score of an agent",
                ["agent_did"],
            )

            # Registry size
            self.registry_size = Gauge(
                "agentmesh_registry_size",
                "Number of agents in registry",
                ["status"],
            )

            # API request duration
            self.api_request_duration = Histogram(
                "agentmesh_api_request_duration_seconds",
                "API request duration in seconds",
                ["method", "endpoint", "status"],
            )

            # Tool call metrics
            self.tool_call_total = Counter(
                "agentmesh_tool_call_total",
                "Total number of tool calls",
                ["agent_did", "tool_name", "status"],
            )

            # Reward signal metrics
            self.reward_signal_total = Counter(
                "agentmesh_reward_signal_total",
                "Total number of reward signals",
                ["agent_did", "dimension"],
            )

            # Audit log metrics
            self.audit_log_total = Counter(
                "agentmesh_audit_log_total",
                "Total number of audit log entries",
                ["event_type", "outcome"],
            )

            # Credential issuance metrics
            self.credential_issued_total = Counter(
                "agentmesh_credential_issued_total",
                "Total number of credentials issued",
                ["agent_did"],
            )

            # Credential revocation metrics
            self.credential_revoked_total = Counter(
                "agentmesh_credential_revoked_total",
                "Total number of credentials revoked",
                ["agent_did", "reason"],
            )

            self._enabled = True
        except ImportError:
            # Prometheus client not installed
            self._enabled = False

    @property
    def enabled(self) -> bool:
        """Check if metrics are enabled."""
        return self._enabled

    def record_handshake(self, success: bool):
        """Record a trust handshake."""
        if not self._enabled:
            return
        status = "success" if success else "fail"
        self.handshake_total.labels(status=status).inc()

    def record_policy_violation(self, policy_id: str, agent_did: str):
        """Record a policy violation."""
        if not self._enabled:
            return
        self.policy_violation_count.labels(
            policy_id=policy_id,
            agent_did=agent_did,
        ).inc()

    def set_trust_score(self, agent_did: str, score: int):
        """Set trust score for an agent."""
        if not self._enabled:
            return
        self.trust_score_gauge.labels(agent_did=agent_did).set(score)

    def set_registry_size(self, status: str, count: int):
        """Set registry size."""
        if not self._enabled:
            return
        self.registry_size.labels(status=status).set(count)

    def record_api_request(
        self,
        method: str,
        endpoint: str,
        status: int,
        duration: float,
    ):
        """Record API request."""
        if not self._enabled:
            return
        self.api_request_duration.labels(
            method=method,
            endpoint=endpoint,
            status=status,
        ).observe(duration)

    def record_tool_call(
        self,
        agent_did: str,
        tool_name: str,
        success: bool,
    ):
        """Record a tool call."""
        if not self._enabled:
            return
        status = "success" if success else "fail"
        self.tool_call_total.labels(
            agent_did=agent_did,
            tool_name=tool_name,
            status=status,
        ).inc()

    def record_reward_signal(self, agent_did: str, dimension: str):
        """Record a reward signal."""
        if not self._enabled:
            return
        self.reward_signal_total.labels(
            agent_did=agent_did,
            dimension=dimension,
        ).inc()

    def record_audit_log(self, event_type: str, outcome: str):
        """Record an audit log entry."""
        if not self._enabled:
            return
        self.audit_log_total.labels(
            event_type=event_type,
            outcome=outcome,
        ).inc()

    def record_credential_issued(self, agent_did: str):
        """Record credential issuance."""
        if not self._enabled:
            return
        self.credential_issued_total.labels(agent_did=agent_did).inc()

    def record_credential_revoked(self, agent_did: str, reason: str):
        """Record credential revocation."""
        if not self._enabled:
            return
        self.credential_revoked_total.labels(
            agent_did=agent_did,
            reason=reason,
        ).inc()


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def setup_metrics() -> MetricsCollector:
    """
    Setup Prometheus metrics.

    Returns:
        MetricsCollector instance
    """
    global _metrics_collector

    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()

    return _metrics_collector


def get_metrics() -> Optional[MetricsCollector]:
    """Get metrics collector instance."""
    return _metrics_collector


class MeshMetrics:
    """Prometheus metrics for mesh health monitoring.

    Tracks handshake latency, trust scores, active agents, delegation depth,
    verification failures, and policy evaluations.

    Args:
        prefix: Optional metric name prefix. Defaults to ``agentmesh``.
    """

    def __init__(self, prefix: str = "agentmesh") -> None:
        try:
            from prometheus_client import Counter, Gauge, Histogram

            self.handshake_duration = Histogram(
                f"{prefix}_handshake_duration_seconds",
                "Handshake latency in seconds",
            )
            self.trust_score = Gauge(
                f"{prefix}_trust_score",
                "Current trust score for an agent",
                ["agent_did"],
            )
            self.active_agents = Gauge(
                f"{prefix}_active_agents_total",
                "Number of active agents in the mesh",
            )
            self.scope_chain_depth = Histogram(
                f"{prefix}_scope_chain_depth",
                "Scope chain depths",
            )
            self.failed_verifications = Counter(
                f"{prefix}_failed_verifications_total",
                "Failed trust verifications",
                ["reason"],
            )
            self.handshakes_total = Counter(
                f"{prefix}_handshakes_total",
                "Total handshakes by result",
                ["result"],
            )
            self.policy_evaluations = Counter(
                f"{prefix}_policy_evaluations_total",
                "Policy evaluation decisions",
                ["decision"],
            )
            self._enabled = True
        except ImportError:
            self._enabled = False

    @property
    def enabled(self) -> bool:
        """Return whether prometheus_client is available."""
        return self._enabled

    def record_handshake(self, duration_seconds: float, result: str) -> None:
        """Record a handshake with its duration and result.

        Args:
            duration_seconds: Handshake latency in seconds.
            result: Outcome label, e.g. ``success`` or ``failure``.
        """
        if not self._enabled:
            return
        self.handshake_duration.observe(duration_seconds)
        self.handshakes_total.labels(result=result).inc()

    def update_trust_score(self, agent_did: str, score: float) -> None:
        """Update the trust score gauge for an agent.

        Args:
            agent_did: DID of the agent.
            score: Current trust score value.
        """
        if not self._enabled:
            return
        self.trust_score.labels(agent_did=agent_did).set(score)

    def record_verification_failure(self, reason: str) -> None:
        """Increment the failed verifications counter.

        Args:
            reason: Failure reason label.
        """
        if not self._enabled:
            return
        self.failed_verifications.labels(reason=reason).inc()

    def record_delegation(self, depth: int) -> None:
        """Record a scope chain depth observation.

        Args:
            depth: Depth of the scope chain.
        """
        if not self._enabled:
            return
        self.scope_chain_depth.observe(depth)

    def record_policy_evaluation(self, decision: str) -> None:
        """Record a policy evaluation decision.

        Args:
            decision: Decision label, e.g. ``allow``, ``deny``, or ``warn``.
        """
        if not self._enabled:
            return
        self.policy_evaluations.labels(decision=decision).inc()

    def set_active_agents(self, count: int) -> None:
        """Set the active agents gauge.

        Args:
            count: Number of currently active agents.
        """
        if not self._enabled:
            return
        self.active_agents.set(count)


def start_metrics_server(port: int = 9090):
    """Start Prometheus metrics HTTP server.

    Args:
        port: Port to listen on (default: 9090).
    """
    try:
        from prometheus_client import start_http_server

        start_http_server(port)
    except ImportError:
        pass
