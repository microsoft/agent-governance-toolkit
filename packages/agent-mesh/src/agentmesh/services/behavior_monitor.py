# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Behavior Monitor
======================

Runtime anomaly detection and quarantine for rogue agent behavior.
Tracks per-agent metrics and triggers alerts or quarantine when
thresholds are breached.

Monitored signals:
  - Tool call frequency (burst detection)
  - Consecutive failure rate
  - Capability escalation attempts
  - Trust score manipulation attempts

Usage::

    monitor = AgentBehaviorMonitor()
    monitor.record_tool_call("did:mesh:abc", "sql_query", success=True)
    # ... later ...
    if monitor.is_quarantined("did:mesh:abc"):
        raise PermissionError("Agent is quarantined")
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AgentMetrics:
    """Rolling metrics for a single agent."""

    agent_did: str
    total_calls: int = 0
    failed_calls: int = 0
    consecutive_failures: int = 0
    capability_denials: int = 0
    last_activity: Optional[datetime] = None
    quarantined: bool = False
    quarantine_reason: Optional[str] = None
    quarantined_at: Optional[datetime] = None
    # Rolling window for burst detection
    call_timestamps: list[datetime] = field(default_factory=list)


class AgentBehaviorMonitor:
    """Monitors agent behavior and quarantines anomalous agents.

    Args:
        burst_window_seconds: Time window for burst detection.
        burst_threshold: Max calls in the burst window before alert.
        consecutive_failure_threshold: Failures in a row before quarantine.
        capability_denial_threshold: Denied capability checks before quarantine.
        quarantine_duration: How long an auto-quarantine lasts.
        max_tracked_agents: Evict oldest agents beyond this limit.
    """

    def __init__(
        self,
        burst_window_seconds: int = 60,
        burst_threshold: int = 100,
        consecutive_failure_threshold: int = 20,
        capability_denial_threshold: int = 10,
        quarantine_duration: timedelta = timedelta(minutes=15),
        max_tracked_agents: int = 50_000,
    ) -> None:
        self._agents: dict[str, AgentMetrics] = {}
        self._lock = threading.Lock()
        self._burst_window = timedelta(seconds=burst_window_seconds)
        self._burst_threshold = burst_threshold
        self._consecutive_failure_threshold = consecutive_failure_threshold
        self._capability_denial_threshold = capability_denial_threshold
        self._quarantine_duration = quarantine_duration
        self._max_tracked = max_tracked_agents

    def _get_metrics(self, agent_did: str) -> AgentMetrics:
        with self._lock:
            if agent_did not in self._agents:
                if len(self._agents) >= self._max_tracked:
                    oldest = min(
                        self._agents,
                        key=lambda d: self._agents[d].last_activity or datetime.min,
                    )
                    del self._agents[oldest]
                self._agents[agent_did] = AgentMetrics(agent_did=agent_did)
            return self._agents[agent_did]

    def record_tool_call(
        self,
        agent_did: str,
        tool_name: str,
        *,
        success: bool,
    ) -> None:
        """Record a tool invocation and check for anomalies."""
        m = self._get_metrics(agent_did)
        now = datetime.utcnow()
        m.total_calls += 1
        m.last_activity = now

        if success:
            m.consecutive_failures = 0
        else:
            m.failed_calls += 1
            m.consecutive_failures += 1
            if m.consecutive_failures >= self._consecutive_failure_threshold:
                self._quarantine(
                    agent_did,
                    f"Consecutive failure threshold breached "
                    f"({m.consecutive_failures} failures)",
                )

        # Burst detection
        cutoff = now - self._burst_window
        m.call_timestamps = [t for t in m.call_timestamps if t > cutoff]
        m.call_timestamps.append(now)
        if len(m.call_timestamps) > self._burst_threshold:
            self._quarantine(
                agent_did,
                f"Burst threshold breached ({len(m.call_timestamps)} calls "
                f"in {self._burst_window.total_seconds()}s)",
            )

    def record_capability_denial(self, agent_did: str, capability: str) -> None:
        """Record a denied capability check (possible privilege escalation)."""
        m = self._get_metrics(agent_did)
        m.capability_denials += 1
        if m.capability_denials >= self._capability_denial_threshold:
            self._quarantine(
                agent_did,
                f"Capability denial threshold breached "
                f"({m.capability_denials} denials, last: {capability})",
            )

    def _quarantine(self, agent_did: str, reason: str) -> None:
        m = self._get_metrics(agent_did)
        if m.quarantined:
            return  # already quarantined
        m.quarantined = True
        m.quarantine_reason = reason
        m.quarantined_at = datetime.utcnow()
        logger.warning("QUARANTINE agent %s: %s", agent_did, reason)

    def is_quarantined(self, agent_did: str) -> bool:
        """Check if an agent is currently quarantined."""
        m = self._agents.get(agent_did)
        if not m or not m.quarantined:
            return False
        # Auto-release after quarantine duration
        if m.quarantined_at and datetime.utcnow() - m.quarantined_at > self._quarantine_duration:
            self.release_quarantine(agent_did)
            return False
        return True

    def release_quarantine(self, agent_did: str) -> None:
        """Manually release an agent from quarantine."""
        m = self._agents.get(agent_did)
        if m:
            m.quarantined = False
            m.quarantine_reason = None
            m.quarantined_at = None
            m.consecutive_failures = 0
            m.capability_denials = 0
            logger.info("Released agent %s from quarantine", agent_did)

    def get_metrics(self, agent_did: str) -> Optional[AgentMetrics]:
        """Get current metrics for an agent (read-only snapshot)."""
        return self._agents.get(agent_did)

    def get_quarantined_agents(self) -> list[AgentMetrics]:
        """List all currently quarantined agents."""
        return [m for m in self._agents.values() if m.quarantined]
