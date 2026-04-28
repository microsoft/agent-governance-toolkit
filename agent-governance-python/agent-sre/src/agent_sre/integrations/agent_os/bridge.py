# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent OS integration — policy signals and preview mode hooks.

Connects to Agent OS's governance layer:
- Policy violations → SLO breaches (100% compliance SLO)
- Audit log → trace capture feed for replay
- Preview mode → progressive delivery preview step
- Policy review events → incident context
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_sre.incidents.detector import Signal, SignalType
from agent_sre.slo.indicators import SLI, SLIValue, TimeWindow


class PolicyComplianceSLI(SLI):
    """SLI that tracks Agent OS policy check results."""

    def __init__(self, target: float = 1.0, window: TimeWindow | str = "24h") -> None:
        super().__init__("agent_os_policy_compliance", target, window)
        self._total = 0
        self._compliant = 0

    def record_check(self, compliant: bool, policy_name: str = "", metadata: dict[str, Any] | None = None) -> SLIValue:
        self._total += 1
        if compliant:
            self._compliant += 1
        rate = self._compliant / self._total if self._total > 0 else 1.0
        return self.record(rate, {"policy_name": policy_name, **(metadata or {})})

    def collect(self) -> SLIValue:
        rate = self._compliant / self._total if self._total > 0 else 1.0
        return self.record(rate)


@dataclass
class AuditLogEntry:
    """An audit log entry from Agent OS."""

    entry_type: str  # blocked, warning, allowed, policy_review
    agent_id: str = ""
    action: str = ""
    policy_name: str = ""
    outcome: str = ""
    timestamp: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


class AgentOSBridge:
    """Bridge between Agent OS and Agent SRE.

    Translates OS policy signals into SRE signals and SLIs.
    """

    def __init__(self) -> None:
        self._policy_sli = PolicyComplianceSLI()
        self._events_processed = 0
        self._blocked_count = 0
        self._warning_count = 0
        self._policy_review_count = 0
        self._events_by_agent: dict[str, int] = {}

    @property
    def policy_sli(self) -> PolicyComplianceSLI:
        return self._policy_sli

    def process_audit_entry(self, entry: AuditLogEntry) -> Signal | None:
        """Process an Agent OS audit log entry and return a Signal if relevant."""
        self._events_processed += 1
        self._events_by_agent[entry.agent_id] = self._events_by_agent.get(entry.agent_id, 0) + 1

        if entry.entry_type == "blocked":
            self._blocked_count += 1
            self._policy_sli.record_check(False, entry.policy_name)
            return Signal(
                signal_type=SignalType.POLICY_VIOLATION,
                source=entry.agent_id,
                message=f"Action blocked by policy '{entry.policy_name}': {entry.action}",
                metadata=entry.details,
            )

        if entry.entry_type == "warning":
            self._warning_count += 1
            self._policy_sli.record_check(True, entry.policy_name)
            return None

        if entry.entry_type == "allowed":
            self._policy_sli.record_check(True, entry.policy_name)
            return None

        if entry.entry_type == "policy_review":
            self._policy_review_count += 1
            outcome = entry.details.get("review_outcome", "pending")
            if outcome == "rejected":
                self._policy_sli.record_check(False, "policy_review")
                return Signal(
                    signal_type=SignalType.POLICY_VIOLATION,
                    source=entry.agent_id,
                    message=f"Policy review rejected for {entry.agent_id}: {entry.action}",
                    metadata={**entry.details, "policy_review": True},
                )
            # Approved reviews count as compliant
            self._policy_sli.record_check(True, "policy_review")
            return None

        return None

    def get_agent_violation_count(self, agent_id: str) -> int:
        """Get number of events processed for a specific agent."""
        return self._events_by_agent.get(agent_id, 0)

    def slis(self) -> list[SLI]:
        return [self._policy_sli]

    def summary(self) -> dict[str, Any]:
        return {
            "events_processed": self._events_processed,
            "blocked_count": self._blocked_count,
            "warning_count": self._warning_count,
            "policy_review_count": self._policy_review_count,
            "policy_compliance": self._policy_sli.current_value(),
            "agents_seen": len(self._events_by_agent),
        }
