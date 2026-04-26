# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Mesh integration — pull telemetry and trust signals into Agent SRE.

Connects to Agent Mesh's observability stack:
- Prometheus metrics (port 9090): handshakes, trust scores, policy violations
- Audit events: tamper-evident CloudEvents for incident detection
- Audit trail correlation: map to distributed traces for replay
- AgentRegistry: discover deployment targets for rollouts
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_sre.incidents.detector import Signal, SignalType
from agent_sre.slo.indicators import SLI, SLIValue, TimeWindow


class TrustScoreSLI(SLI):
    """SLI that tracks Agent Mesh trust scores.

    Trust scores range 0-1000 in Agent Mesh.
    This SLI normalizes to 0.0-1.0.
    """

    def __init__(self, target: float = 0.8, window: TimeWindow | str = "24h") -> None:
        super().__init__("trust_score", target, window)

    def record_trust(self, score: int, agent_did: str = "") -> SLIValue:
        """Record a trust score (0-1000 scale, normalized to 0-1)."""
        normalized = min(1.0, max(0.0, score / 1000.0))
        return self.record(normalized, {"agent_did": agent_did, "raw_score": score})

    def collect(self) -> SLIValue:
        val = self.current_value()
        return self.record(val if val is not None else 0.0)


class HandshakeSuccessRateSLI(SLI):
    """SLI that tracks Agent Mesh handshake success rate."""

    def __init__(self, target: float = 0.99, window: TimeWindow | str = "1h") -> None:
        super().__init__("handshake_success_rate", target, window)
        self._total = 0
        self._success = 0

    def record_handshake(self, success: bool, metadata: dict[str, Any] | None = None) -> SLIValue:
        self._total += 1
        if success:
            self._success += 1
        rate = self._success / self._total if self._total > 0 else 0.0
        return self.record(rate, metadata)

    def collect(self) -> SLIValue:
        rate = self._success / self._total if self._total > 0 else 0.0
        return self.record(rate)


@dataclass
class MeshEvent:
    """An event from Agent Mesh to process."""

    event_type: str  # trust_revocation, credential_rotation, agent_registered, policy_violation
    agent_did: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


class AgentMeshBridge:
    """Bridge between Agent Mesh and Agent SRE.

    Translates Mesh telemetry into SRE signals and SLIs.
    """

    def __init__(self) -> None:
        self._trust_sli = TrustScoreSLI()
        self._handshake_sli = HandshakeSuccessRateSLI()
        self._events_processed = 0
        self._events_by_type: dict[str, int] = {}
        self._agent_trust_cache: dict[str, int] = {}

    @property
    def trust_sli(self) -> TrustScoreSLI:
        return self._trust_sli

    @property
    def handshake_sli(self) -> HandshakeSuccessRateSLI:
        return self._handshake_sli

    def process_event(self, event: MeshEvent) -> Signal | None:
        """Process an Agent Mesh event and return a Signal if relevant."""
        self._events_processed += 1
        self._events_by_type[event.event_type] = self._events_by_type.get(event.event_type, 0) + 1

        if event.event_type == "trust_revocation":
            self._agent_trust_cache[event.agent_did] = 0
            return Signal(
                signal_type=SignalType.TRUST_REVOCATION,
                source=event.agent_did,
                message=f"Trust revoked for {event.agent_did}",
                metadata=event.details,
            )

        if event.event_type == "policy_violation":
            return Signal(
                signal_type=SignalType.POLICY_VIOLATION,
                source=event.agent_did,
                message=f"Policy violation by {event.agent_did}",
                metadata=event.details,
            )

        if event.event_type == "credential_rotation":
            # Track rotation for operational visibility — not an incident
            return None

        if event.event_type == "trust_update":
            score = event.details.get("score", 500)
            self._trust_sli.record_trust(score, event.agent_did)
            self._agent_trust_cache[event.agent_did] = score
            return None

        if event.event_type == "handshake":
            success = event.details.get("success", True)
            self._handshake_sli.record_handshake(
                success, {"agent_did": event.agent_did, **event.details}
            )
            return None

        return None

    def get_agent_trust(self, agent_did: str) -> int | None:
        """Get last known trust score for an agent."""
        return self._agent_trust_cache.get(agent_did)

    def slis(self) -> list[SLI]:
        """Get all SLIs provided by this integration."""
        return [self._trust_sli, self._handshake_sli]

    def summary(self) -> dict[str, Any]:
        return {
            "events_processed": self._events_processed,
            "events_by_type": dict(self._events_by_type),
            "trust_score": self._trust_sli.current_value(),
            "handshake_rate": self._handshake_sli.current_value(),
            "tracked_agents": len(self._agent_trust_cache),
        }
