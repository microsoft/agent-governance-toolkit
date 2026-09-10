# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Durable, JSON-safe governance records for Agent Learning artifacts."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

GOVERNANCE_METADATA_KEY = "agent_governance"
GOVERNANCE_SCHEMA_VERSION = "1.0"


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


class GovernanceOutcome(str, Enum):
    """Result of applying a governance policy to an action."""

    ALLOWED = "allowed"
    DENIED = "denied"
    MODIFIED = "modified"
    WARNED = "warned"


class RiskLevel(str, Enum):
    """Normalized governance risk classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class PolicyDecisionRecord:
    """One policy decision made while selecting or executing an action."""

    policy_name: str
    action_id: str
    outcome: GovernanceOutcome
    reason: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    id: str = field(default_factory=_new_id)
    timestamp: str = field(default_factory=_utcnow_iso)
    modified_action_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "policy_name": self.policy_name,
            "action_id": self.action_id,
            "outcome": self.outcome.value,
            "reason": self.reason,
            "risk_level": self.risk_level.value,
            "timestamp": self.timestamp,
            "modified_action_id": self.modified_action_id,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PolicyDecisionRecord:
        return cls(
            id=str(data["id"]),
            policy_name=str(data["policy_name"]),
            action_id=str(data["action_id"]),
            outcome=GovernanceOutcome(data["outcome"]),
            reason=str(data.get("reason", "")),
            risk_level=RiskLevel(data.get("risk_level", RiskLevel.LOW.value)),
            timestamp=str(data["timestamp"]),
            modified_action_id=data.get("modified_action_id"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class GovernanceViolation:
    """A policy violation persisted with an episode or learning artifact."""

    policy_name: str
    description: str
    severity: RiskLevel
    action_id: str | None = None
    blocked: bool = False
    penalty: float = 0.0
    decision_id: str | None = None
    id: str = field(default_factory=_new_id)
    timestamp: str = field(default_factory=_utcnow_iso)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "policy_name": self.policy_name,
            "description": self.description,
            "severity": self.severity.value,
            "action_id": self.action_id,
            "blocked": self.blocked,
            "penalty": self.penalty,
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GovernanceViolation:
        return cls(
            id=str(data["id"]),
            policy_name=str(data["policy_name"]),
            description=str(data["description"]),
            severity=RiskLevel(data["severity"]),
            action_id=data.get("action_id"),
            blocked=bool(data.get("blocked", False)),
            penalty=float(data.get("penalty", 0.0)),
            decision_id=data.get("decision_id"),
            timestamp=str(data["timestamp"]),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class ToolUsageRecord:
    """Governance result for a tool invocation, without raw tool secrets."""

    tool_name: str
    outcome: GovernanceOutcome
    action_id: str | None = None
    decision_id: str | None = None
    duration_ms: int | None = None
    cost: float | None = None
    timestamp: str = field(default_factory=_utcnow_iso)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "outcome": self.outcome.value,
            "action_id": self.action_id,
            "decision_id": self.decision_id,
            "duration_ms": self.duration_ms,
            "cost": self.cost,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ToolUsageRecord:
        return cls(
            tool_name=str(data["tool_name"]),
            outcome=GovernanceOutcome(data["outcome"]),
            action_id=data.get("action_id"),
            decision_id=data.get("decision_id"),
            duration_ms=data.get("duration_ms"),
            cost=data.get("cost"),
            timestamp=str(data["timestamp"]),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class GovernanceTelemetry:
    """Governance metadata embedded in Agent Learning durable records."""

    decisions: tuple[PolicyDecisionRecord, ...] = ()
    violations: tuple[GovernanceViolation, ...] = ()
    tool_usage: tuple[ToolUsageRecord, ...] = ()
    selection_basis: str | None = None
    reinforce_eligible: bool | None = None
    schema_version: str = GOVERNANCE_SCHEMA_VERSION
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "decisions": [decision.to_dict() for decision in self.decisions],
            "violations": [violation.to_dict() for violation in self.violations],
            "tool_usage": [usage.to_dict() for usage in self.tool_usage],
            "selection_basis": self.selection_basis,
            "reinforce_eligible": self.reinforce_eligible,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GovernanceTelemetry:
        return cls(
            schema_version=str(data.get("schema_version", GOVERNANCE_SCHEMA_VERSION)),
            decisions=tuple(
                PolicyDecisionRecord.from_dict(item) for item in data.get("decisions", ())
            ),
            violations=tuple(
                GovernanceViolation.from_dict(item) for item in data.get("violations", ())
            ),
            tool_usage=tuple(
                ToolUsageRecord.from_dict(item) for item in data.get("tool_usage", ())
            ),
            selection_basis=data.get("selection_basis"),
            reinforce_eligible=data.get("reinforce_eligible"),
            metadata=dict(data.get("metadata", {})),
        )

    def merge_metadata(self, metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Return artifact metadata with this telemetry under the stable namespace."""
        merged = dict(metadata or {})
        existing = merged.get(GOVERNANCE_METADATA_KEY, {})
        namespace = dict(existing) if isinstance(existing, Mapping) else {}
        namespace.update(self.to_dict())
        merged[GOVERNANCE_METADATA_KEY] = namespace
        return merged

    @classmethod
    def from_metadata(cls, metadata: Mapping[str, Any] | None) -> GovernanceTelemetry:
        if not metadata or GOVERNANCE_METADATA_KEY not in metadata:
            return cls()
        value = metadata[GOVERNANCE_METADATA_KEY]
        if not isinstance(value, Mapping):
            raise TypeError("agent_governance metadata must be a mapping")
        return cls.from_dict(value)


__all__ = [
    "GOVERNANCE_METADATA_KEY",
    "GOVERNANCE_SCHEMA_VERSION",
    "GovernanceOutcome",
    "GovernanceTelemetry",
    "GovernanceViolation",
    "PolicyDecisionRecord",
    "RiskLevel",
    "ToolUsageRecord",
]
