# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Audit events and sinks for governed Agent Learning lifecycles."""

from __future__ import annotations

import json
import threading
import uuid
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


class AuditEventType(str, Enum):
    """Governance lifecycle events emitted by this integration."""

    POLICY_EVALUATED = "policy_evaluated"
    EPISODE_CAPTURED = "episode_captured"
    REWARD_SHAPED = "reward_shaped"
    LEARNING_RUN_STARTED = "learning_run_started"
    LEARNING_RUN_COMPLETED = "learning_run_completed"
    LEARNING_RUN_FAILED = "learning_run_failed"
    POLICY_VALIDATED = "policy_validated"
    PROMOTION_APPROVED = "promotion_approved"
    PROMOTION_BLOCKED = "promotion_blocked"
    PROMOTION_FAILED = "promotion_failed"
    POLICY_DEPLOYED = "policy_deployed"


@dataclass(frozen=True)
class AuditEvent:
    """A JSON-safe audit event linked to Agent Learning artifacts."""

    event_type: AuditEventType
    agent_id: str
    artifact_type: str
    artifact_id: str
    outcome: str
    task_id: str = "default"
    policy_id: str | None = None
    policy_version: int | None = None
    action_id: str | None = None
    correlation_id: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=_new_id)
    timestamp: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_type": self.event_type.value,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "artifact_type": self.artifact_type,
            "artifact_id": self.artifact_id,
            "outcome": self.outcome,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "action_id": self.action_id,
            "correlation_id": self.correlation_id,
            "details": dict(self.details),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuditEvent:
        return cls(
            id=str(data["id"]),
            event_type=AuditEventType(data["event_type"]),
            agent_id=str(data["agent_id"]),
            task_id=str(data.get("task_id", "default")),
            artifact_type=str(data["artifact_type"]),
            artifact_id=str(data["artifact_id"]),
            outcome=str(data["outcome"]),
            policy_id=data.get("policy_id"),
            policy_version=data.get("policy_version"),
            action_id=data.get("action_id"),
            correlation_id=data.get("correlation_id"),
            details=dict(data.get("details", {})),
            timestamp=str(data["timestamp"]),
        )


class AuditSink(Protocol):
    """Persistence protocol for governance audit events."""

    def emit(self, event: AuditEvent) -> None:
        """Persist one audit event."""
        ...

    def query(
        self,
        *,
        agent_id: str | None = None,
        event_type: AuditEventType | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Return recent matching events."""
        ...


class InMemoryAuditSink:
    """Thread-safe audit sink for tests and notebooks."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def query(
        self,
        *,
        agent_id: str | None = None,
        event_type: AuditEventType | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        if limit < 1:
            raise ValueError("limit must be at least one")
        with self._lock:
            matches = [
                event
                for event in self._events
                if (agent_id is None or event.agent_id == agent_id)
                and (event_type is None or event.event_type is event_type)
            ]
        return list(reversed(matches[-limit:]))


class JsonlAuditSink:
    """Append-only local JSONL audit sink for offline workflows."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(payload)
            handle.write("\n")

    def query(
        self,
        *,
        agent_id: str | None = None,
        event_type: AuditEventType | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        if limit < 1:
            raise ValueError("limit must be at least one")
        if not self.path.exists():
            return []
        matches: deque[AuditEvent] = deque(maxlen=limit)
        with self._lock, self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                event = AuditEvent.from_dict(json.loads(line))
                if (agent_id is None or event.agent_id == agent_id) and (
                    event_type is None or event.event_type is event_type
                ):
                    matches.append(event)
        return list(reversed(matches))


def emit_audit_event(sink: AuditSink | None, event: AuditEvent) -> None:
    """Emit when a sink is configured, keeping audit optional for callers."""
    if sink is not None:
        sink.emit(event)


__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditSink",
    "InMemoryAuditSink",
    "JsonlAuditSink",
    "emit_audit_event",
]
