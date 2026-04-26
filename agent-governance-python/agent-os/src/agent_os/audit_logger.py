# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Standard governance audit logger with pluggable backends."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """A governance audit log entry."""

    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = ""
    agent_id: str = ""
    action: str = ""
    decision: str = ""
    reason: str = ""
    latency_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class AuditBackend(Protocol):
    """Protocol for audit log backends."""

    def write(self, entry: AuditEntry) -> None: ...
    def flush(self) -> None: ...


class JsonlFileBackend:
    """Writes audit entries as JSONL to a file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.path, "a", encoding="utf-8")

    def write(self, entry: AuditEntry) -> None:
        self._file.write(entry.to_json() + "\n")

    def flush(self) -> None:
        self._file.flush()

    def close(self) -> None:
        self._file.close()


class InMemoryBackend:
    """Stores audit entries in memory (useful for testing)."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def write(self, entry: AuditEntry) -> None:
        self.entries.append(entry)

    def flush(self) -> None:
        pass


class LoggingBackend:
    """Writes audit entries via Python logging."""

    def __init__(self, logger_name: str = "agent_os.audit") -> None:
        self._logger = logging.getLogger(logger_name)

    def write(self, entry: AuditEntry) -> None:
        self._logger.info(
            "[%s] agent=%s action=%s decision=%s latency=%.1fms",
            entry.event_type, entry.agent_id, entry.action,
            entry.decision, entry.latency_ms,
        )

    def flush(self) -> None:
        pass


class GovernanceAuditLogger:
    """Standard audit logger with pluggable backends.

    Example::

        audit = GovernanceAuditLogger()
        audit.add_backend(InMemoryBackend())
        audit.log_decision(agent_id="a1", action="search", decision="allow")
    """

    def __init__(self) -> None:
        self._backends: list[Any] = []

    def add_backend(self, backend: Any) -> None:
        self._backends.append(backend)

    def log(self, entry: AuditEntry) -> None:
        for backend in self._backends:
            backend.write(entry)

    def log_decision(
        self,
        agent_id: str,
        action: str,
        decision: str,
        reason: str = "",
        latency_ms: float = 0.0,
        **metadata: Any,
    ) -> None:
        entry = AuditEntry(
            event_type="governance_decision",
            agent_id=agent_id,
            action=action,
            decision=decision,
            reason=reason,
            latency_ms=latency_ms,
            metadata=metadata,
        )
        self.log(entry)

    def flush(self) -> None:
        for backend in self._backends:
            backend.flush()
