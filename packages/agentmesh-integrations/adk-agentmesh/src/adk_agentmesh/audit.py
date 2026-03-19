# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Structured audit events for ADK governance."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


logger = logging.getLogger(__name__)


@dataclass
class AuditEvent:
    """A structured governance audit event."""
    event_type: str
    agent_name: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tool_name: str = ""
    verdict: str = ""
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class AuditHandler(Protocol):
    """Protocol for audit event handlers."""
    def handle(self, event: AuditEvent) -> None: ...


class LoggingAuditHandler:
    """Audit handler that logs events via Python logging."""

    def __init__(self, logger_name: str = "adk_agentmesh.audit"):
        self._logger = logging.getLogger(logger_name)

    def handle(self, event: AuditEvent) -> None:
        self._logger.info(
            "[%s] agent=%s tool=%s verdict=%s reason=%s",
            event.event_type,
            event.agent_name,
            event.tool_name,
            event.verdict,
            event.reason,
        )
