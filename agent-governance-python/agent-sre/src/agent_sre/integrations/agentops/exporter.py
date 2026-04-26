# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentOps exporter — export Agent-SRE sessions and events.

AgentOps is session-based (like a recording of an agent's execution).
Operates in offline mode when api_key is empty.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SessionRecord:
    """A session record."""

    session_id: str
    agent_id: str
    tags: list[str]
    start_time: float
    end_time: float | None = None
    end_state: str = ""


@dataclass
class EventRecord:
    """An event within a session."""

    session_id: str
    event_type: str
    data: dict[str, Any]
    timestamp: float = field(default_factory=time.time)


class AgentOpsExporter:
    """Exports Agent SRE data as AgentOps sessions and events.

    Args:
        api_key: AgentOps API key. Empty string means offline mode.
        project_name: AgentOps project name.
    """

    def __init__(self, api_key: str = "", project_name: str = "agent-sre") -> None:
        self._api_key = api_key
        self._project_name = project_name
        self._offline = not api_key
        self._sessions: list[SessionRecord] = []
        self._events: list[EventRecord] = []

    @property
    def is_offline(self) -> bool:
        """True if operating in offline/test mode."""
        return self._offline

    @property
    def sessions(self) -> list[SessionRecord]:
        """Get recorded sessions."""
        return list(self._sessions)

    @property
    def events(self) -> list[EventRecord]:
        """Get recorded events."""
        return list(self._events)

    def start_session(
        self,
        agent_id: str,
        tags: list[str] | None = None,
    ) -> SessionRecord:
        """Start a new session.

        Args:
            agent_id: Agent identifier.
            tags: Optional session tags.

        Returns:
            The created SessionRecord.
        """
        session = SessionRecord(
            session_id=str(uuid.uuid4()),
            agent_id=agent_id,
            tags=list(tags) if tags else [],
            start_time=time.time(),
        )
        self._sessions.append(session)
        return session

    def end_session(
        self,
        session_id: str,
        success: bool = True,
        end_state: str = "success",
    ) -> SessionRecord | None:
        """End a session.

        Args:
            session_id: Session ID to end.
            success: Whether the session was successful.
            end_state: End state string.

        Returns:
            The updated SessionRecord, or None if not found.
        """
        for session in self._sessions:
            if session.session_id == session_id:
                session.end_time = time.time()
                session.end_state = end_state if success else "fail"
                return session
        return None

    def record_event(
        self,
        session_id: str,
        event_type: str,
        data: dict[str, Any] | None = None,
    ) -> EventRecord:
        """Record an event in a session.

        Args:
            session_id: Session ID.
            event_type: Type of event.
            data: Optional event data.

        Returns:
            The created EventRecord.
        """
        event = EventRecord(
            session_id=session_id,
            event_type=event_type,
            data=dict(data) if data else {},
        )
        self._events.append(event)
        return event

    def record_slo_check(self, session_id: str, slo: Any) -> EventRecord:
        """Record SLO evaluation as an event.

        Args:
            session_id: Session ID.
            slo: An agent_sre.slo.objectives.SLO instance.

        Returns:
            The created EventRecord.
        """
        status = slo.evaluate()
        data: dict[str, Any] = {
            "slo_name": slo.name,
            "status": status.value,
            "budget_remaining": slo.error_budget.remaining,
            "burn_rate": slo.error_budget.burn_rate(),
        }
        return self.record_event(session_id, "slo_check", data)

    def record_tool_call(
        self,
        session_id: str,
        tool_name: str,
        success: bool = True,
        latency_ms: float = 0.0,
    ) -> EventRecord:
        """Record a tool call event.

        Args:
            session_id: Session ID.
            tool_name: Name of the tool called.
            success: Whether the call succeeded.
            latency_ms: Latency in milliseconds.

        Returns:
            The created EventRecord.
        """
        data = {
            "tool_name": tool_name,
            "success": success,
            "latency_ms": latency_ms,
        }
        return self.record_event(session_id, "tool_call", data)

    def clear(self) -> None:
        """Clear all recorded sessions and events."""
        self._sessions.clear()
        self._events.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get exporter statistics."""
        return {
            "project_name": self._project_name,
            "total_sessions": len(self._sessions),
            "total_events": len(self._events),
            "is_offline": self._offline,
        }
