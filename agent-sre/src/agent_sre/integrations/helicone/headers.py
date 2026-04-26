# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Helicone integration — HTTP headers and event logging.

Helicone is a proxy-based LLM observability platform. This module provides:
1. **HeliconeHeaders**: Generate Helicone-compatible HTTP headers
2. **HeliconeLogger**: Log feedback and SLO scores to Helicone API

No Helicone dependency required — uses standard HTTP headers and urllib.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HeliconeEvent:
    """A logged Helicone event."""

    helicone_id: str
    event_type: str
    data: dict[str, Any]
    timestamp: float = field(default_factory=time.time)


class HeliconeHeaders:
    """Generate Helicone-compatible HTTP headers for LLM requests.

    Helicone uses HTTP headers to track requests through its proxy.
    This class builds the correct header dictionary for Agent-SRE agents.

    Args:
        api_key: Helicone API key for authentication.
        agent_id: Agent identifier for tracking.
        enabled: Whether header generation is enabled.

    Example:
        headers = HeliconeHeaders(api_key="sk-...", agent_id="bot-1")
        h = headers.get_headers(session_name="task-1")
        # Use h as additional headers in LLM API calls
    """

    def __init__(
        self,
        api_key: str = "",
        agent_id: str = "",
        enabled: bool = True,
    ) -> None:
        self._api_key = api_key
        self._agent_id = agent_id
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        """Whether header generation is enabled."""
        return self._enabled

    def get_headers(
        self,
        session_name: str = "",
        user_id: str = "",
        custom_properties: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Generate Helicone-compatible HTTP headers.

        Args:
            session_name: Session identifier for grouping requests.
            user_id: Optional user identifier.
            custom_properties: Additional custom properties as key-value pairs.

        Returns:
            Dictionary of HTTP headers. Empty dict if disabled.
        """
        if not self._enabled:
            return {}

        headers: dict[str, str] = {}

        if self._api_key:
            headers["Helicone-Auth"] = f"Bearer {self._api_key}"

        if session_name:
            headers["Helicone-Session-Id"] = session_name

        if self._agent_id:
            headers["Helicone-User-Id"] = self._agent_id
            headers["Helicone-Property-AgentId"] = self._agent_id

        if user_id:
            headers["Helicone-User-Id"] = user_id

        if custom_properties:
            for key, value in custom_properties.items():
                headers[f"Helicone-Property-{key}"] = value

        return headers


class HeliconeLogger:
    """Log feedback and SLO scores to Helicone API.

    Operates in two modes:
    - **Live mode**: Sends data to Helicone REST API (when api_key is provided)
    - **Offline mode**: Stores events in memory (when api_key is empty)

    Args:
        api_key: Helicone API key. Empty string for offline mode.
        base_url: Helicone API base URL.

    Example:
        hlogger = HeliconeLogger()  # offline mode
        hlogger.log_feedback("req-123", rating=True, comment="Good response")
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://api.helicone.ai",
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url
        self._offline = not bool(api_key)
        self._events: list[HeliconeEvent] = []

    @property
    def is_offline(self) -> bool:
        """True if operating in offline/test mode."""
        return self._offline

    @property
    def logged_events(self) -> list[HeliconeEvent]:
        """Get all logged events."""
        return list(self._events)

    def log_feedback(
        self,
        helicone_id: str,
        rating: bool,
        comment: str = "",
    ) -> HeliconeEvent:
        """Log quality feedback for a Helicone-tracked request.

        Args:
            helicone_id: Helicone request ID
            rating: Positive (True) or negative (False) feedback
            comment: Optional comment

        Returns:
            The created HeliconeEvent
        """
        event = HeliconeEvent(
            helicone_id=helicone_id,
            event_type="feedback",
            data={
                "rating": rating,
                "comment": comment,
            },
        )
        self._events.append(event)

        if not self._offline:
            self._send_feedback(helicone_id, rating, comment)

        return event

    def log_slo_score(
        self,
        helicone_id: str,
        slo_name: str,
        status: str,
        budget_remaining: float,
    ) -> HeliconeEvent:
        """Log SLO evaluation as Helicone feedback.

        Args:
            helicone_id: Helicone request ID
            slo_name: SLO name
            status: SLO status (healthy, warning, critical, exhausted)
            budget_remaining: Error budget remaining (0.0-1.0)

        Returns:
            The created HeliconeEvent
        """
        event = HeliconeEvent(
            helicone_id=helicone_id,
            event_type="slo_score",
            data={
                "slo_name": slo_name,
                "status": status,
                "budget_remaining": budget_remaining,
            },
        )
        self._events.append(event)

        if not self._offline:
            rating = status in ("healthy", "warning")
            self._send_feedback(
                helicone_id,
                rating=rating,
                comment=f"SLO {slo_name}: {status} (budget: {budget_remaining:.1%})",
            )

        return event

    def _send_feedback(
        self,
        helicone_id: str,
        rating: bool,
        comment: str,
    ) -> None:
        """Send feedback to Helicone API via urllib."""
        import json
        import urllib.request

        url = f"{self._base_url}/v1/request/{helicone_id}/feedback"
        data = json.dumps({"rating": rating, "comment": comment}).encode()
        req = urllib.request.Request(  # noqa: S310 — Helicone API endpoint URL
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)  # noqa: S310 — Helicone API endpoint URL
        except Exception as e:
            logger.warning(f"Failed to send feedback to Helicone: {e}")

    def clear(self) -> None:
        """Clear all logged events."""
        self._events.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about logged events."""
        feedback_count = sum(1 for e in self._events if e.event_type == "feedback")
        slo_count = sum(1 for e in self._events if e.event_type == "slo_score")
        return {
            "total_events": len(self._events),
            "feedback_events": feedback_count,
            "slo_score_events": slo_count,
        }
