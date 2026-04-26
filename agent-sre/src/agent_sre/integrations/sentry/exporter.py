# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Sentry exporter - capture Agent-SRE errors and reliability context.

This module provides a lightweight Sentry integration without requiring a hard
runtime dependency on ``sentry-sdk``:
- **Live mode**: Uses a provided Sentry-compatible client (or auto-inits
  ``sentry_sdk`` when available and DSN is provided).
- **Offline mode**: Stores captured events in memory for tests/inspection.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class SentryClient(Protocol):
    """Protocol matching the subset of sentry-sdk client methods we use."""

    def capture_exception(self, error: BaseException, **kwargs: Any) -> Any: ...

    def capture_message(self, message: str, level: str = "info", **kwargs: Any) -> Any: ...


@dataclass
class SentryEvent:
    """Structured event captured by the exporter."""

    kind: str
    message: str
    level: str
    tags: dict[str, str] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class SentryExporter:
    """Export Agent SRE events to Sentry.

    Args:
        dsn: Optional Sentry DSN. If provided and no client is passed, tries to
            initialize ``sentry_sdk``.
        environment: Optional environment tag (prod, staging, etc.).
        release: Optional release tag for grouping.
        client: Optional Sentry-compatible client. When provided, takes
            precedence over DSN-based initialization.
    """

    def __init__(
        self,
        dsn: str = "",
        environment: str = "",
        release: str = "",
        client: Any | None = None,
    ) -> None:
        self._dsn = dsn
        self._environment = environment
        self._release = release
        self._events: list[SentryEvent] = []

        self._client = client
        if self._client is None and dsn:
            self._client = self._init_client(dsn=dsn, environment=environment, release=release)
        self._offline = self._client is None

    @property
    def is_offline(self) -> bool:
        """True if operating in offline/test mode."""
        return self._offline

    @property
    def events(self) -> list[SentryEvent]:
        """Get captured events."""
        return list(self._events)

    def capture_incident(
        self,
        title: str,
        severity: str = "error",
        tags: dict[str, str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> SentryEvent:
        """Capture an incident as a Sentry message event."""
        return self._record_message(
            message=title,
            level=severity,
            tags=tags or {},
            context=context or {},
        )

    def capture_exception(
        self,
        error: BaseException,
        tags: dict[str, str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> SentryEvent:
        """Capture an exception event."""
        message = str(error) or error.__class__.__name__
        event = SentryEvent(
            kind="exception",
            message=message,
            level="error",
            tags=tags or {},
            context=context or {},
        )
        self._events.append(event)

        if self._client is not None:
            self._safe_send_exception(error=error, tags=event.tags, context=event.context)
        return event

    def capture_slo_breach(
        self,
        slo: Any,
        agent_id: str = "",
        tags: dict[str, str] | None = None,
    ) -> SentryEvent:
        """Capture an SLO breach with structured context."""
        status = slo.evaluate()
        burn_rate = slo.error_budget.burn_rate()
        merged_tags = {"slo": slo.name, "status": status.value}
        if agent_id:
            merged_tags["agent_id"] = agent_id
        if tags:
            merged_tags.update(tags)

        context = {
            "slo_name": slo.name,
            "status": status.value,
            "budget_remaining": slo.error_budget.remaining,
            "burn_rate": burn_rate,
        }
        return self._record_message(
            message=f"SLO breach detected: {slo.name} ({status.value})",
            level="error",
            tags=merged_tags,
            context=context,
        )

    def clear(self) -> None:
        """Clear all stored events."""
        self._events.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get exporter statistics."""
        return {
            "is_offline": self._offline,
            "total_events": len(self._events),
            "environment": self._environment,
            "release": self._release,
        }

    def _record_message(
        self,
        message: str,
        level: str,
        tags: dict[str, str],
        context: dict[str, Any],
    ) -> SentryEvent:
        event = SentryEvent(
            kind="message",
            message=message,
            level=level,
            tags=tags,
            context=context,
        )
        self._events.append(event)

        if self._client is not None:
            self._safe_send_message(
                message=message,
                level=level,
                tags=tags,
                context=context,
            )
        return event

    def _safe_send_message(
        self,
        message: str,
        level: str,
        tags: dict[str, str],
        context: dict[str, Any],
    ) -> None:
        try:
            self._client.capture_message(
                message,
                level=level,
                tags=tags,
                context=context,
            )
        except Exception as e:
            logger.warning(f"Failed to send message to Sentry: {e}")

    def _safe_send_exception(
        self,
        error: BaseException,
        tags: dict[str, str],
        context: dict[str, Any],
    ) -> None:
        try:
            self._client.capture_exception(error, tags=tags, context=context)
        except Exception as e:
            logger.warning(f"Failed to send exception to Sentry: {e}")

    def _init_client(self, dsn: str, environment: str, release: str) -> Any | None:
        """Initialize sentry_sdk if installed; otherwise stay offline."""
        try:
            import sentry_sdk  # type: ignore[import-not-found]

            sentry_sdk.init(
                dsn=dsn,
                environment=environment or None,
                release=release or None,
            )
            return sentry_sdk
        except Exception as e:
            logger.warning(f"Sentry SDK unavailable or init failed, using offline mode: {e}")
            return None
