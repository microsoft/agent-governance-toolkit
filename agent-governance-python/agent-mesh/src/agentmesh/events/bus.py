# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Event bus abstraction for control/analytics plane separation.

Provides in-memory and async event buses with glob-style pattern matching
for decoupled event-driven architecture within AgentMesh.
"""

from __future__ import annotations

import asyncio
import fnmatch
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


# Standard event types
EVENT_TRUST_VERIFIED = "trust.verified"
EVENT_TRUST_FAILED = "trust.failed"
EVENT_TRUST_SCORE_CHANGED = "trust.score_changed"
EVENT_POLICY_EVALUATED = "policy.evaluated"
EVENT_POLICY_VIOLATED = "policy.violated"
EVENT_AUTHORITY_RESOLVED = "authority.resolved"
EVENT_AGENT_REGISTERED = "agent.registered"
EVENT_AGENT_REVOKED = "agent.revoked"
EVENT_AUDIT_ENTRY = "audit.entry"
EVENT_HANDSHAKE_COMPLETED = "handshake.completed"

ALL_EVENT_TYPES = [
    EVENT_TRUST_VERIFIED,
    EVENT_TRUST_FAILED,
    EVENT_TRUST_SCORE_CHANGED,
    EVENT_POLICY_EVALUATED,
    EVENT_POLICY_VIOLATED,
    EVENT_AUTHORITY_RESOLVED,
    EVENT_AGENT_REGISTERED,
    EVENT_AGENT_REVOKED,
    EVENT_AUDIT_ENTRY,
    EVENT_HANDSHAKE_COMPLETED,
]


@dataclass
class Event:
    """An event emitted by the AgentMesh system."""

    event_type: str
    source: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: str = field(default_factory=lambda: f"evt-{time.monotonic_ns()}")


EventHandler = Callable[[Event], Any]


class EventBus(ABC):
    """Abstract base class for event bus implementations."""

    @abstractmethod
    def emit(self, event: Event) -> None:
        """Emit an event to all matching subscribers."""

    @abstractmethod
    def subscribe(self, pattern: str, handler: EventHandler) -> None:
        """Subscribe a handler to events matching a glob-style pattern.

        Args:
            pattern: Glob-style pattern (e.g., ``trust.*``, ``*``).
            handler: Callable invoked with the matching Event.
        """

    @abstractmethod
    def unsubscribe(self, handler: EventHandler) -> None:
        """Remove a handler from all subscriptions."""


class InMemoryEventBus(EventBus):
    """Synchronous in-process event bus with glob-style pattern matching."""

    def __init__(self) -> None:
        self._subscriptions: list[tuple[str, EventHandler]] = []

    def emit(self, event: Event) -> None:
        for pattern, handler in self._subscriptions:
            if fnmatch.fnmatch(event.event_type, pattern):
                handler(event)

    def subscribe(self, pattern: str, handler: EventHandler) -> None:
        self._subscriptions.append((pattern, handler))

    def unsubscribe(self, handler: EventHandler) -> None:
        self._subscriptions = [
            (p, h) for p, h in self._subscriptions if h is not handler
        ]


class AsyncEventBus(EventBus):
    """Async queue-based event bus for decoupled analytics.

    Events are placed on an asyncio queue and delivered to subscribers
    by a background consumer task.
    """

    def __init__(self, maxsize: int = 10000) -> None:
        self._subscriptions: list[tuple[str, EventHandler]] = []
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize)
        self._running = False
        self._consumer_task: asyncio.Task[None] | None = None

    def emit(self, event: Event) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # drop events when queue is full

    def subscribe(self, pattern: str, handler: EventHandler) -> None:
        self._subscriptions.append((pattern, handler))

    def unsubscribe(self, handler: EventHandler) -> None:
        self._subscriptions = [
            (p, h) for p, h in self._subscriptions if h is not handler
        ]

    async def start(self) -> None:
        """Start the background consumer task."""
        if self._running:
            return
        self._running = True
        self._consumer_task = asyncio.create_task(self._consume())

    async def stop(self) -> None:
        """Stop the background consumer and drain remaining events."""
        self._running = False
        if self._consumer_task is not None:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
            self._consumer_task = None
        # Drain remaining events
        while not self._queue.empty():
            event = self._queue.get_nowait()
            self._dispatch(event)

    def _dispatch(self, event: Event) -> None:
        for pattern, handler in self._subscriptions:
            if fnmatch.fnmatch(event.event_type, pattern):
                result = handler(event)
                if asyncio.iscoroutine(result):
                    asyncio.ensure_future(result)

    async def _consume(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.1)
                self._dispatch(event)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
