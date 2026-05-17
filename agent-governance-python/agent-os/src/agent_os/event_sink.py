# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""GovernanceEventSink SPI -- pluggable backends for governance event routing.

This module provides the Service Provider Interface for delivering governance
events to external systems (SIEM, XDR, observability platforms, message buses).

Architecture follows the OTel SpanExporter + BatchSpanProcessor pattern:
  - GovernanceEventSink: Protocol that backends implement (sync emit())
  - GovernanceEventProcessor: Batch fan-out engine with background thread
  - GovernanceEvent: Immutable event envelope with schema versioning

External sink packages can implement GovernanceEventSink via structural
typing (Protocol) without importing agent-os as a dependency.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, Sequence, runtime_checkable

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1"

_DEFAULT_MAX_QUEUE_SIZE = 1024
_DEFAULT_SCHEDULE_DELAY_MS = 2000
_DEFAULT_MAX_BATCH_SIZE = 100
_DEFAULT_EXPORT_TIMEOUT_MS = 10000
_DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
_DEFAULT_CIRCUIT_BREAKER_COOLDOWN_S = 60


class GovernanceEventKind(str, Enum):
    """Classification of governance events."""

    POLICY_CHECK = "policy_check"
    POLICY_VIOLATION = "policy_violation"
    TOOL_CALL_BLOCKED = "tool_call_blocked"
    PROMPT_INJECTION_DETECTED = "prompt_injection_detected"
    IDENTITY_VERIFIED = "identity_verified"
    IDENTITY_REJECTED = "identity_rejected"
    RESOURCE_ACCESS = "resource_access"
    ESCALATION_REQUESTED = "escalation_requested"
    CHECKPOINT_CREATED = "checkpoint_created"
    ANOMALY_DETECTED = "anomaly_detected"
    MCP_TOOL_POISONING = "mcp_tool_poisoning"
    CONTENT_VIOLATION = "content_violation"


class SinkExportResult(Enum):
    """Result of a sink emit() call."""

    SUCCESS = 0
    FAILURE = 1
    DROPPED = 2


@dataclass(frozen=True)
class GovernanceEvent:
    """Immutable governance event envelope. Schema v1.

    Fields are additive-only across schema versions. Sinks must
    tolerate unknown fields by ignoring them.
    """

    schema_version: str = field(default=SCHEMA_VERSION)

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    occurred_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    kind: GovernanceEventKind = GovernanceEventKind.POLICY_CHECK
    severity: str = "info"

    agent_id: str = ""
    agent_did: str | None = None
    session_id: str | None = None

    action: str = ""
    resource: str | None = None
    decision: str = ""
    reason: str = ""
    policy_name: str | None = None
    latency_ms: float = 0.0

    trace_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None

    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a flat dict suitable for JSON delivery."""
        return {
            k: (v.value if isinstance(v, Enum) else v)
            for k, v in asdict(self).items()
            if v is not None
        }


@runtime_checkable
class GovernanceEventSink(Protocol):
    """SPI contract for governance event backends.

    Implementations receive batches of GovernanceEvent objects and deliver
    them to a target system.

    Contract:
      - emit() MUST NOT raise exceptions; wrap errors and return FAILURE
      - emit() MUST be thread-safe
      - shutdown() SHOULD flush in-flight events before returning

    Structural typing: external packages implement this without importing
    agent-os, matching the OTelSpanSink pattern in agent-sre.
    """

    def emit(self, events: Sequence[GovernanceEvent]) -> SinkExportResult:
        """Deliver a batch of governance events to the backend."""
        ...

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        """Flush in-flight events and release resources."""
        ...

    def force_flush(self, timeout_ms: int = 30000) -> bool:
        """Block until all buffered events are delivered or timeout expires."""
        ...


class GovernanceEventSinkBase:
    """Optional convenience base class for sink implementors.

    Provides safe default implementations of shutdown() and force_flush().
    Subclass and override emit() to create a sink.
    """

    def emit(self, events: Sequence[GovernanceEvent]) -> SinkExportResult:
        raise NotImplementedError

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        return True

    def force_flush(self, timeout_ms: int = 30000) -> bool:
        return True


class _SinkState:
    """Per-sink circuit breaker state."""

    __slots__ = ("consecutive_failures", "circuit_open_until")

    def __init__(self) -> None:
        self.consecutive_failures: int = 0
        self.circuit_open_until: float = 0.0


class GovernanceEventProcessor:
    """Fan-out processor: routes GovernanceEvents to registered sinks.

    Mirrors OTel's BatchSpanProcessor pattern:
      - Bounded queue with DROP_OLDEST backpressure
      - Configurable batch size and schedule delay
      - Per-sink error isolation (one failing sink never affects others)
      - Circuit breaker per sink after consecutive failures

    Environment variables:
      AGT_GSP_MAX_QUEUE_SIZE      (default: 1024)
      AGT_GSP_SCHEDULE_DELAY_MS   (default: 2000)
      AGT_GSP_MAX_BATCH_SIZE      (default: 100)
      AGT_GSP_EXPORT_TIMEOUT_MS   (default: 10000)
    """

    def __init__(
        self,
        max_queue_size: int | None = None,
        schedule_delay_ms: float | None = None,
        max_batch_size: int | None = None,
        export_timeout_ms: float | None = None,
        circuit_breaker_threshold: int = _DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
        circuit_breaker_cooldown_s: float = _DEFAULT_CIRCUIT_BREAKER_COOLDOWN_S,
    ) -> None:
        self._max_queue_size = max_queue_size or int(
            os.environ.get("AGT_GSP_MAX_QUEUE_SIZE", _DEFAULT_MAX_QUEUE_SIZE)
        )
        self._schedule_delay_s = (schedule_delay_ms or float(
            os.environ.get("AGT_GSP_SCHEDULE_DELAY_MS", _DEFAULT_SCHEDULE_DELAY_MS)
        )) / 1000.0
        self._max_batch_size = max_batch_size or int(
            os.environ.get("AGT_GSP_MAX_BATCH_SIZE", _DEFAULT_MAX_BATCH_SIZE)
        )
        self._export_timeout_s = (export_timeout_ms or float(
            os.environ.get("AGT_GSP_EXPORT_TIMEOUT_MS", _DEFAULT_EXPORT_TIMEOUT_MS)
        )) / 1000.0
        self._cb_threshold = circuit_breaker_threshold
        self._cb_cooldown_s = circuit_breaker_cooldown_s

        self._sinks: list[GovernanceEventSink] = []
        self._sink_states: dict[int, _SinkState] = {}
        self._queue: deque[GovernanceEvent] = deque(maxlen=self._max_queue_size)
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._stopped = False
        self._dropped_count = 0
        self._worker: threading.Thread | None = None

    def _ensure_worker(self) -> None:
        """Lazily start the background worker on first sink registration."""
        if self._worker is None:
            self._worker = threading.Thread(
                target=self._run, name="agt-governance-event-processor", daemon=True
            )
            self._worker.start()

    def add_sink(self, sink: GovernanceEventSink) -> GovernanceEventProcessor:
        """Register a sink. Returns self for chaining."""
        with self._lock:
            self._sinks.append(sink)
            self._sink_states[id(sink)] = _SinkState()
        self._ensure_worker()
        return self

    def on_event(self, event: GovernanceEvent) -> None:
        """Enqueue a governance event for async delivery.

        Non-blocking. If the queue is full, the oldest event is dropped
        (DROP_OLDEST policy: recent events are more valuable for SIEM).
        """
        with self._condition:
            if self._stopped:
                return
            if len(self._queue) >= self._max_queue_size:
                self._dropped_count += 1
            self._queue.append(event)
            self._condition.notify()

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        """Stop the processor and flush remaining events."""
        with self._condition:
            self._stopped = True
            self._condition.notify()

        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=timeout_ms / 1000.0)

        # Final flush
        self._flush_queue()

        for sink in self._sinks:
            try:
                sink.shutdown(timeout_ms=timeout_ms)
            except Exception:
                logger.exception("Sink %r raised during shutdown", sink)

        return not (self._worker and self._worker.is_alive())

    def force_flush(self, timeout_ms: int = 30000) -> bool:
        """Flush all queued events synchronously."""
        self._flush_queue()
        results = []
        for sink in self._sinks:
            try:
                results.append(sink.force_flush(timeout_ms=timeout_ms))
            except Exception:
                logger.exception("Sink %r raised during force_flush", sink)
                results.append(False)
        return all(results)

    @property
    def dropped_count(self) -> int:
        """Number of events dropped due to queue overflow."""
        return self._dropped_count

    def _run(self) -> None:
        """Background worker loop."""
        while True:
            with self._condition:
                if self._stopped:
                    break
                self._condition.wait(timeout=self._schedule_delay_s)
                if self._stopped and len(self._queue) == 0:
                    break

            self._flush_queue()

    def _flush_queue(self) -> None:
        """Drain the queue and dispatch batches to sinks."""
        while True:
            batch = self._drain_batch()
            if not batch:
                break
            self._dispatch_batch(batch)

    def _drain_batch(self) -> list[GovernanceEvent]:
        """Pop up to max_batch_size events from the queue."""
        with self._lock:
            batch: list[GovernanceEvent] = []
            while self._queue and len(batch) < self._max_batch_size:
                batch.append(self._queue.popleft())
            return batch

    def _dispatch_batch(self, events: list[GovernanceEvent]) -> None:
        """Fan out a batch to all registered sinks with error isolation."""
        now = time.monotonic()
        for sink in self._sinks:
            state = self._sink_states.get(id(sink))
            if state is None:
                state = _SinkState()
                self._sink_states[id(sink)] = state

            # Circuit breaker: skip if open
            if state.circuit_open_until > now:
                continue

            try:
                result = sink.emit(events)
                if result == SinkExportResult.SUCCESS:
                    state.consecutive_failures = 0
                elif result == SinkExportResult.FAILURE:
                    state.consecutive_failures += 1
                    logger.warning(
                        "Sink %r returned FAILURE for %d events", sink, len(events)
                    )
                # DROPPED is intentional, no failure count
            except Exception:
                state.consecutive_failures += 1
                logger.exception(
                    "Sink %r raised unexpectedly for %d events", sink, len(events)
                )

            # Trip circuit breaker if threshold reached
            if state.consecutive_failures >= self._cb_threshold:
                state.circuit_open_until = now + self._cb_cooldown_s
                logger.warning(
                    "Circuit breaker OPEN for sink %r after %d consecutive failures, "
                    "cooldown %.0fs",
                    sink,
                    state.consecutive_failures,
                    self._cb_cooldown_s,
                )
                state.consecutive_failures = 0


class AuditBackendSinkAdapter(GovernanceEventSinkBase):
    """Adapts an existing AuditBackend to the GovernanceEventSink interface.

    Bridges the legacy AuditBackend (write/flush) protocol to the new
    batch-oriented GovernanceEventSink, allowing existing backends
    (JsonlFileBackend, OTelLogsBackend, StderrAuditBackend) to be used
    with GovernanceEventProcessor without modification.
    """

    def __init__(self, backend: Any) -> None:
        self._backend = backend

    def emit(self, events: Sequence[GovernanceEvent]) -> SinkExportResult:
        """Convert GovernanceEvents to AuditEntry and write to backend."""
        from agent_os.audit_logger import AuditEntry

        try:
            for event in events:
                entry = AuditEntry(
                    timestamp=event.occurred_at,
                    event_type=event.kind.value,
                    agent_id=event.agent_id,
                    action=event.action,
                    decision=event.decision,
                    reason=event.reason,
                    latency_ms=event.latency_ms,
                    metadata={
                        "event_id": event.event_id,
                        "schema_version": event.schema_version,
                        "severity": event.severity,
                        **({"resource": event.resource} if event.resource else {}),
                        **({"policy_name": event.policy_name} if event.policy_name else {}),
                        **({"session_id": event.session_id} if event.session_id else {}),
                        **event.attributes,
                    },
                )
                self._backend.write(entry)
            self._backend.flush()
            return SinkExportResult.SUCCESS
        except Exception:
            logger.exception("AuditBackendSinkAdapter failed")
            return SinkExportResult.FAILURE

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        try:
            self._backend.flush()
        except Exception:
            logger.exception("AuditBackendSinkAdapter flush failed during shutdown")
        return True
