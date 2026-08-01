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

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, Sequence, runtime_checkable
from urllib.parse import quote

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1"

# CloudEvents 1.0 signature extension attributes (lowercase per CE naming rules).
_CE_SIGNATURE_ATTR = "agtsignature"
_CE_SIGNATURE_ALG_ATTR = "agtsignaturealg"
_CE_SIGNATURE_ALG = "HMAC-SHA256"

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


# CloudEvents 1.0 `type` mapping (reverse-DNS). Agent OS is a distinct event
# PRODUCER from Agent Mesh, so it uses its own `ai.agentos.*` namespace rather
# than the `ai.agentmesh.*` namespace ADR-0021 reserves for mesh audit entries
# (to avoid producer collisions). The envelope shape follows CloudEvents 1.0 /
# AUDIT-COMPLIANCE-1.0 §20.4; the `type` strings are Agent OS-specific because
# GovernanceEventKind is finer-grained than the mesh audit-entry taxonomy.
_GOVERNANCE_CE_TYPE_MAP: dict[GovernanceEventKind, str] = {
    GovernanceEventKind.POLICY_CHECK: "ai.agentos.policy.check",
    GovernanceEventKind.POLICY_VIOLATION: "ai.agentos.policy.violation",
    GovernanceEventKind.TOOL_CALL_BLOCKED: "ai.agentos.tool.blocked",
    GovernanceEventKind.PROMPT_INJECTION_DETECTED: "ai.agentos.prompt_injection.detected",
    GovernanceEventKind.IDENTITY_VERIFIED: "ai.agentos.identity.verified",
    GovernanceEventKind.IDENTITY_REJECTED: "ai.agentos.identity.rejected",
    GovernanceEventKind.RESOURCE_ACCESS: "ai.agentos.resource.access",
    GovernanceEventKind.ESCALATION_REQUESTED: "ai.agentos.escalation.requested",
    GovernanceEventKind.CHECKPOINT_CREATED: "ai.agentos.checkpoint.created",
    GovernanceEventKind.ANOMALY_DETECTED: "ai.agentos.anomaly.detected",
    GovernanceEventKind.MCP_TOOL_POISONING: "ai.agentos.mcp.tool_poisoning",
    GovernanceEventKind.CONTENT_VIOLATION: "ai.agentos.content.violation",
}


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

    def to_cloudevent(
        self,
        source: str | None = None,
        *,
        signer: "GovernanceEventSigner | None" = None,
    ) -> dict[str, Any]:
        """Serialize as a CloudEvents 1.0 envelope, optionally HMAC-signed.

        Implements the documented export contract (ADR-0021, AUDIT-COMPLIANCE-1.0
        §20.4): the required attributes ``specversion``/``id``/``source``/``type``
        plus ``time``/``datacontenttype``/``data``. When a ``signer`` is provided
        the returned envelope is tamper-evident, carrying the ``agtsignaturealg``
        and ``agtsignature`` extension attributes.

        Args:
            source: CloudEvents ``source`` URI-reference identifying the emitter.
                When omitted it is derived from ``agent_did`` or ``agent_id``.
            signer: Optional :class:`GovernanceEventSigner`; when present the
                envelope is signed.

        Returns:
            A CloudEvents 1.0 envelope as a JSON-serializable dict.

        Raises:
            ValueError: If no non-empty ``source`` can be resolved.
        """
        resolved_source = source or self.agent_did or (
            f"/agent-os/agent/{quote(self.agent_id, safe='')}"
            if self.agent_id
            else ""
        )
        if not resolved_source:
            raise ValueError(
                "CloudEvents 'source' must be a non-empty URI-reference; pass "
                "source= or set agent_did/agent_id on the event"
            )

        ce_type = _GOVERNANCE_CE_TYPE_MAP.get(
            self.kind, f"ai.agentos.governance.{self.kind.value}"
        )

        # Custom attributes are spread FIRST so the authoritative event fields
        # (action/decision/agent_id/...) always win. A signed CloudEvent must not
        # let a free-form attribute key shadow the real, immutable event field —
        # otherwise a valid signature could cover a record that misrepresents the
        # decision or actor.
        data: dict[str, Any] = {
            **self.attributes,
            "action": self.action,
            "decision": self.decision,
            "reason": self.reason,
            "severity": self.severity,
            "latency_ms": self.latency_ms,
            **({"resource": self.resource} if self.resource else {}),
            **({"policy_name": self.policy_name} if self.policy_name else {}),
            **({"agent_id": self.agent_id} if self.agent_id else {}),
            **({"agent_did": self.agent_did} if self.agent_did else {}),
        }

        cloudevent: dict[str, Any] = {
            "specversion": "1.0",
            "id": self.event_id,
            "type": ce_type,
            "source": resolved_source,
            "time": self.occurred_at,
            "datacontenttype": "application/json",
            "data": data,
            "schemaversion": self.schema_version,
        }
        if self.session_id:
            cloudevent["sessionid"] = self.session_id
        if self.trace_id:
            cloudevent["traceid"] = self.trace_id
        if self.span_id:
            cloudevent["spanid"] = self.span_id
        if self.parent_span_id:
            cloudevent["parentspanid"] = self.parent_span_id

        if signer is not None:
            cloudevent = signer.sign(cloudevent)
        return cloudevent


class GovernanceEventSigner:
    """HMAC-SHA256 signer/verifier for CloudEvents governance envelopes.

    Produces tamper-evident audit records: the signature covers the canonical
    (sorted-key) CloudEvent including the algorithm attribute, so both payload
    and algorithm tampering are detected. The signing key is never logged.
    """

    def __init__(self, signing_key: bytes) -> None:
        """Initialize the signer.

        Args:
            signing_key: Shared secret used for HMAC. Must be at least 32 bytes.
        """
        if not signing_key or len(signing_key) < 32:
            raise ValueError("signing_key must be at least 32 bytes")
        self._signing_key = signing_key

    @staticmethod
    def generate_key() -> bytes:
        """Return a new cryptographically random 32-byte signing key."""
        return secrets.token_bytes(32)

    def sign(self, cloudevent: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of *cloudevent* with signature extension attributes."""
        signed = {k: v for k, v in cloudevent.items() if k != _CE_SIGNATURE_ATTR}
        signed[_CE_SIGNATURE_ALG_ATTR] = _CE_SIGNATURE_ALG
        signed[_CE_SIGNATURE_ATTR] = self._compute(signed)
        return signed

    def verify(self, cloudevent: dict[str, Any]) -> bool:
        """Return True when *cloudevent*'s signature is present and valid."""
        signature = cloudevent.get(_CE_SIGNATURE_ATTR)
        if not isinstance(signature, str):
            return False
        if cloudevent.get(_CE_SIGNATURE_ALG_ATTR) != _CE_SIGNATURE_ALG:
            return False
        payload = {k: v for k, v in cloudevent.items() if k != _CE_SIGNATURE_ATTR}
        return hmac.compare_digest(self._compute(payload), signature)

    def _compute(self, cloudevent_without_signature: dict[str, Any]) -> str:
        canonical = json.dumps(
            cloudevent_without_signature,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        digest = hmac.new(
            self._signing_key, canonical.encode("utf-8"), hashlib.sha256
        ).digest()
        return base64.b64encode(digest).decode("ascii")


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
        self._queue: deque[GovernanceEvent] = deque()
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._stopped = False
        self._submitted_count = 0
        self._delivered_count = 0
        self._failed_count = 0
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

        Non-blocking. Every event is accounted: if the queue is full the oldest
        event is dropped (DROP_OLDEST policy) and counted; if the processor has
        already stopped the event is counted as dropped rather than silently
        discarded, so ``submitted == delivered + failed + dropped``.
        """
        with self._condition:
            self._submitted_count += 1
            if self._stopped:
                # Fail-closed accounting: do not silently swallow post-shutdown events.
                self._dropped_count += 1
                return
            if len(self._queue) >= self._max_queue_size:
                self._queue.popleft()
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
    def submitted_count(self) -> int:
        """Total events accepted by ``on_event`` (before queueing decisions)."""
        with self._lock:
            return self._submitted_count

    @property
    def delivered_count(self) -> int:
        """Events in a batch that at least one sink emitted successfully."""
        with self._lock:
            return self._delivered_count

    @property
    def failed_count(self) -> int:
        """Events dispatched to sinks where no sink succeeded (all failed/skipped)."""
        with self._lock:
            return self._failed_count

    @property
    def dropped_count(self) -> int:
        """Events never dispatched: queue overflow or discarded after shutdown."""
        with self._lock:
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
        """Fan out a batch to all registered sinks with error isolation.

        Terminal accounting for the batch (each event counted exactly once):
          - delivered: at least one sink emitted the batch successfully;
          - failed:    no success, but at least one sink FAILED, raised, or was
                       skipped by an open circuit breaker (non-delivery);
          - dropped:   no success and no failure — every sink that ran returned
                       DROPPED (an intentional sink-side drop, e.g. sampling), or
                       there were no sinks. This keeps DROPPED out of the failure
                       count so an operator can distinguish intentional drops from
                       real delivery failures.
        """
        now = time.monotonic()
        any_success = False
        any_failure = False
        for sink in self._sinks:
            state = self._sink_states.get(id(sink))
            if state is None:
                state = _SinkState()
                self._sink_states[id(sink)] = state

            # Circuit breaker: skip if open. A skipped sink means the batch was
            # not delivered to it, so it counts toward failure (not an intentional
            # drop) unless another sink succeeds.
            if state.circuit_open_until > now:
                any_failure = True
                continue

            try:
                result = sink.emit(events)
                if result == SinkExportResult.SUCCESS:
                    any_success = True
                    state.consecutive_failures = 0
                elif result == SinkExportResult.FAILURE:
                    any_failure = True
                    state.consecutive_failures += 1
                    logger.warning(
                        "Sink %r returned FAILURE for %d events", sink, len(events)
                    )
                elif result == SinkExportResult.DROPPED:
                    logger.info(
                        "Sink %r intentionally DROPPED %d events", sink, len(events)
                    )
            except Exception:
                any_failure = True
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

        # Account every dispatched event exactly once. "delivered if any sink
        # succeeds" still hides a partial fan-out failure when a DIFFERENT sink
        # fails alongside a success; that remains observable via the per-sink
        # FAILURE / circuit-breaker logs above.
        with self._lock:
            if any_success:
                self._delivered_count += len(events)
            elif any_failure:
                self._failed_count += len(events)
            else:
                self._dropped_count += len(events)


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


class StdoutGovernanceSink(GovernanceEventSinkBase):
    """Sink that writes signed CloudEvents as JSON lines to a stream.

    Emits one CloudEvents 1.0 envelope per line (newline-delimited JSON), the
    common shape ingested by SIEM/log collectors. When a signer is provided the
    envelopes are tamper-evident.
    """

    def __init__(
        self,
        source: str = "/agent-os",
        *,
        signer: GovernanceEventSigner | None = None,
        stream: Any = None,
    ) -> None:
        """Initialize the sink.

        Args:
            source: CloudEvents ``source`` URI-reference for emitted events.
            signer: Optional signer; when present envelopes are signed.
            stream: Writable text stream. Defaults to ``sys.stdout`` at emit time.
        """
        self._source = source
        self._signer = signer
        self._stream = stream

    def emit(self, events: Sequence[GovernanceEvent]) -> SinkExportResult:
        import sys

        stream = self._stream if self._stream is not None else sys.stdout
        try:
            for event in events:
                cloudevent = event.to_cloudevent(self._source, signer=self._signer)
                stream.write(json.dumps(cloudevent, sort_keys=True, default=str) + "\n")
            stream.flush()
            return SinkExportResult.SUCCESS
        except Exception:
            logger.exception("StdoutGovernanceSink failed")
            return SinkExportResult.FAILURE


class OTLPGovernanceSink(GovernanceEventSinkBase):
    """Sink that exports signed CloudEvents via OpenTelemetry (OTLP).

    Thin wrapper over :class:`agent_os.otel_audit_backend.OTelLogsBackend`, which
    routes structured records to any OTLP-compatible collector. It follows the
    same opt-in pattern: when ``opentelemetry`` is not installed the backend is a
    safe no-op, and ``emit`` returns ``DROPPED`` (not ``SUCCESS``) so the
    processor does not count un-exported events as delivered.
    """

    def __init__(
        self,
        source: str = "/agent-os",
        *,
        signer: GovernanceEventSigner | None = None,
        backend: Any = None,
    ) -> None:
        """Initialize the sink.

        Args:
            source: CloudEvents ``source`` URI-reference for emitted events.
            signer: Optional signer; when present the embedded CloudEvent is signed.
            backend: Optional ``OTelLogsBackend``; one is created when omitted.
        """
        self._source = source
        self._signer = signer
        if backend is None:
            from agent_os.otel_audit_backend import OTelLogsBackend

            backend = OTelLogsBackend()
        self._backend = backend

    @property
    def enabled(self) -> bool:
        """Return True when the underlying OTel backend is active."""
        return bool(getattr(self._backend, "enabled", False))

    def emit(self, events: Sequence[GovernanceEvent]) -> SinkExportResult:
        from agent_os.audit_logger import AuditEntry

        # Honest accounting: if the OTel backend is a no-op (opentelemetry not
        # installed / not initialized), nothing is exported — report DROPPED so
        # the processor does not credit these events as delivered.
        if not self.enabled:
            return SinkExportResult.DROPPED

        try:
            for event in events:
                cloudevent = event.to_cloudevent(self._source, signer=self._signer)
                # Promote the same searchable metadata keys the
                # AuditBackendSinkAdapter exposes (OTelLogsBackend turns each into
                # an `agt.audit.meta.*` attribute) IN ADDITION to the full signed
                # CloudEvent envelope, so severity/resource/policy_name/session_id
                # stay individually queryable in the collector.
                metadata: dict[str, Any] = {
                    "event_id": event.event_id,
                    "schema_version": event.schema_version,
                    "severity": event.severity,
                    "cloudevent": json.dumps(cloudevent, sort_keys=True, default=str),
                }
                if event.resource:
                    metadata["resource"] = event.resource
                if event.policy_name:
                    metadata["policy_name"] = event.policy_name
                if event.session_id:
                    metadata["session_id"] = event.session_id
                entry = AuditEntry(
                    timestamp=event.occurred_at,
                    event_type=event.kind.value,
                    agent_id=event.agent_id,
                    action=event.action,
                    decision=event.decision,
                    reason=event.reason,
                    latency_ms=event.latency_ms,
                    metadata=metadata,
                )
                self._backend.write(entry)
            self._backend.flush()
            return SinkExportResult.SUCCESS
        except Exception:
            logger.exception("OTLPGovernanceSink failed")
            return SinkExportResult.FAILURE

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        try:
            self._backend.flush()
        except Exception:
            logger.exception("OTLPGovernanceSink flush failed during shutdown")
        return True
