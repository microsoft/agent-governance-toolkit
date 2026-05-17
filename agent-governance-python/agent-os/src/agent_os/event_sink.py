# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pluggable GovernanceEventSink — provider interface (SPI) for governance event routing.

Defines the sink interface and two reference implementations:

* :class:`StdoutEventSink` — writes JSON to stdout; suitable for development and CI.
* :class:`OtlpEventSink` — emits via the OpenTelemetry Logs Bridge API; compatible with
  Defender for Cloud, Microsoft Sentinel, Splunk, Datadog, Honeycomb, Dynatrace, and any
  other OTLP-capable backend.

Architecture
------------
AGT emits structured, signed governance events; the *sink* routes them to external
observability and enforcement backends.  This project does not implement OS-level
enforcement — that is the responsibility of the backend (Defender, Falco, Tetragon, etc.).

Event Categories (aligned with CloudEvents + OTEL semantic conventions):

* ``policy.decision``  — policy allow/deny/warn/require-approval outcome
* ``policy.breach``    — policy violation detected
* ``identity.assertion`` — agent identity claim or verification result
* ``tool.invocation``  — tool call intercepted before execution
* ``sandbox.event``    — sandbox lifecycle event (create, execute, destroy)
* ``audit.chain``      — hash-chain audit entry emitted

Usage::

    import asyncio
    from agent_os.event_sink import StdoutEventSink, SignedGovernanceEvent, GovernanceEventCategory

    async def main():
        sink = StdoutEventSink()
        event = SignedGovernanceEvent.build(
            category=GovernanceEventCategory.POLICY_DECISION,
            source="did:agentmesh:agent-1",
            subject="tool:file_write",
            data={"decision": "deny", "reason": "path outside allowed dirs"},
        )
        await sink.emit(event)

    asyncio.run(main())
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Conditional OpenTelemetry imports  (same opt-in pattern as otel_audit_backend.py)
# ---------------------------------------------------------------------------

_HAS_OTEL_LOGS = False
_LogRecord: Any = None
_SeverityNumber: Any = None

try:
    from opentelemetry._logs import (
        LogRecord as _LR,
        SeverityNumber as _SN,
        get_logger_provider,
    )

    _HAS_OTEL_LOGS = True
    _LogRecord = _LR
    _SeverityNumber = _SN
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Event categories
# ---------------------------------------------------------------------------


class GovernanceEventCategory(str, Enum):
    """Categories of governance events routed through the sink SPI.

    Values follow the ``ai.agentmesh.<category>`` CloudEvents type convention.
    """

    POLICY_DECISION = "policy.decision"
    POLICY_BREACH = "policy.breach"
    IDENTITY_ASSERTION = "identity.assertion"
    TOOL_INVOCATION = "tool.invocation"
    SANDBOX_EVENT = "sandbox.event"
    AUDIT_CHAIN = "audit.chain"

    def cloud_event_type(self) -> str:
        """Return the full CloudEvents ``type`` string."""
        return f"ai.agentmesh.{self.value}"


# ---------------------------------------------------------------------------
# Canonical signed event envelope
# ---------------------------------------------------------------------------


@dataclass
class SignedGovernanceEvent:
    """CloudEvents 1.0 envelope with optional tamper-evidence signature.

    Fields follow the `CloudEvents specification <https://github.com/cloudevents/spec>`_.
    The ``signature`` extension field is a caller-supplied MAC or digest over the
    canonical form::

        "{type}\\n{source}\\n{time}\\n{id}\\n{data_json}"

    Signing is performed by the caller via the ``sign_fn`` parameter of
    :meth:`build` — this module does not import any cryptographic primitives
    directly.  To use HMAC-SHA256, supply a ``sign_fn`` that wraps your
    preferred crypto library (e.g. ``hmac`` from the standard library or
    ``agent_mesh.crypto``).

    When no ``sign_fn`` is supplied the ``signature`` field is left empty.

    Attributes:
        specversion: Always ``"1.0"`` (CloudEvents version).
        id: Unique event identifier (UUID v4).
        type: CloudEvents type, e.g. ``"ai.agentmesh.policy.decision"``.
        source: Agent DID or service URI.
        time: ISO 8601 UTC timestamp.
        datacontenttype: Always ``"application/json"``.
        subject: Tool name, resource, or other context-specific subject.
        data: Event-specific payload dictionary.
        signature: Caller-supplied signature (empty when unsigned).
    """

    specversion: str = "1.0"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""
    source: str = ""
    time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    datacontenttype: str = "application/json"
    subject: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    signature: str = ""

    @classmethod
    def build(
        cls,
        category: GovernanceEventCategory,
        source: str,
        subject: str = "",
        data: dict[str, Any] | None = None,
        sign_fn: Callable[[str], str] | None = None,
    ) -> "SignedGovernanceEvent":
        """Construct and optionally sign a :class:`SignedGovernanceEvent`.

        Args:
            category: The governance event category.
            source: Agent DID or service URI (e.g. ``"did:agentmesh:agent-1"``).
            subject: Tool name, resource, or subject string.
            data: Arbitrary event payload.  Defaults to an empty dict.
            sign_fn: Optional callable ``(canonical: str) -> str`` that returns
                a hex-encoded signature for the canonical event string.  When
                ``None`` (the default) the event is unsigned (``signature`` is
                left empty).  Use standard-library ``hmac``/``hashlib`` or
                the ``agent_mesh.crypto`` module to create this function.

        Returns:
            A fully constructed :class:`SignedGovernanceEvent`.
        """
        now = datetime.now(timezone.utc).isoformat()
        event_id = str(uuid.uuid4())
        event_type = category.cloud_event_type()
        payload_data = data or {}
        data_json = json.dumps(payload_data, sort_keys=True, separators=(",", ":"))

        sig = ""
        if sign_fn is not None:
            canonical = f"{event_type}\n{source}\n{now}\n{event_id}\n{data_json}"
            sig = sign_fn(canonical)

        return cls(
            id=event_id,
            type=event_type,
            source=source,
            time=now,
            subject=subject,
            data=payload_data,
            signature=sig,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise as a plain dict (CloudEvents JSON representation)."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialise as a JSON string."""
        return json.dumps(self.to_dict(), default=str)

    def verify_signature(self, verify_fn: Callable[[str, str], bool]) -> bool:
        """Verify this event's signature using a caller-supplied function.

        Args:
            verify_fn: Callable ``(canonical: str, signature: str) -> bool``
                that returns ``True`` when the signature is valid.  Use
                ``hmac.compare_digest`` from the standard library (or
                ``agent_mesh.crypto``) to build a constant-time comparison.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
            Always returns ``False`` when the event has no signature.
        """
        if not self.signature:
            return False
        data_json = json.dumps(self.data, sort_keys=True, separators=(",", ":"))
        canonical = f"{self.type}\n{self.source}\n{self.time}\n{self.id}\n{data_json}"
        return verify_fn(canonical, self.signature)


# ---------------------------------------------------------------------------
# Sink protocol
# ---------------------------------------------------------------------------


class GovernanceEventSink(Protocol):
    """Provider interface (SPI) for governance event routing.

    One async method — :meth:`emit` — takes a :class:`SignedGovernanceEvent`
    and forwards it to the configured backend.  Mirrors the
    :class:`~agent_os.sandbox_provider.SandboxProvider` shape for consistency.

    Reference implementations:

    * :class:`StdoutEventSink` — JSON to stdout (dev / CI)
    * :class:`OtlpEventSink` — OTLP Logs Bridge (Defender, Sentinel, Splunk, …)

    Custom sinks can integrate with any SIEM, XDR, or enforcement platform::

        class MySplunkSink:
            async def emit(self, event: SignedGovernanceEvent) -> None:
                await splunk_client.ingest(event.to_json())
    """

    async def emit(self, event: SignedGovernanceEvent) -> None:
        """Emit a governance event to the configured backend.

        Args:
            event: The signed governance event to forward.
        """
        ...


# ---------------------------------------------------------------------------
# Reference sink: Stdout
# ---------------------------------------------------------------------------


class StdoutEventSink:
    """Reference sink that writes governance events as JSON lines to stdout.

    Suitable for development, CI pipelines, and container environments where
    stdout is collected by a log aggregator (Fluentd, Vector, Logstash, etc.).

    Example::

        sink = StdoutEventSink()
        await sink.emit(event)  # → {"specversion":"1.0","type":"ai.agentmesh.policy.decision",...}
    """

    async def emit(self, event: SignedGovernanceEvent) -> None:
        """Write the event as a single JSON line to ``sys.stdout``."""
        print(event.to_json(), file=sys.stdout, flush=True)


# ---------------------------------------------------------------------------
# Reference sink: OTLP
# ---------------------------------------------------------------------------


class OtlpEventSink:
    """Reference sink that emits governance events via the OTel Logs Bridge API.

    Routes events to any OTLP-compatible backend:
    Microsoft Defender for Cloud, Microsoft Sentinel, Splunk, Datadog, Honeycomb,
    Dynatrace, Grafana Loki, New Relic, etc.

    When ``opentelemetry-sdk`` is not installed, :meth:`emit` is a safe no-op.

    Args:
        logger_name: OTel logger instrument name.  Defaults to
            ``"agent_os.governance.events"``.
        logger_provider: An explicit ``LoggerProvider``.  When ``None``
            the global provider is used (via ``get_logger_provider()``).
        service_name: Informational service name written into log resource.

    Example::

        from agent_os.event_sink import OtlpEventSink
        sink = OtlpEventSink()
        await sink.emit(event)
    """

    # OTEL attribute namespace (consistent with otel_audit_backend.py)
    _ATTR_EVENT_DOMAIN = "event.domain"
    _ATTR_EVENT_NAME = "event.name"
    _ATTR_EVENT_CATEGORY = "agt.governance.event.category"
    _ATTR_EVENT_SOURCE = "agt.governance.event.source"
    _ATTR_EVENT_SUBJECT = "agt.governance.event.subject"
    _ATTR_EVENT_ID = "agt.governance.event.id"
    _ATTR_EVENT_TYPE = "agt.governance.event.type"
    _ATTR_SIGNED = "agt.governance.event.signed"

    def __init__(
        self,
        logger_name: str = "agent_os.governance.events",
        logger_provider: Any = None,
        service_name: str = "agent-governance-toolkit",
    ) -> None:
        self._enabled = _HAS_OTEL_LOGS
        self._otel_logger: Any = None
        self._service_name = service_name

        if not _HAS_OTEL_LOGS:
            logger.debug(
                "opentelemetry-sdk not installed — OtlpEventSink disabled. "
                "Install with: pip install opentelemetry-sdk opentelemetry-api"
            )
            return

        try:
            provider = logger_provider or get_logger_provider()
            self._otel_logger = provider.get_logger(logger_name)
        except Exception:  # pragma: no cover — defensive opt-in path
            logger.debug(
                "Failed to initialise OTel logger — OtlpEventSink disabled",
                exc_info=True,
            )
            self._enabled = False

    @property
    def enabled(self) -> bool:
        """``True`` when the OTel Logs SDK is available and initialised."""
        return self._enabled and self._otel_logger is not None

    async def emit(self, event: SignedGovernanceEvent) -> None:
        """Emit the event as an OTel ``LogRecord``.

        Attributes follow the ``agt.governance.*`` namespace so they are
        searchable across all AGT OTel instrumentation.  The full CloudEvents
        JSON envelope is written to the log body.
        """
        if not self.enabled:
            return

        attributes = {
            self._ATTR_EVENT_DOMAIN: "agent_os.governance",
            self._ATTR_EVENT_NAME: "governance_event",
            self._ATTR_EVENT_CATEGORY: event.type,
            self._ATTR_EVENT_SOURCE: event.source,
            self._ATTR_EVENT_SUBJECT: event.subject,
            self._ATTR_EVENT_ID: event.id,
            self._ATTR_EVENT_TYPE: event.type,
            self._ATTR_SIGNED: bool(event.signature),
        }

        self._otel_logger.emit(
            _LogRecord(
                body=event.to_json(),
                severity_text="INFO",
                severity_number=_SeverityNumber.INFO,
                attributes=attributes,
            )
        )
