# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry Logs backend for :class:`GovernanceAuditLogger`.

Emits governance audit entries as structured OTel LogRecords via the
`Logs Bridge API <https://opentelemetry.io/docs/specs/otel/logs/bridge-api/>`_,
routing them to any OTLP-compatible collector (Datadog, Splunk, Grafana
Loki, New Relic, etc.).

Follows the same opt-in import pattern used by :mod:`agent_os._mcp_metrics`
and :mod:`agentmesh.observability.otel_sdk` — all methods are safe no-ops
when ``opentelemetry`` is not installed.

Usage::

    from agent_os.audit_logger import GovernanceAuditLogger
    from agent_os.otel_audit_backend import OTelLogsBackend

    audit = GovernanceAuditLogger()
    audit.add_backend(OTelLogsBackend())
    audit.log_decision(agent_id="a1", action="search", decision="allow")
"""

from __future__ import annotations

import logging
from typing import Any

from agent_os.audit_logger import AuditEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Conditional OpenTelemetry imports  (same pattern as _mcp_metrics.py)
# ---------------------------------------------------------------------------

_HAS_OTEL_LOGS = False
_LogRecord: Any = None
_SeverityNumber: Any = None

try:
    from opentelemetry._logs import (
        LogRecord as _LR,
    )
    from opentelemetry._logs import (
        SeverityNumber as _SN,
    )
    from opentelemetry._logs import (
        get_logger_provider,
    )

    _HAS_OTEL_LOGS = True
    _LogRecord = _LR
    _SeverityNumber = _SN
except ImportError:  # pragma: no cover
    pass

# ---------------------------------------------------------------------------
# Semantic attribute names  (aligned with otel_governance.py conventions)
# ---------------------------------------------------------------------------

ATTR_EVENT_DOMAIN = "event.domain"
ATTR_EVENT_NAME = "event.name"
ATTR_AGENT_ID = "agt.agent.id"
ATTR_EVENT_TYPE = "agt.audit.event_type"
ATTR_ACTION = "agt.audit.action"
ATTR_DECISION = "agt.audit.decision"
ATTR_REASON = "agt.audit.reason"
ATTR_LATENCY_MS = "agt.audit.latency_ms"


class OTelLogsBackend:
    """Emit governance audit entries as OTel LogRecords.

    Conforms to the :class:`~agent_os.audit_logger.AuditBackend` protocol.
    When ``opentelemetry-sdk`` is not installed, ``write()`` and ``flush()``
    are safe no-ops.

    Args:
        logger_name: OTel logger instrument name.  Defaults to
            ``"agent_os.governance.audit"`` — the same namespace
            used by AGT's existing OTel instrumentation.
        logger_provider: An explicit ``LoggerProvider``.  When *None*
            the global provider is used (via
            ``get_logger_provider()``).
        service_name: Informational service name written into the log
            resource.  Only used when *logger_provider* is not supplied.

    Example::

        from agent_os.otel_audit_backend import OTelLogsBackend

        backend = OTelLogsBackend()
        assert backend.enabled  # True when opentelemetry is installed
    """

    def __init__(
        self,
        logger_name: str = "agent_os.governance.audit",
        logger_provider: Any = None,
        service_name: str = "agent-governance-toolkit",
    ) -> None:
        self._enabled = _HAS_OTEL_LOGS
        self._otel_logger: Any = None
        self._service_name = service_name

        if not _HAS_OTEL_LOGS:
            logger.debug(
                "opentelemetry-sdk not installed — OTelLogsBackend disabled. "
                "Install with: pip install opentelemetry-sdk opentelemetry-api"
            )
            return

        try:
            provider = logger_provider or get_logger_provider()
            self._otel_logger = provider.get_logger(logger_name)
        except Exception:  # pragma: no cover — defensive opt-in path
            logger.debug(
                "Failed to initialise OTel logger — OTelLogsBackend disabled",
                exc_info=True,
            )
            self._enabled = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Return ``True`` when OTel Logs SDK is available and initialised."""
        return self._enabled and self._otel_logger is not None

    # ------------------------------------------------------------------
    # AuditBackend Protocol
    # ------------------------------------------------------------------

    def write(self, entry: AuditEntry) -> None:
        """Emit an :class:`AuditEntry` as an OTel ``LogRecord``.

        Attributes follow the same ``agt.*`` namespace used by
        :mod:`agentmesh.observability.otel_governance` and
        :mod:`agentmesh.governance.otel_observability`.
        """
        if not self.enabled:
            return

        attributes = {
            ATTR_EVENT_DOMAIN: "agent_os.governance",
            ATTR_EVENT_NAME: "audit_entry",
            ATTR_AGENT_ID: entry.agent_id,
            ATTR_EVENT_TYPE: entry.event_type,
            ATTR_ACTION: entry.action,
            ATTR_DECISION: entry.decision,
            ATTR_LATENCY_MS: entry.latency_ms,
        }

        if entry.reason:
            attributes[ATTR_REASON] = entry.reason

        # Promote non-empty metadata keys as top-level attributes so
        # they are searchable in the observability backend.
        for key, value in (entry.metadata or {}).items():
            attributes[f"agt.audit.meta.{key}"] = str(value)

        self._otel_logger.emit(
            _LogRecord(
                body=entry.to_json(),
                severity_text="INFO",
                severity_number=_SeverityNumber.INFO,
                attributes=attributes,
            )
        )

    def flush(self) -> None:
        """Flush is a no-op — the OTLP exporter handles batching."""
        pass
