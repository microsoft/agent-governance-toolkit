# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry-friendly metrics helpers for MCP governance components."""

from __future__ import annotations

import logging
from typing import Any, Protocol

logger = logging.getLogger(__name__)

try:
    from opentelemetry import metrics as _otel_metrics

    _HAS_OTEL = True
except ImportError:  # pragma: no cover
    _otel_metrics = None  # type: ignore[assignment]
    _HAS_OTEL = False


class MCPMetricsRecorder(Protocol):
    """Protocol for MCP governance metric emission."""

    def record_decision(
        self,
        *,
        allowed: bool,
        agent_id: str,
        tool_name: str,
        stage: str,
    ) -> None:
        """Record an allow or deny decision."""

    def record_threats_detected(
        self,
        count: int,
        *,
        tool_name: str,
        server_name: str,
    ) -> None:
        """Record detected threats from an MCP scan."""

    def record_rate_limit_hit(self, *, agent_id: str, tool_name: str) -> None:
        """Record a rate limit rejection."""

    def record_scan(
        self,
        *,
        operation: str,
        tool_name: str,
        server_name: str,
    ) -> None:
        """Record an MCP scan invocation."""


class NoOpMCPMetrics:
    """No-op metrics recorder used when OTel is unavailable."""

    def record_decision(
        self,
        *,
        allowed: bool,
        agent_id: str,
        tool_name: str,
        stage: str,
    ) -> None:
        return None

    def record_threats_detected(
        self,
        count: int,
        *,
        tool_name: str,
        server_name: str,
    ) -> None:
        return None

    def record_rate_limit_hit(self, *, agent_id: str, tool_name: str) -> None:
        return None

    def record_scan(
        self,
        *,
        operation: str,
        tool_name: str,
        server_name: str,
    ) -> None:
        return None


class MCPMetrics(NoOpMCPMetrics):
    """MCP governance counters backed by OpenTelemetry when available."""

    def __init__(self, meter_provider: Any | None = None) -> None:
        self._enabled = _HAS_OTEL
        self._decisions = None
        self._threats_detected = None
        self._rate_limit_hits = None
        self._scans = None
        if not _HAS_OTEL:
            return

        try:
            if meter_provider is not None:
                meter = meter_provider.get_meter("agent_os.mcp", version="3.1.0")
            else:
                meter = _otel_metrics.get_meter("agent_os.mcp", version="3.1.0")

            self._decisions = meter.create_counter(
                "mcp_decisions",
                description="Total MCP gateway allow and deny decisions.",
            )
            self._threats_detected = meter.create_counter(
                "mcp_threats_detected",
                description="Threats detected by MCP scanners.",
            )
            self._rate_limit_hits = meter.create_counter(
                "mcp_rate_limit_hits",
                description="MCP requests denied by rate limiting.",
            )
            self._scans = meter.create_counter(
                "mcp_scans",
                description="MCP scan operations performed.",
            )
        except Exception:  # pragma: no cover - defensive opt-in path
            logger.debug("Failed to initialize MCP OpenTelemetry counters", exc_info=True)
            self._enabled = False

    def record_decision(
        self,
        *,
        allowed: bool,
        agent_id: str,
        tool_name: str,
        stage: str,
    ) -> None:
        if not self._enabled or self._decisions is None:
            return
        self._decisions.add(
            1,
            {
                "agent_id": agent_id,
                "tool_name": tool_name,
                "decision": "allow" if allowed else "deny",
                "stage": stage,
            },
        )

    def record_threats_detected(
        self,
        count: int,
        *,
        tool_name: str,
        server_name: str,
    ) -> None:
        if count <= 0 or not self._enabled or self._threats_detected is None:
            return
        self._threats_detected.add(
            count,
            {
                "tool_name": tool_name,
                "server_name": server_name,
            },
        )

    def record_rate_limit_hit(self, *, agent_id: str, tool_name: str) -> None:
        if not self._enabled or self._rate_limit_hits is None:
            return
        self._rate_limit_hits.add(
            1,
            {
                "agent_id": agent_id,
                "tool_name": tool_name,
            },
        )

    def record_scan(
        self,
        *,
        operation: str,
        tool_name: str,
        server_name: str,
    ) -> None:
        if not self._enabled or self._scans is None:
            return
        self._scans.add(
            1,
            {
                "operation": operation,
                "tool_name": tool_name,
                "server_name": server_name,
            },
        )
