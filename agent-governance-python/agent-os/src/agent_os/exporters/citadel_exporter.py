# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Citadel Audit Exporter

Exports AGT governance events to Azure Event Hub and Application Insights,
enabling Citadel's observability pipeline to include agent-level governance data.

Events include correlation IDs linking AGT decisions to APIM request traces
and Foundry execution traces, enabling unified observability dashboards.

Usage:
    from agent_os.exporters import CitadelAuditExporter

    exporter = CitadelAuditExporter.from_env()
    exporter.export_event(event)
    await exporter.flush()
    await exporter.close()
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class GovernanceEventType(str, Enum):
    """Types of governance events exported to Citadel."""

    POLICY_DECISION = "policy_decision"
    POLICY_VIOLATION = "policy_violation"
    TRUST_SCORE_CHANGE = "trust_score_change"
    ACTION_INTERCEPTED = "action_intercepted"
    BUNDLE_LOADED = "bundle_loaded"


class Decision(str, Enum):
    """Outcome of a policy evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    FLAG = "flag"


@dataclass
class CorrelationContext:
    """Correlation IDs tying together traces across systems.

    Attributes:
        apim_request_id: The APIM gateway request ID (from x-ms-request-id header).
        foundry_trace_id: The Foundry Control Plane trace ID (OpenTelemetry).
        agt_decision_id: The AGT policy decision ID.
        session_id: Optional agent session/conversation ID.
    """

    apim_request_id: str = ""
    foundry_trace_id: str = ""
    agt_decision_id: str = ""
    session_id: str = ""


@dataclass
class GovernanceEvent:
    """A governance event to be exported to Citadel's observability pipeline.

    Attributes:
        event_type: Category of governance event.
        timestamp: ISO 8601 timestamp.
        agent_id: The governed agent's identifier.
        action: The action being evaluated.
        decision: Allow/deny/flag outcome.
        policy_name: Which policy was evaluated.
        policy_bundle_id: The policy bundle version.
        trust_score: Current trust score (0-1000).
        correlation: Cross-system correlation IDs.
        hash_chain_prev: Previous hash in the tamper-evidence chain.
        hash_chain_current: Current hash after this event.
        detail: Human-readable explanation of the decision.
        metadata: Additional context.
    """

    event_type: GovernanceEventType
    agent_id: str
    action: str
    decision: Decision
    policy_name: str = ""
    policy_bundle_id: str = ""
    trust_score: int = 0
    correlation: CorrelationContext = field(default_factory=CorrelationContext)
    hash_chain_prev: str = ""
    hash_chain_current: str = ""
    detail: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    )
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary for export."""
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["decision"] = self.decision.value
        return data

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class CitadelAuditExporter:
    """Exports AGT governance events to Azure Event Hub and Application Insights.

    Supports batching, async flush, and graceful degradation when Azure
    services are unavailable. Events are queued locally and retried on
    reconnection (fail-open for telemetry).

    Usage:
        exporter = CitadelAuditExporter.from_env()
        exporter.export_event(event)
        await exporter.flush()
        await exporter.close()
    """

    def __init__(
        self,
        eventhub_connection_string: str = "",
        appinsights_connection_string: str = "",
        batch_size: int = 50,
        flush_interval_seconds: int = 10,
        eventhub_name: str = "agt-governance-events",
    ) -> None:
        """Initialize the exporter.

        Args:
            eventhub_connection_string: Azure Event Hub connection string.
            appinsights_connection_string: Application Insights connection string.
            batch_size: Number of events to batch before auto-flushing.
            flush_interval_seconds: Maximum seconds between flushes.
            eventhub_name: Event Hub name for governance events.
        """
        self._eventhub_conn = eventhub_connection_string
        self._appinsights_conn = appinsights_connection_string
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._eventhub_name = eventhub_name

        self._buffer: list[GovernanceEvent] = []
        self._failed_buffer: list[GovernanceEvent] = []
        self._last_flush: float = time.time()
        self._total_exported: int = 0
        self._total_failed: int = 0

        # Lazy-initialized clients
        self._eventhub_producer: Any = None
        self._appinsights_logger: Any = None

    @classmethod
    def from_env(cls) -> CitadelAuditExporter:
        """Create an exporter from environment variables.

        Environment variables:
            CITADEL_EVENTHUB_CONNECTION_STRING: Event Hub connection string.
            CITADEL_APPINSIGHTS_CONNECTION_STRING: App Insights connection string.
            CITADEL_EVENTHUB_NAME: Event Hub name (default: agt-governance-events).
            CITADEL_EXPORT_BATCH_SIZE: Batch size (default: 50).
            CITADEL_EXPORT_FLUSH_INTERVAL: Flush interval in seconds (default: 10).
        """
        return cls(
            eventhub_connection_string=os.environ.get(
                "CITADEL_EVENTHUB_CONNECTION_STRING", ""
            ),
            appinsights_connection_string=os.environ.get(
                "CITADEL_APPINSIGHTS_CONNECTION_STRING", ""
            ),
            eventhub_name=os.environ.get(
                "CITADEL_EVENTHUB_NAME", "agt-governance-events"
            ),
            batch_size=int(os.environ.get("CITADEL_EXPORT_BATCH_SIZE", "50")),
            flush_interval_seconds=int(
                os.environ.get("CITADEL_EXPORT_FLUSH_INTERVAL", "10")
            ),
        )

    @property
    def has_eventhub(self) -> bool:
        """Whether Event Hub export is configured."""
        return bool(self._eventhub_conn)

    @property
    def has_appinsights(self) -> bool:
        """Whether Application Insights export is configured."""
        return bool(self._appinsights_conn)

    @property
    def stats(self) -> dict[str, int]:
        """Export statistics."""
        return {
            "buffered": len(self._buffer),
            "failed_pending_retry": len(self._failed_buffer),
            "total_exported": self._total_exported,
            "total_failed": self._total_failed,
        }

    def export_event(self, event: GovernanceEvent) -> None:
        """Add a governance event to the export buffer.

        Events are batched and flushed periodically or when the buffer
        reaches batch_size. Call flush() to force immediate export.

        Args:
            event: The governance event to export.
        """
        self._buffer.append(event)
        logger.debug(
            "Buffered event: %s %s -> %s (buffer: %d/%d)",
            event.event_type.value,
            event.action,
            event.decision.value,
            len(self._buffer),
            self._batch_size,
        )

        # Auto-flush if buffer is full
        if len(self._buffer) >= self._batch_size:
            # Schedule async flush if running in event loop, else log warning
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.flush())
            except RuntimeError:
                logger.debug(
                    "Buffer full (%d events), call flush() to export",
                    len(self._buffer),
                )

    async def flush(self) -> int:
        """Flush buffered events to configured destinations.

        Returns:
            Number of events successfully exported.
        """
        if not self._buffer and not self._failed_buffer:
            return 0

        # Combine current buffer with any previously failed events
        events_to_send = self._failed_buffer + self._buffer
        self._buffer = []
        self._failed_buffer = []
        self._last_flush = time.time()

        exported = 0
        failed: list[GovernanceEvent] = []

        # Export to Event Hub
        if self.has_eventhub:
            success, failures = await self._send_to_eventhub(events_to_send)
            exported += success
            failed.extend(failures)
        else:
            # Log locally as fallback
            for event in events_to_send:
                logger.info(
                    "Governance event (local): %s agent=%s action=%s decision=%s",
                    event.event_type.value,
                    event.agent_id,
                    event.action,
                    event.decision.value,
                )
                exported += 1

        # Export to Application Insights (independent of Event Hub)
        if self.has_appinsights:
            await self._send_to_appinsights(events_to_send)

        # Track failures for retry
        self._failed_buffer = failed
        self._total_exported += exported
        self._total_failed += len(failed)

        if exported > 0:
            logger.info("Flushed %d governance events to Citadel", exported)
        if failed:
            logger.warning(
                "%d events failed to export, queued for retry", len(failed)
            )

        return exported

    async def _send_to_eventhub(
        self, events: list[GovernanceEvent]
    ) -> tuple[int, list[GovernanceEvent]]:
        """Send events to Azure Event Hub.

        Returns:
            Tuple of (success_count, failed_events).
        """
        try:
            from azure.eventhub import EventData
            from azure.eventhub.aio import EventHubProducerClient
        except ImportError:
            logger.warning(
                "azure-eventhub not installed. Install with: "
                "pip install azure-eventhub"
            )
            return 0, events

        try:
            if self._eventhub_producer is None:
                self._eventhub_producer = EventHubProducerClient.from_connection_string(
                    self._eventhub_conn,
                    eventhub_name=self._eventhub_name,
                )

            async with self._eventhub_producer:
                batch = await self._eventhub_producer.create_batch()
                sent = 0
                overflow: list[GovernanceEvent] = []

                for event in events:
                    event_data = EventData(event.to_json())
                    event_data.properties = {
                        "event_type": event.event_type.value,
                        "agent_id": event.agent_id,
                        "decision": event.decision.value,
                    }
                    try:
                        batch.add(event_data)
                        sent += 1
                    except ValueError:
                        # Batch is full, send and start new batch
                        await self._eventhub_producer.send_batch(batch)
                        batch = await self._eventhub_producer.create_batch()
                        batch.add(event_data)
                        sent += 1

                if sent > 0:
                    await self._eventhub_producer.send_batch(batch)

                # Reset producer for next use
                self._eventhub_producer = None
                return sent, overflow

        except Exception as e:
            logger.error("Failed to send events to Event Hub: %s", e)
            self._eventhub_producer = None
            return 0, events

    async def _send_to_appinsights(self, events: list[GovernanceEvent]) -> None:
        """Send events to Application Insights as custom events."""
        try:
            from azure.monitor.opentelemetry.exporter import (
                AzureMonitorTraceExporter,
            )
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError:
            logger.debug(
                "azure-monitor-opentelemetry-exporter not installed. "
                "App Insights export skipped."
            )
            return

        try:
            if self._appinsights_logger is None:
                exporter = AzureMonitorTraceExporter(
                    connection_string=self._appinsights_conn
                )
                provider = TracerProvider()
                provider.add_span_processor(BatchSpanProcessor(exporter))
                self._appinsights_logger = provider.get_tracer("agt-governance")

            tracer = self._appinsights_logger
            for event in events:
                with tracer.start_as_current_span(
                    name=f"agt.{event.event_type.value}",
                    attributes={
                        "agt.agent_id": event.agent_id,
                        "agt.action": event.action,
                        "agt.decision": event.decision.value,
                        "agt.policy_name": event.policy_name,
                        "agt.trust_score": event.trust_score,
                        "agt.policy_bundle_id": event.policy_bundle_id,
                        "agt.hash_chain": event.hash_chain_current,
                        "citadel.apim_request_id": event.correlation.apim_request_id,
                        "citadel.foundry_trace_id": event.correlation.foundry_trace_id,
                    },
                ):
                    pass  # Span creation is the export mechanism

        except Exception as e:
            logger.error("Failed to send events to Application Insights: %s", e)

    async def close(self) -> None:
        """Flush remaining events and close connections."""
        await self.flush()
        if self._eventhub_producer:
            try:
                await self._eventhub_producer.close()
            except Exception:
                pass
            self._eventhub_producer = None
        logger.info(
            "Citadel exporter closed. Total exported: %d, Total failed: %d",
            self._total_exported,
            self._total_failed,
        )

    def flush_sync(self) -> int:
        """Synchronous flush for non-async contexts.

        Returns:
            Number of events exported.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Cannot run async in running loop, just log count
                count = len(self._buffer)
                logger.info(
                    "Sync flush requested in async context, %d events pending", count
                )
                return 0
            return loop.run_until_complete(self.flush())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self.flush())
            finally:
                loop.close()
