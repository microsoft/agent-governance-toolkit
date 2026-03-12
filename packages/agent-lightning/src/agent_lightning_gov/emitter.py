# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
FlightRecorderEmitter - Export Audit Logs to LightningStore
============================================================

Adapts Agent OS Flight Recorder logs to Agent-Lightning's
span format for unified training and audit trail.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class LightningSpan:
    """
    Span compatible with Agent-Lightning's LightningStore.

    Maps Agent OS Flight Recorder entries to the span format
    expected by Agent-Lightning's training and analysis tools.
    """
    span_id: str
    trace_id: str
    name: str
    start_time: datetime
    end_time: datetime | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "name": self.name,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "attributes": self.attributes,
            "events": self.events,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class FlightRecorderEmitter:
    """
    Emits Agent OS Flight Recorder entries to Agent-Lightning.

    This adapter enables:
    1. Complete audit trail from training to production
    2. RL algorithms learning from policy violations
    3. Compliance-friendly training logs

    Example:
        >>> from agent_os import FlightRecorder
        >>> from agent_os.integrations.agent_lightning import FlightRecorderEmitter
        >>>
        >>> recorder = FlightRecorder()
        >>> emitter = FlightRecorderEmitter(recorder)
        >>>
        >>> # Emit all logs to LightningStore
        >>> emitter.emit_to_store(store)
        >>>
        >>> # Or stream continuously
        >>> async for span in emitter.stream():
        ...     store.emit_span(span)
    """

    def __init__(
        self,
        flight_recorder: Any,  # FlightRecorder
        *,
        include_policy_checks: bool = True,
        include_signals: bool = True,
        include_tool_calls: bool = True,
        trace_id_prefix: str = "agentos",
    ):
        """
        Initialize the emitter.

        Args:
            flight_recorder: Agent OS FlightRecorder instance
            include_policy_checks: Include policy check spans
            include_signals: Include signal dispatch spans
            include_tool_calls: Include tool call spans
            trace_id_prefix: Prefix for generated trace IDs
        """
        self.recorder = flight_recorder
        self.include_policy_checks = include_policy_checks
        self.include_signals = include_signals
        self.include_tool_calls = include_tool_calls
        self.trace_id_prefix = trace_id_prefix

        self._emitted_count = 0
        self._last_position = 0

    def _convert_entry(self, entry: Any) -> LightningSpan | None:
        """Convert a Flight Recorder entry to a Lightning span."""
        entry_type = getattr(entry, 'type', getattr(entry, 'entry_type', 'unknown'))

        # Filter by entry type
        if entry_type == 'policy_check' and not self.include_policy_checks:
            return None
        if entry_type == 'signal' and not self.include_signals:
            return None
        if entry_type == 'tool_call' and not self.include_tool_calls:
            return None

        # Extract common fields
        span_id = getattr(entry, 'id', getattr(entry, 'entry_id', str(self._emitted_count)))
        timestamp = getattr(entry, 'timestamp', datetime.now(timezone.utc))
        agent_id = getattr(entry, 'agent_id', 'unknown')

        # Build attributes
        attributes = {
            "agent_os.entry_type": entry_type,
            "agent_os.agent_id": agent_id,
        }

        # Add type-specific attributes
        if entry_type == 'policy_check':
            attributes.update({
                "agent_os.policy_name": getattr(entry, 'policy_name', 'unknown'),
                "agent_os.policy_result": getattr(entry, 'result', 'unknown'),
                "agent_os.policy_violated": getattr(entry, 'violated', False),
            })
        elif entry_type == 'signal':
            attributes.update({
                "agent_os.signal_type": getattr(entry, 'signal', 'unknown'),
                "agent_os.signal_target": getattr(entry, 'target', 'unknown'),
            })
        elif entry_type == 'tool_call':
            attributes.update({
                "agent_os.tool_name": getattr(entry, 'tool_name', 'unknown'),
                "agent_os.tool_args": str(getattr(entry, 'args', {}))[:1000],  # Truncate
                "agent_os.tool_result": str(getattr(entry, 'result', None))[:1000],
            })

        # Copy any additional attributes
        if hasattr(entry, 'metadata'):
            for key, value in entry.metadata.items():
                attributes[f"agent_os.{key}"] = value

        return LightningSpan(
            span_id=str(span_id),
            trace_id=f"{self.trace_id_prefix}-{agent_id}",
            name=f"agent_os.{entry_type}",
            start_time=timestamp,
            end_time=timestamp,
            attributes=attributes,
        )

    def get_spans(self) -> list[LightningSpan]:
        """
        Get all Flight Recorder entries as Lightning spans.

        Returns:
            List of LightningSpan objects
        """
        spans = []

        # Get entries from recorder
        if hasattr(self.recorder, 'get_entries'):
            entries = self.recorder.get_entries()
        elif hasattr(self.recorder, 'entries'):
            entries = self.recorder.entries
        elif hasattr(self.recorder, 'get_logs'):
            entries = self.recorder.get_logs()
        else:
            logger.warning("Flight recorder has no recognized entry accessor")
            return []

        for entry in entries:
            span = self._convert_entry(entry)
            if span:
                spans.append(span)
                self._emitted_count += 1

        return spans

    def get_new_spans(self) -> list[LightningSpan]:
        """
        Get only new entries since last call.

        Returns:
            List of new LightningSpan objects
        """
        all_spans = self.get_spans()
        new_spans = all_spans[self._last_position:]
        self._last_position = len(all_spans)
        return new_spans

    async def stream(self) -> Iterator[LightningSpan]:
        """
        Stream spans as they are recorded.

        Yields:
            LightningSpan objects as they become available
        """
        import asyncio

        while True:
            new_spans = self.get_new_spans()
            for span in new_spans:
                yield span

            # Wait before checking again
            await asyncio.sleep(0.1)

    def emit_to_store(self, store: Any) -> int:
        """
        Emit all spans to a LightningStore.

        Args:
            store: Agent-Lightning LightningStore instance

        Returns:
            Number of spans emitted
        """
        spans = self.get_spans()

        for span in spans:
            try:
                if hasattr(store, 'emit_span'):
                    store.emit_span(span.to_dict())
                elif hasattr(store, 'add_span'):
                    store.add_span(span.to_dict())
                else:
                    logger.warning("Store has no recognized span emitter")
                    break
            except Exception as e:
                logger.error(f"Failed to emit span: {e}")

        logger.info(f"Emitted {len(spans)} spans to LightningStore")
        return len(spans)

    def export_to_file(self, filepath: str) -> int:
        """
        Export spans to a JSON file.

        Args:
            filepath: Path to output file

        Returns:
            Number of spans exported
        """
        spans = self.get_spans()

        with open(filepath, 'w') as f:
            json.dump([s.to_dict() for s in spans], f, indent=2)

        logger.info(f"Exported {len(spans)} spans to {filepath}")
        return len(spans)

    def get_violation_summary(self) -> dict[str, Any]:
        """
        Get summary of policy violations from recorded entries.

        Returns:
            Summary dictionary with violation statistics
        """
        spans = self.get_spans()

        violations = [
            s for s in spans
            if s.attributes.get("agent_os.policy_violated", False)
        ]

        policies_violated = {}
        for v in violations:
            policy = v.attributes.get("agent_os.policy_name", "unknown")
            policies_violated[policy] = policies_violated.get(policy, 0) + 1

        return {
            "total_entries": len(spans),
            "total_violations": len(violations),
            "violation_rate": len(violations) / max(len(spans), 1),
            "policies_violated": policies_violated,
        }

    def get_stats(self) -> dict[str, Any]:
        """Get emitter statistics."""
        return {
            "emitted_count": self._emitted_count,
            "last_position": self._last_position,
        }


def create_emitter(
    flight_recorder: Any,
    **kwargs: Any,
) -> FlightRecorderEmitter:
    """
    Factory function to create a FlightRecorderEmitter.

    Args:
        flight_recorder: Agent OS FlightRecorder
        **kwargs: Additional configuration

    Returns:
        Configured FlightRecorderEmitter
    """
    return FlightRecorderEmitter(flight_recorder, **kwargs)
