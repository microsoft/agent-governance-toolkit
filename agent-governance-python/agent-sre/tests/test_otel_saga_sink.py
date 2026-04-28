# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the OTelSpanSink adapter."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent_sre.integrations.otel.saga_sink import OTelSpanSink


class TestOTelSpanSink:
    def _make_mock_trace_exporter(self) -> MagicMock:
        """Create a mock TraceExporter with export_span_simple."""
        mock = MagicMock()
        mock.export_span_simple = MagicMock(return_value=MagicMock())
        return mock

    def test_otel_span_attributes(self):
        """Verify saga attributes are set on the OTel span."""
        mock_exporter = self._make_mock_trace_exporter()
        sink = OTelSpanSink(trace_exporter=mock_exporter, agent_id="agent-42")

        attrs = {
            "agent.saga.id": "saga-123",
            "agent.saga.step_id": "step-1",
            "agent.saga.step_action": "validate",
            "agent.saga.state": "ok",
        }

        sink.record_span(
            name="saga.step.validate",
            start_time=1000.0,
            end_time=1002.5,
            attributes=attrs,
            status="ok",
        )

        mock_exporter.export_span_simple.assert_called_once()
        call_kwargs = mock_exporter.export_span_simple.call_args
        passed_attrs = call_kwargs.kwargs.get("attributes") or call_kwargs[1].get("attributes")

        # Check saga-specific attributes were forwarded
        assert passed_attrs["agent.saga.id"] == "saga-123"
        assert passed_attrs["agent.saga.step_action"] == "validate"
        assert passed_attrs["agent.id"] == "agent-42"

    def test_span_timing(self):
        """Verify start/end time are passed correctly (TraceExporter converts to ns)."""
        mock_exporter = self._make_mock_trace_exporter()
        sink = OTelSpanSink(trace_exporter=mock_exporter, agent_id="agent-1")

        sink.record_span(
            name="saga.step.deploy",
            start_time=1700000000.0,
            end_time=1700000002.5,
            attributes={"agent.saga.id": "s1"},
            status="ok",
        )

        call_kwargs = mock_exporter.export_span_simple.call_args
        # extract positional or keyword args
        kw = call_kwargs.kwargs if call_kwargs.kwargs else {}
        assert kw.get("start_time") == 1700000000.0
        assert kw.get("end_time") == 1700000002.5

    def test_error_status_mapping(self):
        """Error status maps to SpanStatus.ERROR."""
        mock_exporter = self._make_mock_trace_exporter()
        sink = OTelSpanSink(trace_exporter=mock_exporter, agent_id="agent-1")

        sink.record_span(
            name="saga.step.fail",
            start_time=1000.0,
            end_time=1001.0,
            attributes={"agent.saga.id": "s1"},
            status="error",
        )

        call_kwargs = mock_exporter.export_span_simple.call_args
        from agent_sre.replay.capture import SpanStatus
        assert call_kwargs.kwargs.get("status") == SpanStatus.ERROR

    def test_spans_exported_counter(self):
        """spans_exported increments on each record_span call."""
        mock_exporter = self._make_mock_trace_exporter()
        sink = OTelSpanSink(trace_exporter=mock_exporter, agent_id="agent-1")

        assert sink.spans_exported == 0

        sink.record_span(
            name="test",
            start_time=0.0,
            end_time=1.0,
            attributes={},
            status="ok",
        )
        assert sink.spans_exported == 1

        sink.record_span(
            name="test2",
            start_time=1.0,
            end_time=2.0,
            attributes={},
            status="ok",
        )
        assert sink.spans_exported == 2
