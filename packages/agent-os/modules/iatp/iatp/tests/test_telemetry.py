# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for IATP telemetry module.
"""
import shutil
import tempfile
from pathlib import Path

import pytest

from iatp.models import (
    AgentCapabilities,
    CapabilityManifest,
    PrivacyContract,
    RetentionPolicy,
)
from iatp.telemetry import FlightRecorder, TraceIDGenerator


@pytest.fixture
def temp_log_dir():
    """Create a temporary directory for logs."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir)


def test_trace_id_generation():
    """Test trace ID generation."""
    trace_id1 = TraceIDGenerator.generate()
    trace_id2 = TraceIDGenerator.generate()

    assert trace_id1 != trace_id2
    assert len(trace_id1) > 0
    assert len(trace_id2) > 0


def test_create_tracing_context():
    """Test creating a tracing context."""
    trace_id = TraceIDGenerator.generate()
    context = TraceIDGenerator.create_context(trace_id, "test-agent")

    assert context.trace_id == trace_id
    assert context.agent_id == "test-agent"
    assert context.parent_trace_id is None
    assert context.timestamp is not None


def test_flight_recorder_log_request(temp_log_dir):
    """Test logging a request."""
    recorder = FlightRecorder(log_dir=temp_log_dir)
    trace_id = "test-trace-123"

    recorder.log_request(
        trace_id=trace_id,
        agent_id="test-agent",
        payload={"task": "test"},
        quarantined=False
    )

    logs = recorder.get_trace_logs(trace_id)
    assert len(logs) == 1
    assert logs[0]["type"] == "request"
    assert logs[0]["trace_id"] == trace_id
    assert logs[0]["agent_id"] == "test-agent"


def test_flight_recorder_log_response(temp_log_dir):
    """Test logging a response."""
    recorder = FlightRecorder(log_dir=temp_log_dir)
    trace_id = "test-trace-456"

    recorder.log_response(
        trace_id=trace_id,
        agent_id="test-agent",
        response={"status": "success"},
        status_code=200,
        latency_ms=123.45
    )

    logs = recorder.get_trace_logs(trace_id)
    assert len(logs) == 1
    assert logs[0]["type"] == "response"
    assert logs[0]["status_code"] == 200
    assert logs[0]["latency_ms"] == 123.45


def test_flight_recorder_log_error(temp_log_dir):
    """Test logging an error."""
    recorder = FlightRecorder(log_dir=temp_log_dir)
    trace_id = "test-trace-789"

    recorder.log_error(
        trace_id=trace_id,
        agent_id="test-agent",
        error="Connection timeout",
        details={"timeout": 30}
    )

    logs = recorder.get_trace_logs(trace_id)
    assert len(logs) == 1
    assert logs[0]["type"] == "error"
    assert logs[0]["error"] == "Connection timeout"
    assert logs[0]["details"]["timeout"] == 30


def test_flight_recorder_log_blocked(temp_log_dir):
    """Test logging a blocked request."""
    recorder = FlightRecorder(log_dir=temp_log_dir)
    trace_id = "test-trace-blocked"

    manifest = CapabilityManifest(
        agent_id="test-agent",
        capabilities=AgentCapabilities(),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.FOREVER
        )
    )

    recorder.log_blocked_request(
        trace_id=trace_id,
        agent_id="test-agent",
        payload={"sensitive": "data"},
        reason="Privacy violation",
        manifest=manifest
    )

    logs = recorder.get_trace_logs(trace_id)
    assert len(logs) == 1
    assert logs[0]["type"] == "blocked"
    assert logs[0]["reason"] == "Privacy violation"


def test_flight_recorder_multiple_logs(temp_log_dir):
    """Test multiple log entries for the same trace."""
    recorder = FlightRecorder(log_dir=temp_log_dir)
    trace_id = "test-trace-multi"

    recorder.log_request(trace_id, "agent1", {"req": 1}, quarantined=False)
    recorder.log_response(trace_id, "agent1", {"resp": 1}, 200, 100.0)
    recorder.log_request(trace_id, "agent2", {"req": 2}, quarantined=False)
    recorder.log_response(trace_id, "agent2", {"resp": 2}, 200, 150.0)

    logs = recorder.get_trace_logs(trace_id)
    assert len(logs) == 4
    assert logs[0]["type"] == "request"
    assert logs[1]["type"] == "response"
    assert logs[2]["type"] == "request"
    assert logs[3]["type"] == "response"


def test_flight_recorder_sensitive_data_scrubbed(temp_log_dir):
    """Test that sensitive data is scrubbed in logs."""
    recorder = FlightRecorder(log_dir=temp_log_dir)
    trace_id = "test-trace-sensitive"

    recorder.log_request(
        trace_id=trace_id,
        agent_id="test-agent",
        payload={"card": "4532-1234-5678-9010"},
        quarantined=False
    )

    logs = recorder.get_trace_logs(trace_id)
    payload_str = str(logs[0]["payload"])
    assert "4532-1234-5678-9010" not in payload_str
    assert "[CREDIT_CARD_REDACTED]" in payload_str


def test_flight_recorder_nonexistent_trace(temp_log_dir):
    """Test retrieving logs for a nonexistent trace."""
    recorder = FlightRecorder(log_dir=temp_log_dir)
    logs = recorder.get_trace_logs("nonexistent-trace")
    assert logs == []
