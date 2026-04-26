# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Telemetry and flight recorder for request/response tracking.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from iatp.models import CapabilityManifest, QuarantineSession, TracingContext
from iatp.security import PrivacyScrubber


def _get_utc_timestamp() -> str:
    """Get current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class FlightRecorder:
    """
    Records all requests and responses for audit and debugging.
    This is the "black box" that helps trace what happened.
    """

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or Path("/tmp/iatp_logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.scrubber = PrivacyScrubber()

    def log_request(
        self,
        trace_id: str,
        agent_id: str,
        payload: Dict[str, Any],
        manifest: Optional[CapabilityManifest] = None,
        quarantined: bool = False
    ) -> None:
        """Log an outgoing request."""
        log_entry = {
            "type": "request",
            "trace_id": trace_id,
            "timestamp": _get_utc_timestamp(),
            "agent_id": agent_id,
            "payload": self.scrubber.scrub_payload(payload),
            "quarantined": quarantined,
            "manifest": manifest.model_dump() if manifest else None
        }
        self._write_log(trace_id, log_entry)

    def log_response(
        self,
        trace_id: str,
        agent_id: str,
        response: Dict[str, Any],
        status_code: int,
        latency_ms: float
    ) -> None:
        """Log a response from an agent."""
        log_entry = {
            "type": "response",
            "trace_id": trace_id,
            "timestamp": _get_utc_timestamp(),
            "agent_id": agent_id,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "response": self.scrubber.scrub_payload(response)
        }
        self._write_log(trace_id, log_entry)

    def log_error(
        self,
        trace_id: str,
        agent_id: str,
        error: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log an error during request processing."""
        log_entry = {
            "type": "error",
            "trace_id": trace_id,
            "timestamp": _get_utc_timestamp(),
            "agent_id": agent_id,
            "error": error,
            "details": details or {}
        }
        self._write_log(trace_id, log_entry)

    def log_blocked_request(
        self,
        trace_id: str,
        agent_id: str,
        payload: Dict[str, Any],
        reason: str,
        manifest: Optional[CapabilityManifest] = None
    ) -> None:
        """Log a request that was blocked by security policies."""
        log_entry = {
            "type": "blocked",
            "trace_id": trace_id,
            "timestamp": _get_utc_timestamp(),
            "agent_id": agent_id,
            "payload": self.scrubber.scrub_payload(payload),
            "reason": reason,
            "manifest": manifest.model_dump() if manifest else None
        }
        self._write_log(trace_id, log_entry)

    def log_user_override(
        self,
        trace_id: str,
        agent_id: str,
        warning: str,
        quarantine_session: QuarantineSession
    ) -> None:
        """Log when a user overrides a security warning."""
        log_entry = {
            "type": "user_override",
            "trace_id": trace_id,
            "timestamp": _get_utc_timestamp(),
            "agent_id": agent_id,
            "warning": warning,
            "quarantine_session": quarantine_session.model_dump()
        }
        self._write_log(trace_id, log_entry)

    def _write_log(self, trace_id: str, entry: Dict[str, Any]) -> None:
        """Write a log entry to the flight recorder."""
        log_file = self.log_dir / f"{trace_id}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def get_trace_logs(self, trace_id: str) -> List[Dict[str, Any]]:
        """Retrieve all log entries for a given trace ID."""
        log_file = self.log_dir / f"{trace_id}.jsonl"
        if not log_file.exists():
            return []

        logs = []
        with open(log_file) as f:
            for line in f:
                if line.strip():
                    logs.append(json.loads(line))
        return logs


class TraceIDGenerator:
    """Generates unique trace IDs for distributed tracing."""

    @staticmethod
    def generate() -> str:
        """Generate a new trace ID."""
        return str(uuid.uuid4())

    @staticmethod
    def create_context(trace_id: str, agent_id: str, parent_trace_id: Optional[str] = None) -> TracingContext:
        """Create a tracing context."""
        return TracingContext(
            trace_id=trace_id,
            parent_trace_id=parent_trace_id,
            timestamp=_get_utc_timestamp(),
            agent_id=agent_id
        )
