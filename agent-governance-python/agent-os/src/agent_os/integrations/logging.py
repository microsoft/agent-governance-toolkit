# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Structured JSON Logging for Agent OS

Provides structured, JSON-formatted logging for governance operations
using only Python's built-in logging module. No external dependencies.

Usage:
    from agent_os.integrations.logging import get_logger

    logger = get_logger("my_module")
    logger.policy_decision(agent_id="agent-1", action="read_file", decision="allow")
    logger.error("Something failed", error_code="E001", agent_id="agent-1")
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Optional

_EXTRA_FIELDS = (
    "agent_id",
    "action",
    "decision",
    "policy_name",
    "duration_ms",
    "request_id",
    "error_code",
)

_logger_cache: dict[str, "GovernanceLogger"] = {}
_cache_lock = threading.Lock()


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in _EXTRA_FIELDS:
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class GovernanceLogger:
    """Structured logger for governance operations.

    Thread-safe logger that outputs JSON-formatted log entries with
    contextual fields for agent governance (agent_id, action, decision, etc.).
    """

    def __init__(self, name: str = "agent_os", level: Optional[str] = None) -> None:
        self._logger = logging.getLogger(name)
        resolved_level = level or os.environ.get("AGENT_OS_LOG_LEVEL", "INFO")
        self._logger.setLevel(getattr(logging, resolved_level.upper(), logging.INFO))
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(JSONFormatter())
            self._logger.addHandler(handler)

    def _log(self, level: int, message: str, **extra: Any) -> None:
        self._logger.log(level, message, extra=extra)
        # Attach extra fields to the LogRecord via a filter-like approach
        # We need to use the internal mechanism to pass extra fields
        pass

    def _make_extra(self, **kwargs: Any) -> dict[str, Any]:
        return {k: v for k, v in kwargs.items() if v is not None}

    def policy_decision(
        self,
        agent_id: str,
        action: str,
        decision: str,
        policy_name: str = "",
        reason: str = "",
        **extra: Any,
    ) -> None:
        """Log a policy decision at INFO level."""
        msg = f"Policy decision: {decision}"
        if reason:
            msg += f" — {reason}"
        fields = self._make_extra(
            agent_id=agent_id,
            action=action,
            decision=decision,
            policy_name=policy_name or None,
            **extra,
        )
        self._logger.info(msg, extra=fields)

    def policy_violation(
        self,
        agent_id: str,
        action: str,
        policy_name: str,
        reason: str,
        **extra: Any,
    ) -> None:
        """Log a policy violation at WARNING level."""
        fields = self._make_extra(
            agent_id=agent_id,
            action=action,
            decision="deny",
            policy_name=policy_name,
            **extra,
        )
        self._logger.warning(f"Policy violation: {reason}", extra=fields)

    def budget_warning(
        self,
        agent_id: str,
        usage_pct: float,
        limit: float,
        **extra: Any,
    ) -> None:
        """Log a budget warning at WARNING level."""
        fields = self._make_extra(agent_id=agent_id, **extra)
        self._logger.warning(
            f"Budget usage at {usage_pct:.1f}% of {limit} limit",
            extra=fields,
        )

    def adapter_call(
        self,
        adapter_name: str,
        agent_id: str,
        action: str,
        duration_ms: float = 0,
        **extra: Any,
    ) -> None:
        """Log an adapter call at INFO level."""
        fields = self._make_extra(
            agent_id=agent_id,
            action=action,
            duration_ms=duration_ms or None,
            **extra,
        )
        self._logger.info(
            f"Adapter call: {adapter_name}",
            extra=fields,
        )

    def audit_event(
        self,
        agent_id: str,
        event_type: str,
        details: Optional[dict[str, Any]] = None,
        **extra: Any,
    ) -> None:
        """Log an audit event at INFO level."""
        fields = self._make_extra(agent_id=agent_id, **extra)
        msg = f"Audit: {event_type}"
        if details:
            msg += f" — {json.dumps(details)}"
        self._logger.info(msg, extra=fields)

    def error(
        self,
        message: str,
        error_code: Optional[str] = None,
        agent_id: Optional[str] = None,
        **extra: Any,
    ) -> None:
        """Log an error at ERROR level."""
        fields = self._make_extra(
            agent_id=agent_id,
            error_code=error_code,
            **extra,
        )
        self._logger.error(message, extra=fields)


def get_logger(name: str = "agent_os") -> GovernanceLogger:
    """Get or create a GovernanceLogger instance (cached per name)."""
    with _cache_lock:
        if name not in _logger_cache:
            _logger_cache[name] = GovernanceLogger(name)
        return _logger_cache[name]
