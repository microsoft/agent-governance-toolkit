# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for structured JSON logging module."""

import json
import logging
import os
import threading

import pytest

from agent_os.integrations.logging import (
    GovernanceLogger,
    JSONFormatter,
    get_logger,
    _logger_cache,
    _cache_lock,
)


@pytest.fixture(autouse=True)
def _clean_loggers():
    """Reset logger cache and handlers between tests."""
    with _cache_lock:
        _logger_cache.clear()
    # Remove any handlers added during tests to avoid duplicate output
    for name in ("agent_os", "test_mod", "test_thread", "test_env", "test_exc"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
    yield
    for name in ("agent_os", "test_mod", "test_thread", "test_env", "test_exc"):
        lg = logging.getLogger(name)
        lg.handlers.clear()


def _capture(logger: GovernanceLogger) -> list:
    """Attach a handler that captures formatted JSON strings."""
    records: list[str] = []
    handler = logging.Handler()
    handler.setFormatter(JSONFormatter())
    handler.emit = lambda record: records.append(handler.format(record))  # type: ignore[assignment]
    logger._logger.addHandler(handler)
    return records


# -- JSONFormatter ----------------------------------------------------------

class TestJSONFormatter:
    def test_basic_format(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello", args=(), exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["message"] == "hello"
        assert data["logger"] == "test"
        assert data["timestamp"].endswith("Z")

    def test_extra_fields(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="", lineno=0,
            msg="warn", args=(), exc_info=None,
        )
        record.agent_id = "a-1"  # type: ignore[attr-defined]
        record.action = "read"  # type: ignore[attr-defined]
        output = formatter.format(record)
        data = json.loads(output)
        assert data["agent_id"] == "a-1"
        assert data["action"] == "read"

    def test_exception_included(self):
        import sys
        formatter = JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="err", args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "boom" in data["exception"]


# -- GovernanceLogger -------------------------------------------------------

class TestGovernanceLogger:
    def test_policy_decision(self):
        logger = GovernanceLogger("test_mod")
        captured = _capture(logger)
        logger.policy_decision(
            agent_id="agent-1", action="write_file",
            decision="allow", policy_name="default",
        )
        assert len(captured) == 1
        data = json.loads(captured[0])
        assert data["level"] == "INFO"
        assert data["agent_id"] == "agent-1"
        assert data["action"] == "write_file"
        assert data["decision"] == "allow"
        assert data["policy_name"] == "default"

    def test_policy_decision_with_reason(self):
        logger = GovernanceLogger("test_mod")
        captured = _capture(logger)
        logger.policy_decision(
            agent_id="a1", action="x", decision="deny", reason="too risky",
        )
        data = json.loads(captured[0])
        assert "too risky" in data["message"]

    def test_policy_violation(self):
        logger = GovernanceLogger("test_mod")
        captured = _capture(logger)
        logger.policy_violation(
            agent_id="agent-2", action="delete_db",
            policy_name="safety", reason="destructive action",
        )
        data = json.loads(captured[0])
        assert data["level"] == "WARNING"
        assert data["decision"] == "deny"
        assert "destructive action" in data["message"]

    def test_budget_warning(self):
        logger = GovernanceLogger("test_mod")
        captured = _capture(logger)
        logger.budget_warning(agent_id="a-1", usage_pct=85.3, limit=100.0)
        data = json.loads(captured[0])
        assert data["level"] == "WARNING"
        assert data["agent_id"] == "a-1"
        assert "85.3%" in data["message"]

    def test_adapter_call(self):
        logger = GovernanceLogger("test_mod")
        captured = _capture(logger)
        logger.adapter_call(
            adapter_name="langchain", agent_id="a-1",
            action="invoke", duration_ms=42,
        )
        data = json.loads(captured[0])
        assert data["level"] == "INFO"
        assert data["duration_ms"] == 42
        assert "langchain" in data["message"]

    def test_audit_event(self):
        logger = GovernanceLogger("test_mod")
        captured = _capture(logger)
        logger.audit_event(
            agent_id="a-1", event_type="checkpoint",
            details={"step": 5},
        )
        data = json.loads(captured[0])
        assert data["level"] == "INFO"
        assert "checkpoint" in data["message"]
        assert '"step": 5' in data["message"]

    def test_audit_event_no_details(self):
        logger = GovernanceLogger("test_mod")
        captured = _capture(logger)
        logger.audit_event(agent_id="a-1", event_type="start")
        data = json.loads(captured[0])
        assert "start" in data["message"]

    def test_error(self):
        logger = GovernanceLogger("test_mod")
        captured = _capture(logger)
        logger.error("disk full", error_code="E500", agent_id="a-1")
        data = json.loads(captured[0])
        assert data["level"] == "ERROR"
        assert data["error_code"] == "E500"
        assert data["agent_id"] == "a-1"
        assert data["message"] == "disk full"

    def test_error_minimal(self):
        logger = GovernanceLogger("test_mod")
        captured = _capture(logger)
        logger.error("oops")
        data = json.loads(captured[0])
        assert data["level"] == "ERROR"
        assert "agent_id" not in data
        assert "error_code" not in data


# -- get_logger / caching / env var ----------------------------------------

class TestGetLogger:
    def test_returns_governance_logger(self):
        logger = get_logger("test_mod")
        assert isinstance(logger, GovernanceLogger)

    def test_caches_by_name(self):
        a = get_logger("test_mod")
        b = get_logger("test_mod")
        assert a is b

    def test_different_names_different_instances(self):
        a = get_logger("test_mod")
        b = get_logger("test_env")
        assert a is not b


class TestLogLevel:
    def test_respects_env_var(self, monkeypatch):
        monkeypatch.setenv("AGENT_OS_LOG_LEVEL", "WARNING")
        logger = GovernanceLogger("test_env")
        assert logger._logger.level == logging.WARNING

    def test_explicit_level_overrides_env(self, monkeypatch):
        monkeypatch.setenv("AGENT_OS_LOG_LEVEL", "DEBUG")
        logger = GovernanceLogger("test_env", level="ERROR")
        assert logger._logger.level == logging.ERROR

    def test_default_level_is_info(self, monkeypatch):
        monkeypatch.delenv("AGENT_OS_LOG_LEVEL", raising=False)
        logger = GovernanceLogger("test_env")
        assert logger._logger.level == logging.INFO


# -- Thread safety ----------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_logging(self):
        logger = GovernanceLogger("test_thread")
        captured = _capture(logger)
        errors: list[Exception] = []

        def worker(tid: int) -> None:
            try:
                for i in range(20):
                    logger.policy_decision(
                        agent_id=f"agent-{tid}",
                        action=f"action-{i}",
                        decision="allow",
                    )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(captured) == 80
        # Every captured record should be valid JSON
        for raw in captured:
            data = json.loads(raw)
            assert "agent_id" in data

    def test_get_logger_thread_safe(self):
        results: list[GovernanceLogger] = []
        errors: list[Exception] = []

        def worker() -> None:
            try:
                results.append(get_logger("test_thread"))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert all(r is results[0] for r in results)
