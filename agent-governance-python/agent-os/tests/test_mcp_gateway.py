# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the MCP Security Gateway (Public Preview)."""

from __future__ import annotations

import pytest

import threading
import time

from agent_os.integrations.base import GovernancePolicy, PatternType
from agent_os.mcp_gateway import (
    ApprovalStatus,
    AuditEntry,
    GatewayConfig,
    MCPGateway,
)
from agent_os.mcp_protocols import InMemoryAuditSink, InMemoryRateLimitStore


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_policy(**overrides) -> GovernancePolicy:
    """Create a GovernancePolicy with sensible test defaults."""
    defaults = dict(
        name="test",
        max_tool_calls=5,
        allowed_tools=[],
        blocked_patterns=[],
        require_human_approval=False,
        log_all_calls=True,
    )
    defaults.update(overrides)
    return GovernancePolicy(**defaults)


class _FakeMetrics:
    def __init__(self) -> None:
        self.decisions: list[dict[str, object]] = []
        self.rate_limit_hits: list[dict[str, str]] = []

    def record_decision(self, **kwargs) -> None:
        self.decisions.append(kwargs)

    def record_threats_detected(self, count: int, *, tool_name: str, server_name: str) -> None:
        return None

    def record_rate_limit_hit(self, *, agent_id: str, tool_name: str) -> None:
        self.rate_limit_hits.append({"agent_id": agent_id, "tool_name": tool_name})

    def record_scan(self, *, operation: str, tool_name: str, server_name: str) -> None:
        return None


class _ConcurrentProbeRateLimitStore:
    def __init__(self) -> None:
        self._value = 0
        self._value_lock = threading.Lock()
        self._active = 0
        self._active_lock = threading.Lock()
        self.max_concurrent_gets = 0

    def get_bucket(self, _agent_id: str) -> int:
        with self._active_lock:
            self._active += 1
            self.max_concurrent_gets = max(self.max_concurrent_gets, self._active)
        time.sleep(0.01)
        with self._value_lock:
            value = self._value
        with self._active_lock:
            self._active -= 1
        return value

    def set_bucket(self, _agent_id: str, bucket: int) -> None:
        with self._value_lock:
            self._value = bucket


# ── Tool allow / deny filtering ─────────────────────────────────────────────


class TestToolFiltering:
    def test_allow_when_allowlist_empty(self):
        """All tools allowed when allowed_tools is empty."""
        gw = MCPGateway(_make_policy(), enable_builtin_sanitization=False)
        allowed, reason = gw.intercept_tool_call("a1", "any_tool", {})
        assert allowed is True

    def test_allow_when_tool_in_allowlist(self):
        policy = _make_policy(allowed_tools=["read_file", "web_search"])
        gw = MCPGateway(policy, enable_builtin_sanitization=False)
        allowed, _ = gw.intercept_tool_call("a1", "read_file", {})
        assert allowed is True

    def test_deny_when_tool_not_in_allowlist(self):
        policy = _make_policy(allowed_tools=["read_file"])
        gw = MCPGateway(policy, enable_builtin_sanitization=False)
        allowed, reason = gw.intercept_tool_call("a1", "delete_file", {})
        assert allowed is False
        assert "not on the allow list" in reason

    def test_deny_list_takes_precedence(self):
        policy = _make_policy(allowed_tools=["read_file", "exec_cmd"])
        gw = MCPGateway(policy, denied_tools=["exec_cmd"], enable_builtin_sanitization=False)
        allowed, reason = gw.intercept_tool_call("a1", "exec_cmd", {})
        assert allowed is False
        assert "deny list" in reason

    def test_deny_list_blocks_even_without_allowlist(self):
        gw = MCPGateway(
            _make_policy(), denied_tools=["evil_tool"], enable_builtin_sanitization=False
        )
        allowed, reason = gw.intercept_tool_call("a1", "evil_tool", {})
        assert allowed is False


# ── Parameter pattern blocking ──────────────────────────────────────────────


class TestParameterSanitization:
    def test_blocked_substring_pattern(self):
        policy = _make_policy(blocked_patterns=["password"])
        gw = MCPGateway(policy, enable_builtin_sanitization=False)
        allowed, reason = gw.intercept_tool_call("a1", "t", {"q": "show password"})
        assert allowed is False
        assert "blocked pattern" in reason

    def test_blocked_regex_pattern(self):
        policy = _make_policy(
            blocked_patterns=[(r"rm\s+-rf", PatternType.REGEX)],
        )
        gw = MCPGateway(policy, enable_builtin_sanitization=False)
        allowed, reason = gw.intercept_tool_call("a1", "t", {"cmd": "rm -rf /"})
        assert allowed is False

    def test_builtin_ssn_detection(self):
        gw = MCPGateway(_make_policy())
        allowed, reason = gw.intercept_tool_call("a1", "t", {"data": "SSN: 123-45-6789"})
        assert allowed is False
        assert "dangerous pattern" in reason

    def test_builtin_credit_card_detection(self):
        gw = MCPGateway(_make_policy())
        allowed, reason = gw.intercept_tool_call("a1", "t", {"cc": "4111-1111-1111-1111"})
        assert allowed is False

    def test_builtin_command_substitution_detection(self):
        gw = MCPGateway(_make_policy())
        allowed, _ = gw.intercept_tool_call("a1", "t", {"x": "$(whoami)"})
        assert allowed is False

    def test_clean_params_pass(self):
        gw = MCPGateway(_make_policy())
        allowed, _ = gw.intercept_tool_call("a1", "t", {"q": "hello world"})
        assert allowed is True

    def test_builtin_sanitization_can_be_disabled(self):
        gw = MCPGateway(_make_policy(), enable_builtin_sanitization=False)
        allowed, _ = gw.intercept_tool_call("a1", "t", {"data": "123-45-6789"})
        assert allowed is True


# ── Rate limit enforcement ──────────────────────────────────────────────────


class TestRateLimiting:
    def test_allows_up_to_budget(self):
        gw = MCPGateway(
            _make_policy(max_tool_calls=3),
            enable_builtin_sanitization=False,
        )
        for _ in range(3):
            allowed, _ = gw.intercept_tool_call("a1", "t", {})
            assert allowed is True

    def test_blocks_after_budget_exceeded(self):
        gw = MCPGateway(
            _make_policy(max_tool_calls=2),
            enable_builtin_sanitization=False,
        )
        gw.intercept_tool_call("a1", "t", {})
        gw.intercept_tool_call("a1", "t", {})
        allowed, reason = gw.intercept_tool_call("a1", "t", {})
        assert allowed is False
        assert "exceeded call budget" in reason

    def test_separate_budgets_per_agent(self):
        gw = MCPGateway(
            _make_policy(max_tool_calls=1),
            enable_builtin_sanitization=False,
        )
        a1, _ = gw.intercept_tool_call("agent-a", "t", {})
        a2, _ = gw.intercept_tool_call("agent-b", "t", {})
        assert a1 is True
        assert a2 is True

    def test_reset_agent_budget(self):
        gw = MCPGateway(
            _make_policy(max_tool_calls=1),
            enable_builtin_sanitization=False,
        )
        gw.intercept_tool_call("a1", "t", {})
        gw.reset_agent_budget("a1")
        allowed, _ = gw.intercept_tool_call("a1", "t", {})
        assert allowed is True

    def test_get_agent_call_count(self):
        gw = MCPGateway(_make_policy(), enable_builtin_sanitization=False)
        assert gw.get_agent_call_count("x") == 0
        gw.intercept_tool_call("x", "t", {})
        assert gw.get_agent_call_count("x") == 1

    def test_rate_limit_counting_is_serialized(self):
        policy = _make_policy(max_tool_calls=1)
        store = _ConcurrentProbeRateLimitStore()
        gw = MCPGateway(
            policy,
            enable_builtin_sanitization=False,
            rate_limit_store=store,
        )
        barrier = threading.Barrier(8)
        results: list[bool] = []
        result_lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            allowed, _ = gw.intercept_tool_call("shared-agent", "read_file", {})
            with result_lock:
                results.append(allowed)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert results.count(True) == 1
        assert results.count(False) == 7
        assert store.max_concurrent_gets == 1


# ── Audit log recording ────────────────────────────────────────────────────


class TestAuditLog:
    def test_records_allowed_call(self):
        gw = MCPGateway(_make_policy(), enable_builtin_sanitization=False)
        gw.intercept_tool_call("a1", "read_file", {"path": "/tmp/x"})
        log = gw.audit_log
        assert len(log) == 1
        assert log[0].allowed is True
        assert log[0].agent_id == "a1"
        assert log[0].tool_name == "read_file"
        assert log[0].parameters == {"path": "/tmp/x"}

    def test_records_blocked_call(self):
        policy = _make_policy(allowed_tools=["safe_tool"])
        gw = MCPGateway(policy, enable_builtin_sanitization=False)
        gw.intercept_tool_call("a1", "bad_tool", {})
        log = gw.audit_log
        assert len(log) == 1
        assert log[0].allowed is False

    def test_audit_entry_to_dict(self):
        gw = MCPGateway(_make_policy(), enable_builtin_sanitization=False)
        gw.intercept_tool_call("a1", "t", {"k": "v"})
        d = gw.audit_log[0].to_dict()
        assert isinstance(d, dict)
        assert "timestamp" in d
        assert d["agent_id"] == "a1"

    def test_multiple_calls_recorded_in_order(self):
        gw = MCPGateway(_make_policy(), enable_builtin_sanitization=False)
        gw.intercept_tool_call("a1", "t1", {})
        gw.intercept_tool_call("a1", "t2", {})
        gw.intercept_tool_call("a2", "t3", {})
        log = gw.audit_log
        assert len(log) == 3
        assert [e.tool_name for e in log] == ["t1", "t2", "t3"]

    def test_audit_redaction_and_store_injection(self):
        audit_sink = InMemoryAuditSink()
        rate_limit_store = InMemoryRateLimitStore()
        gw = MCPGateway(
            _make_policy(),
            enable_builtin_sanitization=False,
            audit_sink=audit_sink,
            rate_limit_store=rate_limit_store,
            clock=lambda: 123.0,
        )

        allowed, _ = gw.intercept_tool_call(
            "a1",
            "read_file",
            {"token": "sk-test_abcdefghijklmnopqrstuvwxyz"},
        )

        assert allowed is True
        assert gw.audit_log[0].timestamp == 123.0
        assert gw.audit_log[0].parameters == {"token": "[REDACTED]"}
        assert audit_sink.entries()[0]["parameters"] == {"token": "[REDACTED]"}
        assert rate_limit_store.get_bucket("a1") == 1


# ── Human approval workflow ─────────────────────────────────────────────────


class TestHumanApproval:
    def test_pending_when_no_callback(self):
        gw = MCPGateway(
            _make_policy(require_human_approval=True),
            enable_builtin_sanitization=False,
        )
        allowed, reason = gw.intercept_tool_call("a1", "t", {})
        assert allowed is False
        assert "Awaiting human approval" in reason

    def test_approved_via_callback(self):
        def approve(*_args):
            return ApprovalStatus.APPROVED

        gw = MCPGateway(
            _make_policy(require_human_approval=True),
            approval_callback=approve,
            enable_builtin_sanitization=False,
        )
        allowed, reason = gw.intercept_tool_call("a1", "t", {})
        assert allowed is True
        assert "Approved" in reason

    def test_denied_via_callback(self):
        def deny(*_args):
            return ApprovalStatus.DENIED

        gw = MCPGateway(
            _make_policy(require_human_approval=True),
            approval_callback=deny,
            enable_builtin_sanitization=False,
        )
        allowed, reason = gw.intercept_tool_call("a1", "t", {})
        assert allowed is False
        assert "denied" in reason.lower()

    def test_sensitive_tool_triggers_approval(self):
        gw = MCPGateway(
            _make_policy(),
            sensitive_tools=["deploy"],
            enable_builtin_sanitization=False,
        )
        allowed, reason = gw.intercept_tool_call("a1", "deploy", {})
        assert allowed is False
        assert "approval" in reason.lower()

    def test_non_sensitive_tool_skips_approval(self):
        gw = MCPGateway(
            _make_policy(),
            sensitive_tools=["deploy"],
            enable_builtin_sanitization=False,
        )
        allowed, _ = gw.intercept_tool_call("a1", "read_file", {})
        assert allowed is True

    def test_approval_status_recorded_in_audit(self):
        def approve(*_args):
            return ApprovalStatus.APPROVED

        gw = MCPGateway(
            _make_policy(),
            sensitive_tools=["deploy"],
            approval_callback=approve,
            enable_builtin_sanitization=False,
        )
        gw.intercept_tool_call("a1", "deploy", {})
        assert gw.audit_log[0].approval_status == ApprovalStatus.APPROVED


# ── wrap_mcp_server ─────────────────────────────────────────────────────────


class TestWrapMCPServer:
    def test_returns_gateway_config(self):
        policy = _make_policy(
            allowed_tools=["read_file"],
            max_tool_calls=20,
        )
        cfg = MCPGateway.wrap_mcp_server(
            {"host": "localhost", "port": 8080},
            policy,
            denied_tools=["exec"],
            sensitive_tools=["deploy"],
        )
        assert isinstance(cfg, GatewayConfig)
        assert cfg.server_config == {"host": "localhost", "port": 8080}
        assert cfg.policy_name == "test"
        assert cfg.allowed_tools == ["read_file"]
        assert cfg.denied_tools == ["exec"]
        assert cfg.sensitive_tools == ["deploy"]
        assert cfg.rate_limit == 20

    def test_does_not_mutate_original_config(self):
        original = {"host": "localhost"}
        MCPGateway.wrap_mcp_server(original, _make_policy())
        assert original == {"host": "localhost"}


class TestMetrics:
    def test_records_decision_stage(self):
        metrics = _FakeMetrics()
        gw = MCPGateway(
            _make_policy(),
            enable_builtin_sanitization=False,
            metrics=metrics,
        )

        allowed, _ = gw.intercept_tool_call("agent-1", "read_file", {})

        assert allowed is True
        assert metrics.decisions[0]["stage"] == "allowed"
        assert metrics.decisions[0]["allowed"] is True

    def test_records_rate_limit_hits(self):
        metrics = _FakeMetrics()
        gw = MCPGateway(
            _make_policy(max_tool_calls=1),
            enable_builtin_sanitization=False,
            metrics=metrics,
        )

        gw.intercept_tool_call("agent-1", "read_file", {})
        allowed, _ = gw.intercept_tool_call("agent-1", "read_file", {})

        assert allowed is False
        assert metrics.decisions[-1]["stage"] == "rate_limit"
        assert metrics.rate_limit_hits == [{"agent_id": "agent-1", "tool_name": "read_file"}]
