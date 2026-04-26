# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for graceful degradation, budget policies, and audit logger."""

import json
from pathlib import Path

import pytest

from agent_os.compat import (
    TOOLKIT_AVAILABLE,
    NoOpGovernanceMiddleware,
    NoOpPolicyEvaluator,
    get_evaluator,
)
from agent_os.policies.budget import BudgetPolicy, BudgetTracker
from agent_os.audit_logger import (
    AuditEntry,
    GovernanceAuditLogger,
    InMemoryBackend,
    JsonlFileBackend,
)


class TestCompat:
    def test_noop_evaluator_allows_all(self):
        e = NoOpPolicyEvaluator()
        result = e.evaluate()
        assert result.allowed is True
        assert result.reason == "no-op"

    def test_noop_middleware_passes_through(self):
        m = NoOpGovernanceMiddleware()
        func = lambda x: x + 1
        assert m(func) is func
        assert m.wrap(func) is func

    def test_toolkit_available(self):
        assert TOOLKIT_AVAILABLE is True

    def test_get_evaluator_returns_real(self):
        e = get_evaluator()
        assert not isinstance(e, NoOpPolicyEvaluator)


class TestBudgetPolicy:
    def test_defaults_all_none(self):
        p = BudgetPolicy()
        assert p.max_tokens is None
        assert p.max_tool_calls is None

    def test_tracker_under_limits(self):
        t = BudgetTracker(BudgetPolicy(max_tokens=100, max_tool_calls=5))
        t.record_tokens(50)
        t.record_tool_call()
        assert not t.is_exceeded()
        assert t.exceeded_reasons() == []

    def test_tracker_over_tokens(self):
        t = BudgetTracker(BudgetPolicy(max_tokens=100))
        t.record_tokens(101)
        assert t.is_exceeded()
        assert "tokens" in t.exceeded_reasons()[0]

    def test_tracker_over_tool_calls(self):
        t = BudgetTracker(BudgetPolicy(max_tool_calls=3))
        for _ in range(4):
            t.record_tool_call()
        assert t.is_exceeded()

    def test_tracker_over_cost(self):
        t = BudgetTracker(BudgetPolicy(max_cost_usd=1.0))
        t.record_cost(1.50)
        assert t.is_exceeded()
        assert "$" in t.exceeded_reasons()[0]

    def test_tracker_remaining(self):
        t = BudgetTracker(BudgetPolicy(max_tokens=100))
        t.record_tokens(40)
        assert t.remaining()["tokens"] == 60

    def test_tracker_utilization(self):
        t = BudgetTracker(BudgetPolicy(max_tokens=100))
        t.record_tokens(25)
        assert t.utilization()["tokens"] == 0.25

    def test_partial_policy(self):
        t = BudgetTracker(BudgetPolicy(max_tokens=100))
        t.record_tool_call()
        assert not t.is_exceeded()
        assert t.remaining()["tool_calls"] is None


class TestAuditLogger:
    def test_entry_to_json(self):
        e = AuditEntry(event_type="test", agent_id="a1")
        j = json.loads(e.to_json())
        assert j["event_type"] == "test"
        assert j["agent_id"] == "a1"

    def test_in_memory_backend(self):
        b = InMemoryBackend()
        b.write(AuditEntry(event_type="test"))
        assert len(b.entries) == 1

    def test_logger_dispatches(self):
        audit = GovernanceAuditLogger()
        b1 = InMemoryBackend()
        b2 = InMemoryBackend()
        audit.add_backend(b1)
        audit.add_backend(b2)
        audit.log_decision(agent_id="a1", action="search", decision="allow")
        assert len(b1.entries) == 1
        assert len(b2.entries) == 1
        assert b1.entries[0].decision == "allow"

    def test_jsonl_file_backend(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        b = JsonlFileBackend(path)
        b.write(AuditEntry(event_type="test", agent_id="a1"))
        b.flush()
        b.close()
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1
        assert json.loads(lines[0])["agent_id"] == "a1"
