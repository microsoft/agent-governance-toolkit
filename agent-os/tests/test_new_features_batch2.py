# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for event bus, task outcome, diff policy, and sandbox provider."""

import pytest

from agent_os.event_bus import GovernanceEventBus, POLICY_VIOLATION, TRUST_PENALTY
from agent_os.task_outcome import TaskOutcomeRecorder
from agent_os.diff_policy import DiffPolicy, DiffFile
from agent_os.sandbox_provider import (
    SandboxConfig,
    SubprocessSandboxProvider,
    NoOpSandboxProvider,
)


class TestEventBus:
    def test_publish_subscribe(self):
        bus = GovernanceEventBus()
        received = []
        bus.subscribe("test.event", lambda e: received.append(e))
        bus.publish("test.event", agent_id="a1", key="val")
        assert len(received) == 1
        assert received[0].agent_id == "a1"
        assert received[0].data["key"] == "val"

    def test_wildcard_subscriber(self):
        bus = GovernanceEventBus()
        received = []
        bus.subscribe("*", lambda e: received.append(e))
        bus.publish("any.event")
        bus.publish("other.event")
        assert len(received) == 2

    def test_unsubscribe(self):
        bus = GovernanceEventBus()
        handler = lambda e: None
        bus.subscribe("test", handler)
        bus.unsubscribe("test", handler)
        event = bus.publish("test")
        assert event.event_type == "test"

    def test_history(self):
        bus = GovernanceEventBus()
        bus.publish("a")
        bus.publish("b")
        bus.publish("a")
        assert len(bus.get_history()) == 3
        assert len(bus.get_history("a")) == 2

    def test_handler_error_doesnt_crash(self):
        bus = GovernanceEventBus()
        bus.subscribe("test", lambda e: 1 / 0)
        event = bus.publish("test")  # Should not raise
        assert event.event_type == "test"

    def test_standard_event_types(self):
        assert POLICY_VIOLATION == "policy.violation"
        assert TRUST_PENALTY == "trust.penalty"


class TestTaskOutcome:
    def test_success_boosts_score(self):
        r = TaskOutcomeRecorder()
        initial = r.get_score("a1")
        r.record("a1", "success", severity=0.8)
        assert r.get_score("a1") > initial

    def test_failure_penalizes_score(self):
        r = TaskOutcomeRecorder()
        r.record("a1", "success")
        after_success = r.get_score("a1")
        r.record("a1", "failure", severity=0.9)
        assert r.get_score("a1") < after_success

    def test_score_clamped(self):
        r = TaskOutcomeRecorder()
        for _ in range(50):
            r.record("a1", "failure", severity=1.0)
        assert r.get_score("a1") >= 0.0

        for _ in range(200):
            r.record("a2", "success", severity=1.0)
        assert r.get_score("a2") <= 1.0

    def test_stats(self):
        r = TaskOutcomeRecorder()
        r.record("a1", "success")
        r.record("a1", "failure")
        stats = r.get_stats("a1")
        assert stats["total_tasks"] == 2
        assert stats["successes"] == 1
        assert stats["failures"] == 1

    def test_unknown_agent_default(self):
        r = TaskOutcomeRecorder()
        assert r.get_score("unknown") == 0.7


class TestDiffPolicy:
    def test_under_limits(self):
        p = DiffPolicy(max_files=10, max_lines=500)
        files = [DiffFile("src/a.py", 10, 5), DiffFile("src/b.py", 20, 10)]
        result = p.evaluate(files)
        assert result.allowed

    def test_over_file_limit(self):
        p = DiffPolicy(max_files=2)
        files = [DiffFile(f"f{i}.py") for i in range(5)]
        result = p.evaluate(files)
        assert not result.allowed
        assert "files:" in result.violations[0]

    def test_over_line_limit(self):
        p = DiffPolicy(max_lines=100)
        files = [DiffFile("big.py", additions=200)]
        result = p.evaluate(files)
        assert not result.allowed

    def test_blocked_path(self):
        p = DiffPolicy(blocked_paths=["*.env", "secrets/**"])
        files = [DiffFile(".env", 1, 0)]
        result = p.evaluate(files)
        assert not result.allowed
        assert "blocked" in result.violations[0]

    def test_allowed_paths(self):
        p = DiffPolicy(allowed_paths=["src/**", "tests/**"])
        files = [DiffFile("src/main.py"), DiffFile("deploy/prod.yml")]
        result = p.evaluate(files)
        assert not result.allowed
        assert "not_allowed" in result.violations[0]

    def test_no_restrictions(self):
        p = DiffPolicy()
        files = [DiffFile(f"f{i}.py", 100, 100) for i in range(50)]
        result = p.evaluate(files)
        assert result.allowed


class TestSandboxProvider:
    def test_noop_sandbox(self):
        s = NoOpSandboxProvider()
        result = s.run("a1", ["echo", "hi"])
        assert result.success
        assert s.is_available()

    def test_subprocess_echo(self):
        s = SubprocessSandboxProvider()
        result = s.run("a1", ["python", "-c", "print('hello')"])
        assert result.success
        assert "hello" in result.stdout

    def test_subprocess_timeout(self):
        s = SubprocessSandboxProvider()
        result = s.run("a1", ["python", "-c", "import time; time.sleep(10)"],
                       config=SandboxConfig(timeout_seconds=1))
        assert not result.success
        assert result.killed

    def test_subprocess_failure(self):
        s = SubprocessSandboxProvider()
        result = s.run("a1", ["python", "-c", "raise SystemExit(1)"])
        assert not result.success
        assert result.exit_code == 1

    def test_config_defaults(self):
        c = SandboxConfig()
        assert c.timeout_seconds == 60.0
        assert c.memory_mb == 512
        assert not c.network_enabled
