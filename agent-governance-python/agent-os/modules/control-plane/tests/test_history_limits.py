# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for limit handling on the control plane's history readers.

GovernanceLayer.get_audit_log already guards the ``limit == 0`` case
(``entries[-0:]`` is the whole list). These tests pin the same contract
on its siblings.
"""

import unittest

from agent_control_plane.control_plane import AgentControlPlane
from agent_control_plane.execution_engine import ExecutionEngine
from agent_control_plane.governance_layer import GovernanceLayer
from agent_control_plane.lifecycle import AgentLogEntry, AgentObservabilityProvider

AGENT = "agent-1"


class _Kernel:
    """Minimal stand-in exposing just the audit log the control plane reads."""

    def __init__(self, count):
        self._entries = [{"n": i} for i in range(count)]

    def get_audit_log(self):
        return list(self._entries)


def _engine(count):
    engine = ExecutionEngine.__new__(ExecutionEngine)
    engine.execution_history = [{"agent_id": AGENT, "n": i} for i in range(count)]
    return engine


def _observability(count):
    provider = AgentObservabilityProvider.__new__(AgentObservabilityProvider)
    provider._logs = [
        AgentLogEntry(agent_id=AGENT, level="info", message=f"m{i}")
        for i in range(count)
    ]
    return provider


def _control_plane(count):
    plane = AgentControlPlane.__new__(AgentControlPlane)
    plane.kernel = _Kernel(count)
    return plane


class LimitContractMixin:
    """Shared assertions for a reader that keeps the most recent entries."""

    def _read(self, **kwargs):
        raise NotImplementedError

    def test_default_returns_every_entry(self):
        self.assertEqual(len(self._read()), 5)

    def test_zero_returns_no_entries(self):
        self.assertEqual(self._read(limit=0), [])

    def test_positive_limit_keeps_the_most_recent(self):
        self.assertEqual(len(self._read(limit=2)), 2)

    def test_limit_above_the_entry_count_returns_every_entry(self):
        self.assertEqual(len(self._read(limit=99)), 5)

    def test_negative_limit_is_rejected(self):
        for limit in (-1, -5):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    self._read(limit=limit)


class TestExecutionHistoryLimit(LimitContractMixin, unittest.TestCase):
    """ExecutionEngine.get_execution_history"""

    def _read(self, **kwargs):
        return _engine(5).get_execution_history(**kwargs)

    def test_zero_returns_no_entries_when_filtered(self):
        self.assertEqual(_engine(5).get_execution_history(agent_id=AGENT, limit=0), [])

    def test_positive_limit_keeps_the_most_recent_when_filtered(self):
        records = _engine(5).get_execution_history(agent_id=AGENT, limit=2)
        self.assertEqual([r["n"] for r in records], [3, 4])


class TestObservabilityLogsLimit(LimitContractMixin, unittest.TestCase):
    """AgentObservabilityProvider.get_logs"""

    def _read(self, **kwargs):
        return _observability(5).get_logs(**kwargs)

    def test_zero_returns_no_entries_when_filtered(self):
        provider = _observability(5)
        self.assertEqual(provider.get_logs(agent_id=AGENT, limit=0), [])
        self.assertEqual(provider.get_logs(level="info", limit=0), [])

    def test_positive_limit_keeps_the_most_recent_when_filtered(self):
        logs = _observability(5).get_logs(agent_id=AGENT, limit=2)
        self.assertEqual([entry.message for entry in logs], ["m3", "m4"])


class TestControlPlaneAuditLogLimit(LimitContractMixin, unittest.TestCase):
    """AgentControlPlane.get_audit_log"""

    def _read(self, **kwargs):
        return _control_plane(5).get_audit_log(**kwargs)


class TestGovernanceLayerAuditLogUnchanged(unittest.TestCase):
    """The already-guarded sibling keeps its contract."""

    def _layer(self, count):
        layer = GovernanceLayer.__new__(GovernanceLayer)
        layer._audit_log = [{"n": i} for i in range(count)]
        return layer

    def test_none_returns_every_entry(self):
        self.assertEqual(len(self._layer(5).get_audit_log(limit=None)), 5)

    def test_zero_returns_no_entries(self):
        self.assertEqual(self._layer(5).get_audit_log(limit=0), [])

    def test_negative_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            self._layer(5).get_audit_log(limit=-1)


if __name__ == "__main__":
    unittest.main()
