# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ``AuditLog.query`` limit handling."""

from __future__ import annotations

import pytest

from agentmesh.governance.audit import AuditLog

AGENT = "did:mesh:agent-alpha-001"


def _log_with(count: int, *, agent_did: str = AGENT) -> AuditLog:
    """Return an :class:`AuditLog` holding ``count`` entries for one agent."""
    log = AuditLog()
    for i in range(count):
        log.log("tool.call", agent_did, f"action-{i}")
    return log


class TestQueryLimit:
    """``limit`` keeps the most recent entries; ``None`` means all, ``0`` none."""

    def test_none_returns_every_entry(self):
        assert len(_log_with(5).query(limit=None)) == 5

    def test_zero_returns_no_entries(self):
        assert _log_with(5).query(limit=0) == []

    def test_zero_returns_no_entries_when_filtered(self):
        # The filtered branch applies the limit separately from the
        # unfiltered one, so it needs its own case.
        assert _log_with(5).query(agent_did=AGENT, limit=0) == []

    def test_positive_limit_keeps_the_most_recent(self):
        entries = _log_with(5).query(limit=2)
        assert [e.action for e in entries] == ["action-3", "action-4"]

    def test_positive_limit_keeps_the_most_recent_when_filtered(self):
        entries = _log_with(5).query(agent_did=AGENT, limit=2)
        assert [e.action for e in entries] == ["action-3", "action-4"]

    def test_limit_above_the_entry_count_returns_every_entry(self):
        assert len(_log_with(3).query(limit=99)) == 3

    @pytest.mark.parametrize("limit", [-1, -5])
    def test_negative_limit_is_rejected(self, limit):
        with pytest.raises(ValueError, match="zero or positive"):
            _log_with(5).query(limit=limit)

    @pytest.mark.parametrize("limit", [-1, -5])
    def test_negative_limit_is_rejected_when_filtered(self, limit):
        with pytest.raises(ValueError, match="zero or positive"):
            _log_with(5).query(agent_did=AGENT, limit=limit)

    def test_query_does_not_expose_the_backing_list(self):
        log = _log_with(3)
        returned = log.query(limit=None)
        returned.clear()
        assert len(log.query(limit=None)) == 3


class TestIndexedReaderLimits:
    """``get_entries_for_agent`` and ``get_entries_by_type`` share the
    ``_tail`` helper, so the same limit contract holds for both."""

    def test_for_agent_default_returns_every_entry(self):
        assert len(_log_with(5).get_entries_for_agent(AGENT)) == 5

    def test_for_agent_none_returns_every_entry(self):
        # The readers took ``limit: int`` and had no way to ask for every entry
        # other than a number above the count; ``None`` now means all, as on query.
        assert len(_log_with(150).get_entries_for_agent(AGENT, limit=None)) == 150

    def test_for_agent_zero_returns_no_entries(self):
        assert _log_with(5).get_entries_for_agent(AGENT, limit=0) == []

    def test_for_agent_positive_limit_keeps_the_most_recent(self):
        entries = _log_with(5).get_entries_for_agent(AGENT, limit=2)
        assert [e.action for e in entries] == ["action-3", "action-4"]

    def test_for_agent_limit_above_the_entry_count_returns_every_entry(self):
        assert len(_log_with(3).get_entries_for_agent(AGENT, limit=99)) == 3

    @pytest.mark.parametrize("limit", [-1, -5])
    def test_for_agent_negative_limit_is_rejected(self, limit):
        with pytest.raises(ValueError, match="zero or positive"):
            _log_with(5).get_entries_for_agent(AGENT, limit=limit)

    def test_by_type_default_returns_every_entry(self):
        assert len(_log_with(5).get_entries_by_type("tool.call")) == 5

    def test_by_type_none_returns_every_entry(self):
        assert len(_log_with(150).get_entries_by_type("tool.call", limit=None)) == 150

    def test_by_type_zero_returns_no_entries(self):
        assert _log_with(5).get_entries_by_type("tool.call", limit=0) == []

    def test_by_type_positive_limit_keeps_the_most_recent(self):
        entries = _log_with(5).get_entries_by_type("tool.call", limit=2)
        assert [e.action for e in entries] == ["action-3", "action-4"]

    def test_by_type_limit_above_the_entry_count_returns_every_entry(self):
        assert len(_log_with(3).get_entries_by_type("tool.call", limit=99)) == 3

    @pytest.mark.parametrize("limit", [-1, -5])
    def test_by_type_negative_limit_is_rejected(self, limit):
        with pytest.raises(ValueError, match="zero or positive"):
            _log_with(5).get_entries_by_type("tool.call", limit=limit)

    def test_unknown_key_returns_no_entries(self):
        log = _log_with(5)
        assert log.get_entries_for_agent("did:mesh:absent") == []
        assert log.get_entries_by_type("absent.event") == []
