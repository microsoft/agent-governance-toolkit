# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ``DashboardAPI`` limit handling on the list endpoints."""

from __future__ import annotations

import pytest

from agentmesh.dashboard import DashboardAPI
from agentmesh.events import AnalyticsPlane, Event, InMemoryEventBus

AGENT = "did:mesh:agent-alpha-001"


def _api_with(count: int) -> DashboardAPI:
    """Return a wired DashboardAPI holding ``count`` audit events."""
    bus = InMemoryEventBus()
    api = DashboardAPI(bus, AnalyticsPlane(bus))
    for i in range(count):
        bus.emit(
            Event(
                event_type="audit.entry",
                source=AGENT,
                payload={"action": f"action-{i}"},
            )
        )
    return api


class TestLiveTrafficLimit:
    """``limit`` keeps the most recent traffic entries; ``0`` keeps none."""

    def test_zero_returns_no_entries(self):
        assert _api_with(5).get_live_traffic(limit=0) == []

    def test_positive_limit_keeps_the_most_recent_first(self):
        entries = _api_with(5).get_live_traffic(limit=2)
        assert [e.event_type for e in entries] == ["audit.entry", "audit.entry"]
        assert len(entries) == 2

    def test_limit_above_the_entry_count_returns_every_entry(self):
        assert len(_api_with(3).get_live_traffic(limit=99)) == 3

    @pytest.mark.parametrize("limit", [-1, -5])
    def test_negative_limit_is_rejected(self, limit):
        with pytest.raises(ValueError, match="zero or positive"):
            _api_with(5).get_live_traffic(limit=limit)


class TestAuditLogLimit:
    """``limit`` applies on both the filtered and the unfiltered path."""

    def test_zero_returns_no_entries(self):
        assert _api_with(5).get_audit_log(limit=0) == []

    def test_zero_returns_no_entries_when_filtered(self):
        assert _api_with(5).get_audit_log(filters={"agent": AGENT}, limit=0) == []

    def test_positive_limit_keeps_the_most_recent_first(self):
        entries = _api_with(5).get_audit_log(limit=2)
        assert [e.action for e in entries] == ["action-4", "action-3"]

    def test_positive_limit_keeps_the_most_recent_first_when_filtered(self):
        entries = _api_with(5).get_audit_log(filters={"agent": AGENT}, limit=2)
        assert [e.action for e in entries] == ["action-4", "action-3"]

    def test_limit_above_the_entry_count_returns_every_entry(self):
        assert len(_api_with(3).get_audit_log(limit=99)) == 3

    @pytest.mark.parametrize("limit", [-1, -5])
    def test_negative_limit_is_rejected(self, limit):
        with pytest.raises(ValueError, match="zero or positive"):
            _api_with(5).get_audit_log(limit=limit)

    @pytest.mark.parametrize("limit", [-1, -5])
    def test_negative_limit_is_rejected_when_filtered(self, limit):
        with pytest.raises(ValueError, match="zero or positive"):
            _api_with(5).get_audit_log(filters={"agent": AGENT}, limit=limit)


class TestLeaderboardLimitUnchanged:
    """``get_leaderboard`` slices forward, so zero already returned none."""

    def test_zero_returns_no_entries(self):
        assert _api_with(5).get_leaderboard(limit=0) == []
