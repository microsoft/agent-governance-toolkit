# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MockState, MockStateConfig, and scenario utilities."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from core.mock_state import (
    MockState,
    MockStateConfig,
    ContextEvent,
    ContextEventType,
    create_stale_pointer_scenario,
    create_zombie_resource_scenario,
)


# ---------------------------------------------------------------------------
# Event tracking
# ---------------------------------------------------------------------------

class TestEventTracking:
    def test_add_event_stores_event(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_SERVICE, service_id="svc-a")
        assert len(state.event_history) == 1
        assert state.event_history[0].service_id == "svc-a"

    def test_add_event_with_metadata(self):
        state = MockState()
        state.add_event(
            ContextEventType.EXECUTE_ACTION, service_id="svc-b",
            action="restart", metadata={"reason": "test"},
        )
        assert state.event_history[0].metadata["reason"] == "test"
        assert state.event_history[0].action == "restart"

    def test_view_logs_updates_focus(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-x")
        assert state.last_focus_service == "svc-x"

    def test_view_service_updates_focus(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_SERVICE, service_id="svc-y")
        assert state.last_focus_service == "svc-y"

    def test_execute_action_does_not_update_focus(self):
        state = MockState()
        state.add_event(ContextEventType.EXECUTE_ACTION, service_id="svc-z")
        assert state.last_focus_service is None

    def test_query_state_does_not_update_focus(self):
        state = MockState()
        state.add_event(ContextEventType.QUERY_STATE)
        assert state.last_focus_service is None


# ---------------------------------------------------------------------------
# Time advancement & staleness
# ---------------------------------------------------------------------------

class TestTimeAndStaleness:
    def test_advance_time_seconds(self):
        state = MockState()
        t0 = state.current_time
        state.advance_time(seconds=60)
        assert (state.current_time - t0).total_seconds() == pytest.approx(60)

    def test_advance_time_minutes(self):
        state = MockState()
        t0 = state.current_time
        state.advance_time(minutes=5)
        assert (state.current_time - t0).total_seconds() == pytest.approx(300)

    def test_advance_time_hours(self):
        state = MockState()
        t0 = state.current_time
        state.advance_time(hours=1)
        assert (state.current_time - t0).total_seconds() == pytest.approx(3600)

    def test_advance_time_combined(self):
        state = MockState()
        t0 = state.current_time
        state.advance_time(seconds=30, minutes=1, hours=1)
        assert (state.current_time - t0).total_seconds() == pytest.approx(3690)

    def test_not_stale_within_ttl(self):
        state = MockState()  # default TTL = 300s
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        state.advance_time(seconds=100)
        assert state.is_context_stale() is False

    def test_stale_after_ttl(self):
        state = MockState()  # default TTL = 300s
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        state.advance_time(seconds=301)
        assert state.is_context_stale() is True

    def test_no_focus_is_not_stale(self):
        state = MockState()
        assert state.is_context_stale() is False

    def test_time_multiplier(self):
        config = MockStateConfig(time_multiplier=10.0)
        state = MockState(config=config)
        t0 = state.current_time
        state.advance_time(seconds=10)
        assert (state.current_time - t0).total_seconds() == pytest.approx(100)


# ---------------------------------------------------------------------------
# Focus tracking
# ---------------------------------------------------------------------------

class TestFocusTracking:
    def test_get_current_focus_within_ttl(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        assert state.get_current_focus() == "svc-a"

    def test_get_current_focus_expired(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        state.advance_time(seconds=301)
        assert state.get_current_focus() is None

    def test_get_current_focus_no_focus(self):
        state = MockState()
        assert state.get_current_focus() is None

    def test_get_current_focus_ttl_not_enforced(self):
        config = MockStateConfig(enforce_ttl=False)
        state = MockState(config=config)
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        state.advance_time(hours=24)
        assert state.get_current_focus() == "svc-a"

    def test_get_time_since_last_focus(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        state.advance_time(seconds=120)
        assert state.get_time_since_last_focus() == pytest.approx(120)

    def test_get_time_since_last_focus_no_focus(self):
        state = MockState()
        assert state.get_time_since_last_focus() is None

    def test_get_last_access(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        ts = state.get_last_access("svc-a")
        assert ts is not None

    def test_get_last_access_unknown_service(self):
        state = MockState()
        assert state.get_last_access("nonexistent") is None


# ---------------------------------------------------------------------------
# Recent events
# ---------------------------------------------------------------------------

class TestRecentEvents:
    def test_get_recent_events_returns_most_recent_first(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        state.advance_time(seconds=10)
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-b")
        events = state.get_recent_events(count=2)
        assert events[0].service_id == "svc-b"

    def test_get_recent_events_filters_by_type(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        state.add_event(ContextEventType.EXECUTE_ACTION, service_id="svc-b", action="restart")
        events = state.get_recent_events(event_type=ContextEventType.EXECUTE_ACTION)
        assert len(events) == 1
        assert events[0].service_id == "svc-b"

    def test_get_recent_events_respects_count(self):
        state = MockState()
        for i in range(5):
            state.add_event(ContextEventType.VIEW_LOGS, service_id=f"svc-{i}")
        events = state.get_recent_events(count=3)
        assert len(events) == 3


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

class TestReset:
    def test_reset_clears_events(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        state.reset()
        assert len(state.event_history) == 0
        assert state.last_focus_service is None
        assert state.last_focus_time is None


# ---------------------------------------------------------------------------
# MockStateConfig
# ---------------------------------------------------------------------------

class TestMockStateConfig:
    def test_custom_ttl(self):
        config = MockStateConfig(context_ttl_seconds=60.0)
        state = MockState(config=config)
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        state.advance_time(seconds=61)
        assert state.is_context_stale() is True
        assert state.get_current_focus() is None

    def test_default_config_values(self):
        config = MockStateConfig()
        assert config.context_ttl_seconds == 300.0
        assert config.enforce_ttl is True
        assert config.time_multiplier == 1.0


# ---------------------------------------------------------------------------
# Scenario utilities
# ---------------------------------------------------------------------------

class TestScenarioUtilities:
    def test_stale_pointer_scenario_focus_is_service_b(self):
        state = create_stale_pointer_scenario()
        assert state.get_current_focus() == "svc-b"

    def test_stale_pointer_scenario_has_two_events(self):
        state = create_stale_pointer_scenario()
        assert len(state.event_history) == 2

    def test_stale_pointer_custom_services(self):
        state = create_stale_pointer_scenario(service_a="alpha", service_b="beta")
        assert state.get_current_focus() == "beta"

    def test_zombie_resource_scenario_has_event(self):
        state = create_zombie_resource_scenario()
        assert len(state.event_history) == 1
        assert state.event_history[0].metadata.get("state") == "partial"

    def test_zombie_resource_scenario_custom_id(self):
        state = create_zombie_resource_scenario(service_id="my-svc")
        assert state.event_history[0].service_id == "my-svc"

    def test_repr_does_not_raise(self):
        state = MockState()
        state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
        repr_str = repr(state)
        assert "MockState" in repr_str
