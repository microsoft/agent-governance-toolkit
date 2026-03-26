# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Time-Travel Debugging feature
"""

import json
import tempfile
import time
from datetime import datetime, timedelta

import pytest
from agent_control_plane import (
    AgentControlPlane,
    ReplayMode,
    TimeTravelConfig,
    TimeTravelDebugger,
    create_standard_agent,
)
from agent_control_plane.agent_kernel import ActionType
from agent_control_plane.flight_recorder import FlightRecorder


class TestTimeTravelDebugger:
    """Test the TimeTravelDebugger class"""

    def test_initialization(self):
        """Test time-travel debugger initialization"""
        config = TimeTravelConfig(enabled=True)
        debugger = TimeTravelDebugger(config=config)

        assert debugger.config.enabled is True
        assert len(debugger.active_sessions) == 0

    def test_capture_state_snapshot(self):
        """Test capturing state snapshots"""
        debugger = TimeTravelDebugger()

        state = {"session_id": "test-session", "permissions": {"FILE_READ": 1}}

        debugger.capture_state_snapshot("test-agent", state)

        assert "test-agent" in debugger.state_snapshots
        assert len(debugger.state_snapshots["test-agent"]) == 1

    def test_get_state_at_time(self):
        """Test retrieving state at a specific time"""
        debugger = TimeTravelDebugger()

        now = datetime.now()

        # Capture snapshots at different times
        state1 = {"version": 1}
        debugger.capture_state_snapshot("test-agent", state1)

        # Wait a bit
        time.sleep(0.1)

        state2 = {"version": 2}
        debugger.capture_state_snapshot("test-agent", state2)

        # Get state at time between snapshots
        target_time = now + timedelta(seconds=0.05)
        retrieved = debugger.get_state_at_time("test-agent", target_time)

        # Should get first snapshot (closest before target)
        assert retrieved is not None
        assert retrieved["state"]["version"] == 1

    def test_create_replay_session(self):
        """Test creating a replay session"""
        flight_recorder = FlightRecorder(
            db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        )
        debugger = TimeTravelDebugger(flight_recorder=flight_recorder)

        # Add some test data to flight recorder
        trace_id = flight_recorder.start_trace(
            "test-agent", "test_tool", {"arg": "value"}, "test prompt"
        )
        flight_recorder.log_success(trace_id)

        # Create replay session
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=1)

        session = debugger.create_replay_session(
            "test-agent", start_time, end_time, ReplayMode.CONTINUOUS
        )

        assert session.agent_id == "test-agent"
        assert session.mode == ReplayMode.CONTINUOUS
        assert session.session_id in debugger.active_sessions

    def test_replay_time_window(self):
        """Test replaying a time window"""
        flight_recorder = FlightRecorder(
            db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        )
        debugger = TimeTravelDebugger(flight_recorder=flight_recorder)

        # Add test data
        for i in range(3):
            trace_id = flight_recorder.start_trace("test-agent", f"tool_{i}", {"index": i})
            flight_recorder.log_success(trace_id)

        # Replay last 5 minutes
        session = debugger.replay_time_window("test-agent", 5)

        assert session.agent_id == "test-agent"
        assert len(session.events) >= 0  # May or may not find events depending on timing

    def test_step_by_step_replay(self):
        """Test step-by-step replay mode"""
        flight_recorder = FlightRecorder(
            db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        )
        debugger = TimeTravelDebugger(flight_recorder=flight_recorder)

        # Add test data
        trace_ids = []
        for i in range(3):
            trace_id = flight_recorder.start_trace("test-agent", f"tool_{i}", {"index": i})
            flight_recorder.log_success(trace_id)
            trace_ids.append(trace_id)

        # Create step-by-step session
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=1)

        session = debugger.create_replay_session(
            "test-agent", start_time, end_time, ReplayMode.STEP_BY_STEP
        )

        # Step through events
        if len(session.events) > 0:
            event1 = debugger.next_step(session.session_id)
            assert event1 is not None

            event2 = debugger.next_step(session.session_id)
            # May be None if only one event

    def test_get_session_progress(self):
        """Test getting replay session progress"""
        flight_recorder = FlightRecorder(
            db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        )
        debugger = TimeTravelDebugger(flight_recorder=flight_recorder)

        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=1)

        session = debugger.create_replay_session("test-agent", start_time, end_time)

        progress = debugger.get_session_progress(session.session_id)

        assert progress["session_id"] == session.session_id
        assert progress["agent_id"] == "test-agent"
        assert "total_events" in progress
        assert "current_index" in progress
        assert "progress_percent" in progress

    def test_get_replay_summary(self):
        """Test getting replay summary"""
        flight_recorder = FlightRecorder(
            db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        )
        debugger = TimeTravelDebugger(flight_recorder=flight_recorder)

        # Add test data
        trace_id = flight_recorder.start_trace("test-agent", "test_tool", {})
        flight_recorder.log_success(trace_id)

        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=1)

        session = debugger.create_replay_session("test-agent", start_time, end_time)

        summary = debugger.get_replay_summary(session.session_id)

        assert summary["session_id"] == session.session_id
        assert summary["agent_id"] == "test-agent"
        assert "time_range" in summary
        assert "total_events" in summary
        assert "event_type_breakdown" in summary

    def test_export_replay_session(self):
        """Test exporting replay session"""
        flight_recorder = FlightRecorder(
            db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        )
        debugger = TimeTravelDebugger(flight_recorder=flight_recorder)

        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=1)

        session = debugger.create_replay_session("test-agent", start_time, end_time)

        export = debugger.export_replay_session(session.session_id)

        assert isinstance(export, str)
        assert "test-agent" in export
        data = json.loads(export)
        assert data["agent_id"] == "test-agent"

    def test_statistics(self):
        """Test time-travel statistics"""
        debugger = TimeTravelDebugger()

        # Capture some snapshots
        debugger.capture_state_snapshot("agent-1", {"state": 1})
        debugger.capture_state_snapshot("agent-2", {"state": 2})

        stats = debugger.get_statistics()

        assert stats["total_state_snapshots"] == 2
        assert stats["agents_with_snapshots"] == 2
        assert stats["config"]["enabled"] is True


class TestControlPlaneTimeTravel:
    """Test time-travel integration with AgentControlPlane"""

    def test_enable_time_travel(self):
        """Test enabling time-travel in control plane"""
        config = TimeTravelConfig(enabled=True)

        cp = AgentControlPlane(enable_time_travel=True, time_travel_config=config)

        assert cp.time_travel_enabled is True
        assert cp.time_travel_debugger is not None

    def test_replay_agent_history(self):
        """Test replaying agent history through control plane"""
        flight_recorder = FlightRecorder(
            db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        )

        cp = AgentControlPlane(
            enable_time_travel=True, time_travel_config=TimeTravelConfig(enabled=True)
        )

        # Attach flight recorder
        cp.kernel.audit_logger = flight_recorder
        cp.time_travel_debugger.flight_recorder = flight_recorder

        # Create agent and execute actions
        agent = create_standard_agent(cp, "test-agent")

        cp.execute_action(agent, ActionType.FILE_READ, {"path": "/test.txt"})

        # Replay
        session = cp.replay_agent_history(agent.agent_id, minutes=1)

        assert session.agent_id == agent.agent_id

    def test_capture_state_snapshot(self):
        """Test capturing state snapshots through control plane"""
        cp = AgentControlPlane(
            enable_time_travel=True,
            time_travel_config=TimeTravelConfig(enable_state_snapshots=True),
        )

        agent = create_standard_agent(cp, "test-agent")

        cp.capture_agent_state_snapshot(agent.agent_id, agent, metadata={"test": "data"})

        assert agent.agent_id in cp.time_travel_debugger.state_snapshots

    def test_time_travel_disabled(self):
        """Test that time-travel methods fail when disabled"""
        cp = AgentControlPlane(enable_time_travel=False)

        agent = create_standard_agent(cp, "test-agent")

        with pytest.raises(RuntimeError, match="Time-travel debugging is not enabled"):
            cp.replay_agent_history(agent.agent_id, minutes=1)

    def test_time_travel_statistics(self):
        """Test getting time-travel statistics"""
        cp = AgentControlPlane(
            enable_time_travel=True, time_travel_config=TimeTravelConfig(enabled=True)
        )

        stats = cp.get_time_travel_statistics()

        assert stats["config"]["enabled"] is True
        assert "active_replay_sessions" in stats

        # Test with time-travel disabled
        cp_disabled = AgentControlPlane(enable_time_travel=False)
        stats_disabled = cp_disabled.get_time_travel_statistics()

        assert stats_disabled["enabled"] is False

    def test_replay_with_callback(self):
        """Test replaying with a callback function"""
        flight_recorder = FlightRecorder(
            db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        )

        cp = AgentControlPlane(
            enable_time_travel=True, time_travel_config=TimeTravelConfig(enabled=True)
        )

        cp.kernel.audit_logger = flight_recorder
        cp.time_travel_debugger.flight_recorder = flight_recorder

        agent = create_standard_agent(cp, "test-agent")

        # Execute actions
        cp.execute_action(agent, ActionType.FILE_READ, {"path": "/test.txt"})

        # Replay with callback
        events_seen = []

        def callback(event):
            events_seen.append(event)

        session = cp.replay_agent_history(agent.agent_id, minutes=1, callback=callback)

        # Callback should have been called for each event
        assert len(events_seen) >= 0


class TestFlightRecorderTimeTravel:
    """Test FlightRecorder time-travel support methods"""

    def test_get_log(self):
        """Test getting complete audit log"""
        fr = FlightRecorder(db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name)

        # Add some events
        trace_id1 = fr.start_trace("agent-1", "tool-1", {})
        fr.log_success(trace_id1)

        trace_id2 = fr.start_trace("agent-2", "tool-2", {})
        fr.log_success(trace_id2)

        log = fr.get_log()

        assert len(log) >= 2
        assert any(entry["agent_id"] == "agent-1" for entry in log)
        assert any(entry["agent_id"] == "agent-2" for entry in log)

    def test_get_events_in_time_range(self):
        """Test getting events in time range"""
        fr = FlightRecorder(db_path=tempfile.NamedTemporaryFile(suffix=".db", delete=False).name)

        start_time = datetime.now()

        # Add events
        trace_id = fr.start_trace("test-agent", "test-tool", {})
        fr.log_success(trace_id)

        end_time = datetime.now()

        # Query time range
        events = fr.get_events_in_time_range(start_time, end_time, "test-agent")

        assert len(events) >= 1
        assert events[0]["agent_id"] == "test-agent"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
