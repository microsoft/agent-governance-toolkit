# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentOps exporter."""

from agent_sre.integrations.agentops.exporter import (
    AgentOpsExporter,
    EventRecord,
    SessionRecord,
)


class TestAgentOpsExporter:
    def test_offline_by_default(self):
        exporter = AgentOpsExporter()
        assert exporter.is_offline is True

    def test_online_with_api_key(self):
        exporter = AgentOpsExporter(api_key="test-key")
        assert exporter.is_offline is False

    def test_start_session(self):
        exporter = AgentOpsExporter()
        session = exporter.start_session("agent-1", tags=["test"])
        assert isinstance(session, SessionRecord)
        assert session.agent_id == "agent-1"
        assert "test" in session.tags
        assert session.session_id

    def test_end_session(self):
        exporter = AgentOpsExporter()
        session = exporter.start_session("agent-1")
        result = exporter.end_session(session.session_id)
        assert result is not None
        assert result.end_state == "success"
        assert result.end_time is not None

    def test_end_session_failure(self):
        exporter = AgentOpsExporter()
        session = exporter.start_session("agent-1")
        result = exporter.end_session(session.session_id, success=False)
        assert result is not None
        assert result.end_state == "fail"

    def test_end_session_not_found(self):
        exporter = AgentOpsExporter()
        assert exporter.end_session("nonexistent") is None

    def test_record_event(self):
        exporter = AgentOpsExporter()
        session = exporter.start_session("agent-1")
        event = exporter.record_event(session.session_id, "action", {"key": "val"})
        assert isinstance(event, EventRecord)
        assert event.event_type == "action"
        assert event.data["key"] == "val"

    def test_record_tool_call(self):
        exporter = AgentOpsExporter()
        session = exporter.start_session("agent-1")
        event = exporter.record_tool_call(session.session_id, "search", latency_ms=150.0)
        assert event.event_type == "tool_call"
        assert event.data["tool_name"] == "search"
        assert event.data["latency_ms"] == 150.0

    def test_clear(self):
        exporter = AgentOpsExporter()
        session = exporter.start_session("agent-1")
        exporter.record_event(session.session_id, "action")
        exporter.clear()
        assert len(exporter.sessions) == 0
        assert len(exporter.events) == 0

    def test_get_stats(self):
        exporter = AgentOpsExporter(project_name="my-project")
        session = exporter.start_session("agent-1")
        exporter.record_event(session.session_id, "action")
        stats = exporter.get_stats()
        assert stats["project_name"] == "my-project"
        assert stats["total_sessions"] == 1
        assert stats["total_events"] == 1
        assert stats["is_offline"] is True

    def test_sessions_property(self):
        exporter = AgentOpsExporter()
        exporter.start_session("a1")
        exporter.start_session("a2")
        assert len(exporter.sessions) == 2
