# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for governance audit persistence."""

from __future__ import annotations

import pytest

from agent_learning_gov import (
    AuditEvent,
    AuditEventType,
    InMemoryAuditSink,
    JsonlAuditSink,
)


def _event(agent_id: str = "agent-1") -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.POLICY_EVALUATED,
        agent_id=agent_id,
        artifact_type="episode",
        artifact_id="episode-1",
        outcome="allowed",
        policy_id="policy-1",
        action_id="search",
        details={"violation_count": 0},
    )


def test_in_memory_sink_filters_events() -> None:
    sink = InMemoryAuditSink()
    sink.emit(_event())
    sink.emit(_event("agent-2"))

    events = sink.query(agent_id="agent-1")

    assert len(events) == 1
    assert events[0].artifact_id == "episode-1"


def test_jsonl_sink_round_trips_utf8(tmp_path) -> None:
    sink = JsonlAuditSink(tmp_path / "audit" / "events.jsonl")
    event = _event()
    sink.emit(event)

    restored = sink.query(event_type=AuditEventType.POLICY_EVALUATED)

    assert restored == [event]
    assert sink.path.read_text(encoding="utf-8").endswith("\n")


def test_jsonl_sink_returns_only_newest_matching_events(tmp_path) -> None:
    sink = JsonlAuditSink(tmp_path / "events.jsonl")
    for index in range(5):
        sink.emit(
            AuditEvent(
                event_type=AuditEventType.POLICY_EVALUATED,
                agent_id="agent-1",
                artifact_type="episode",
                artifact_id=f"episode-{index}",
                outcome="allowed",
            )
        )
    sink.emit(_event("agent-2"))

    restored = sink.query(agent_id="agent-1", limit=2)

    assert [event.artifact_id for event in restored] == ["episode-4", "episode-3"]


def test_audit_query_requires_positive_limit(tmp_path) -> None:
    with pytest.raises(ValueError, match="at least one"):
        InMemoryAuditSink().query(limit=0)
    with pytest.raises(ValueError, match="at least one"):
        JsonlAuditSink(tmp_path / "events.jsonl").query(limit=0)
