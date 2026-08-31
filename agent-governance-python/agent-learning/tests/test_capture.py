# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Focused tests for governed Agent Learning episode capture."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import SimpleNamespace
from typing import Any

import pytest

from agent_learning_gov import (
    AuditEventType,
    EpisodePersistenceError,
    GovernanceDeniedError,
    GovernanceTelemetry,
    GovernedEpisodeCapture,
    InMemoryAuditSink,
    UnresolvedDecisionError,
)


@dataclass
class _CaptureContext:
    metadata: dict[str, Any]
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    episode_id: str = "episode-1"
    agent_id: str = "agent-1"
    task_id: str = "task-1"
    policy_id: str | None = "policy-1"
    policy_version: int | None = 1
    action_id: str | None = None
    action_name: str | None = None
    action_logprob: float | None = None
    correlation_id: str | None = "correlation-1"


class _Capture:
    config = SimpleNamespace(enabled=True, agent_id="agent-1", task_id="task-1")
    store = object()

    def __init__(self) -> None:
        self.episodes: list[Any] = []

    def is_enabled(self) -> bool:
        return True

    def start(self, _user_input: str, **kwargs: Any) -> _CaptureContext:
        return _CaptureContext(
            metadata=kwargs.get("metadata", {}),
            task_id=kwargs.get("task_id", "task-1"),
            policy_id=kwargs.get("policy_id"),
            policy_version=kwargs.get("policy_version"),
            action_id=kwargs.get("action_id"),
            action_name=kwargs.get("action_name"),
            action_logprob=kwargs.get("action_logprob"),
        )

    def record_tool_call(
        self,
        context: _CaptureContext,
        name: str,
        arguments: dict[str, Any],
        result: str | None,
        **kwargs: Any,
    ) -> None:
        context.tool_calls.append(
            {"name": name, "arguments": arguments, "result": result, **kwargs}
        )

    def end(self, context: _CaptureContext, output: str, **kwargs: Any) -> Any:
        fields = {
            "id": context.episode_id,
            "agent_id": context.agent_id,
            "task_id": context.task_id,
            "policy_id": context.policy_id,
            "policy_version": context.policy_version,
            "action_id": context.action_id or "search",
            "correlation_id": context.correlation_id,
            "metadata": context.metadata,
            "output": output,
            **kwargs,
        }
        fields.setdefault("execution_status", None)
        episode = SimpleNamespace(**fields)
        self.episodes.append(episode)
        return episode


class _Policy:
    name = "test-policy"

    def __init__(self, denied: set[str] | None = None) -> None:
        self.denied = denied or set()

    def evaluate(self, action: str, content: str = "", **context: Any) -> Any:
        del content, context
        return SimpleNamespace(
            allowed=action not in self.denied,
            reason="restricted" if action in self.denied else "allowed",
        )


def _decision(selection_basis: str, *, logprob: float | None) -> Any:
    return SimpleNamespace(
        agent_id="agent-1",
        task_id="task-1",
        policy_id="policy-1",
        policy_version=3,
        selected_action=SimpleNamespace(id="search"),
        proposed_action=None,
        selection_basis=selection_basis,
        action_logprob=logprob,
        status="resolved",
        reason="decision resolved",
        candidate_actions=(SimpleNamespace(id="search"),),
        assessments=(),
        information_needs=(),
        rejected_action_ids=(),
        authorization_basis="learned_policy",
        action_probabilities={"search": 1.0},
    )


def test_bayesian_episode_is_auditable_but_not_reinforce_eligible() -> None:
    capture = _Capture()
    governed = GovernedEpisodeCapture(_Policy(), capture=capture)

    context = governed.start(
        "choose a region",
        decision_result=_decision("bayesian_decision", logprob=None),
    )
    episode = governed.end(context, "east", execution_status="completed")

    telemetry = GovernanceTelemetry.from_metadata(episode.metadata)
    assert telemetry.selection_basis == "bayesian_decision"
    assert telemetry.reinforce_eligible == False
    assert telemetry.decisions[0].action_id == "search"
    assert telemetry.metadata["decision_certificate"]["status"] == "resolved"


def test_pending_decision_cannot_start_capture() -> None:
    capture = _Capture()
    governed = GovernedEpisodeCapture(_Policy(), capture=capture)
    decision = _decision("bayesian_decision", logprob=None)
    decision.selected_action = None
    decision.proposed_action = SimpleNamespace(id="search")
    decision.status = "needs_user_tie_break"

    with pytest.raises(UnresolvedDecisionError, match="not executable"):
        governed.start("choose a region", decision_result=decision)

    assert capture.episodes == []


def test_decision_without_explicit_status_cannot_start_capture() -> None:
    capture = _Capture()
    governed = GovernedEpisodeCapture(_Policy(), capture=capture)
    decision = _decision("learned_policy", logprob=-0.2)
    del decision.status

    with pytest.raises(UnresolvedDecisionError, match="not executable"):
        governed.start("choose a region", decision_result=decision)

    assert capture.episodes == []


def test_modified_action_replaces_capture_action_and_is_not_reinforce_eligible() -> None:
    class ModifyPolicy:
        def evaluate(self, action: str, content: str = "", **context: Any) -> Any:
            del content, context
            return {
                "allowed": True,
                "verdict": "modified",
                "modified_action_id": f"safe_{action}",
                "reason": "least-privilege replacement",
            }

    governed = GovernedEpisodeCapture(ModifyPolicy(), capture=_Capture())

    context = governed.start(
        "search",
        decision_result=_decision("learned_policy", logprob=-0.2),
    )
    episode = governed.end(context, "done", execution_status="completed")

    telemetry = GovernanceTelemetry.from_metadata(episode.metadata)
    assert context.action_id == "safe_search"
    assert context.action_name == "safe_search"
    assert context.action_logprob is None
    assert episode.action_id == "safe_search"
    assert telemetry.reinforce_eligible == False
    assert telemetry.decisions[0].modified_action_id == "safe_search"


def test_bayesian_episode_rejects_fabricated_log_probability() -> None:
    governed = GovernedEpisodeCapture(_Policy(), capture=_Capture())

    with pytest.raises(ValueError, match="must not carry"):
        governed.start(
            "choose a region",
            decision_result=_decision("bayesian_decision", logprob=-0.2),
        )


@pytest.mark.parametrize("logprob", [float("nan"), float("inf"), 0.1])
def test_learned_episode_rejects_invalid_log_probability(logprob: float) -> None:
    governed = GovernedEpisodeCapture(_Policy(), capture=_Capture())

    with pytest.raises(ValueError, match="finite non-positive"):
        governed.start(
            "choose a region",
            decision_result=_decision("learned_policy", logprob=logprob),
        )


def test_resolved_decision_fields_cannot_be_overridden() -> None:
    governed = GovernedEpisodeCapture(_Policy(), capture=_Capture())

    with pytest.raises(ValueError, match="action_id conflicts"):
        governed.start(
            "choose a region",
            decision_result=_decision("learned_policy", logprob=-0.2),
            action_id="forged-action",
        )


def test_initial_policy_context_cannot_shadow_decision_scope() -> None:
    received: dict[str, Any] = {}

    class ScopePolicy:
        def evaluate(self, action: str, content: str = "", **context: Any) -> Any:
            received.update(action=action, content=content, context=context)
            return SimpleNamespace(allowed=True, reason="allowed")

    governed = GovernedEpisodeCapture(ScopePolicy(), capture=_Capture())
    governed.start(
        "choose",
        decision_result=_decision("learned_policy", logprob=-0.2),
        governance_context={
            "phase": "forged",
            "agent_id": "other-agent",
            "task_id": "other-task",
            "policy_id": "other-policy",
            "policy_version": 99,
            "action_id": "other-action",
        },
    )

    assert received["context"] == {
        "phase": "episode_capture",
        "agent_id": "agent-1",
        "task_id": "task-1",
        "policy_id": "policy-1",
        "policy_version": 3,
        "action_id": "search",
    }


def test_decision_agent_must_match_capture_configuration() -> None:
    governed = GovernedEpisodeCapture(_Policy(), capture=_Capture())
    decision = _decision("learned_policy", logprob=-0.2)
    decision.agent_id = "other-agent"

    with pytest.raises(ValueError, match="agent_id conflicts"):
        governed.start("choose a region", decision_result=decision)


def test_denied_action_is_persisted_before_capture_raises() -> None:
    capture = _Capture()
    governed = GovernedEpisodeCapture(_Policy({"search"}), capture=capture)

    with pytest.raises(GovernanceDeniedError):
        governed.start(
            "restricted request",
            decision_result=_decision("learned_policy", logprob=-0.2),
        )

    assert len(capture.episodes) == 1
    telemetry = GovernanceTelemetry.from_metadata(capture.episodes[0].metadata)
    assert telemetry.violations[0].blocked == True
    assert capture.episodes[0].execution_status == "governance_denied"


def test_denied_tool_attempt_is_recorded_without_result() -> None:
    governed = GovernedEpisodeCapture(
        _Policy({"delete_file"}),
        capture=_Capture(),
        raise_on_denied=False,
    )
    context = governed.start("clean", action_id="search")

    governed.record_tool_call(
        context,
        "delete_file",
        {"path": "data.txt"},
        "deleted",
    )

    telemetry = GovernanceTelemetry.from_metadata(context.metadata)
    assert telemetry.tool_usage[0].outcome.value == "denied"
    assert telemetry.violations[0].action_id == "delete_file"
    assert context.tool_calls[0]["result"] is None


def test_tool_authorization_checks_arguments_before_execution_and_records_cost() -> None:
    received: dict[str, Any] = {}

    class ToolPolicy:
        def evaluate(self, action: str, content: str = "", **context: Any) -> Any:
            received.update(action=action, content=content, context=context)
            return SimpleNamespace(allowed=True, reason="allowed")

    governed = GovernedEpisodeCapture(ToolPolicy(), capture=_Capture())
    context = governed.start("clean", action_id="search")

    authorization = governed.authorize_tool_call(
        context,
        "lookup",
        {"record_id": "42"},
    )
    governed.record_tool_call(
        context,
        "lookup",
        {"record_id": "42"},
        "found",
        cost=0.02,
        authorization=authorization,
    )

    telemetry = GovernanceTelemetry.from_metadata(context.metadata)
    assert received["action"] == "lookup"
    assert received["content"] == '{"record_id":"42"}'
    assert received["context"]["arguments"] == {"record_id": "42"}
    assert len(telemetry.decisions) == 2
    assert telemetry.tool_usage[0].cost == 0.02
    assert context.tool_calls[0]["name"] == "lookup"


def test_policy_context_cannot_override_trusted_tool_fields() -> None:
    received: dict[str, Any] = {}

    class ToolPolicy:
        def evaluate(self, action: str, content: str = "", **context: Any) -> Any:
            received.update(action=action, content=content, context=context)
            return SimpleNamespace(allowed=True, reason="allowed")

    governed = GovernedEpisodeCapture(ToolPolicy(), capture=_Capture())
    context = governed.start(
        "clean",
        decision_result=_decision("learned_policy", logprob=-0.2),
    )

    governed.authorize_tool_call(
        context,
        "lookup",
        {"record_id": "42"},
        governance_context={
            "phase": "forged",
            "agent_id": "other-agent",
            "task_id": "other-task",
            "policy_id": "other-policy",
            "policy_version": 99,
            "episode_id": "other-episode",
            "target": "delete",
            "arguments": {"record_id": "different"},
        },
    )

    assert received["context"]["phase"] == "tool_call"
    assert received["context"]["agent_id"] == "agent-1"
    assert received["context"]["task_id"] == "task-1"
    assert received["context"]["policy_id"] == "policy-1"
    assert received["context"]["policy_version"] == 3
    assert received["context"]["episode_id"] == "episode-1"
    assert received["context"]["target"] == "lookup"
    assert received["context"]["arguments"] == {"record_id": "42"}


def test_tool_authorization_cannot_be_replayed_with_different_arguments() -> None:
    governed = GovernedEpisodeCapture(_Policy(), capture=_Capture())
    context = governed.start("clean", action_id="search")
    authorization = governed.authorize_tool_call(
        context,
        "lookup",
        {"record_id": "42"},
    )

    with pytest.raises(ValueError, match="does not match"):
        governed.record_tool_call(
            context,
            "lookup",
            {"record_id": "43"},
            "found",
            authorization=authorization,
        )

    assert context.tool_calls == []


def test_tool_authorization_is_consumed_after_one_recording() -> None:
    governed = GovernedEpisodeCapture(_Policy(), capture=_Capture())
    context = governed.start("clean", action_id="search")
    arguments = {"record_id": "42"}
    authorization = governed.authorize_tool_call(context, "lookup", arguments)
    governed.record_tool_call(
        context,
        "lookup",
        arguments,
        "found",
        authorization=authorization,
    )

    with pytest.raises(ValueError, match="already been used"):
        governed.record_tool_call(
            context,
            "lookup",
            arguments,
            "found again",
            authorization=authorization,
        )

    assert len(context.tool_calls) == 1


def test_mutated_tool_authorization_cannot_change_issued_verdict() -> None:
    governed = GovernedEpisodeCapture(
        _Policy({"delete"}),
        capture=_Capture(),
        raise_on_denied=False,
    )
    context = governed.start("clean", action_id="search")
    authorization = governed.authorize_tool_call(context, "delete", {"id": "42"})
    forged = replace(
        authorization,
        decision=replace(
            authorization.decision,
            outcome=authorization.decision.outcome.ALLOWED,
            modified_action_id="safe_delete",
        ),
        violation=None,
    )

    governed.record_tool_call(
        context,
        "delete",
        {"id": "42"},
        "deleted",
        authorization=forged,
    )

    assert context.tool_calls[0]["name"] == "delete"
    assert context.tool_calls[0]["result"] is None


def test_modified_tool_authorization_returns_and_records_effective_tool() -> None:
    class ToolPolicy:
        def evaluate(self, action: str, content: str = "", **context: Any) -> Any:
            del content, context
            return {
                "allowed": True,
                "verdict": "modified",
                "modified_action_id": f"safe_{action}",
            }

    governed = GovernedEpisodeCapture(ToolPolicy(), capture=_Capture())
    context = governed.start("clean", action_id="search")

    authorization = governed.authorize_tool_call(context, "lookup", {"id": "42"})
    governed.record_tool_call(
        context,
        "lookup",
        {"id": "42"},
        "found",
        authorization=authorization,
    )

    telemetry = GovernanceTelemetry.from_metadata(context.metadata)
    assert authorization.effective_action_id == "safe_lookup"
    assert telemetry.tool_usage[0].tool_name == "safe_lookup"
    assert context.tool_calls[0]["name"] == "safe_lookup"


def test_capture_emits_policy_and_episode_audit_events() -> None:
    audit = InMemoryAuditSink()
    governed = GovernedEpisodeCapture(
        _Policy(),
        capture=_Capture(),
        audit_sink=audit,
    )

    context = governed.start("clean", action_id="search")
    governed.end(context, "done", execution_status="completed")

    events = audit.query(agent_id="agent-1")
    assert {event.event_type for event in events} == {
        AuditEventType.POLICY_EVALUATED,
        AuditEventType.EPISODE_CAPTURED,
    }


def test_capture_does_not_audit_episode_when_persistence_is_missing() -> None:
    class MissingStore:
        def get_episode(self, episode_id: str, agent_id: str) -> None:
            del episode_id, agent_id

    audit = InMemoryAuditSink()
    capture = _Capture()
    capture.store = MissingStore()
    governed = GovernedEpisodeCapture(_Policy(), capture=capture, audit_sink=audit)
    context = governed.start("clean", action_id="search")

    with pytest.raises(EpisodePersistenceError, match="did not persist"):
        governed.end(context, "done", execution_status="completed")

    assert [event.event_type for event in audit.query(agent_id="agent-1")] == [
        AuditEventType.POLICY_EVALUATED
    ]
