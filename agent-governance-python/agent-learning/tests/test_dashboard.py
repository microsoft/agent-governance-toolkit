# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the learning governance dashboard projection."""

from __future__ import annotations

from types import SimpleNamespace

from agent_learning_gov import (
    AuditEvent,
    AuditEventType,
    GovernanceOutcome,
    GovernanceTelemetry,
    GovernanceViolation,
    InMemoryAuditSink,
    LearningGovernanceDashboardModel,
    PolicyDecisionRecord,
    RiskLevel,
)


class _Store:
    def __init__(self, episode, reward, policy, run) -> None:
        self.episode = episode
        self.reward = reward
        self.policy = policy
        self.run = run

    def query_episodes(self, agent_id: str, **kwargs):
        del agent_id, kwargs
        return [self.episode]

    def query_rewards(self, agent_id: str, **kwargs):
        del agent_id, kwargs
        return [self.reward]

    def list_policies(self, agent_id: str, task_id: str, **kwargs):
        del agent_id, task_id, kwargs
        return [self.policy]

    def list_training_runs(self, agent_id: str, **kwargs):
        del agent_id, kwargs
        return [self.run]


def test_dashboard_projects_governance_without_raw_episode_content() -> None:
    telemetry = GovernanceTelemetry(
        decisions=(
            PolicyDecisionRecord(
                policy_name="policy",
                action_id="search",
                outcome=GovernanceOutcome.DENIED,
                risk_level=RiskLevel.HIGH,
            ),
        ),
        violations=(
            GovernanceViolation(
                policy_name="policy",
                description="blocked",
                severity=RiskLevel.HIGH,
                action_id="search",
                blocked=True,
            ),
            GovernanceViolation(
                policy_name="policy",
                description="warned",
                severity=RiskLevel.LOW,
                action_id="search",
                blocked=False,
            ),
        ),
        selection_basis="bayesian_decision",
        reinforce_eligible=False,
    )
    episode = SimpleNamespace(
        id="episode-1",
        created_at="2026-08-10T00:00:00+00:00",
        policy_id="policy-1",
        policy_version=1,
        action_id="search",
        execution_status="governance_denied",
        user_input="private prompt",
        assistant_output="private output",
        metadata=telemetry.merge_metadata(),
    )
    reward = SimpleNamespace(
        id="reward-1",
        episode_id="episode-1",
        source="aggregate",
        value=-0.5,
        created_at="2026-08-10T00:00:01+00:00",
        metadata={
            "agent_governance": {
                "reward_shaping": {
                    "base_reward": 0.25,
                    "governance_bonus": 0.0,
                    "violation_penalty": -0.75,
                }
            }
        },
    )
    policy = SimpleNamespace(
        id="policy-1",
        version=1,
        created_at="2026-08-10T00:00:00+00:00",
        episodes_seen=1,
        updates_applied=1,
        actions=[SimpleNamespace(id="search")],
        metadata={
            "agent_governance": {
                "promotion": {
                    "status": "blocked",
                    "stage": "canary",
                    "history": [{"stage": "canary", "status": "blocked"}],
                }
            }
        },
    )
    run = SimpleNamespace(
        id="run-1",
        task_id="task-1",
        policy_id="policy-1",
        algorithm="ReinforceLearner",
        status="succeeded",
        started_at="2026-08-10T00:00:00+00:00",
        completed_at="2026-08-10T00:00:02+00:00",
        episode_ids=["episode-1"],
        metadata={"agent_governance": {"report": {}}},
    )
    audit = InMemoryAuditSink()
    audit.emit(
        AuditEvent(
            event_type=AuditEventType.PROMOTION_BLOCKED,
            agent_id="agent-1",
            task_id="task-1",
            artifact_type="policy",
            artifact_id="policy-1",
            outcome="blocked",
        )
    )
    model = LearningGovernanceDashboardModel(
        _Store(episode, reward, policy, run),
        audit_sink=audit,
    )

    snapshot = model.snapshot("agent-1", task_id="task-1")
    payload = snapshot.to_dict()

    assert payload["summary"]["bayesian_episodes"] == 1
    assert payload["summary"]["denied_actions"] == 1
    assert payload["summary"]["violations"] == 2
    assert payload["summary"]["violation_rate"] == 1.0
    assert payload["summary"]["promotion_events"] == 1
    assert payload["rewards"][0]["base_reward"] == 0.25
    assert "user_input" not in payload["episodes"][0]
    assert "assistant_output" not in payload["episodes"][0]
