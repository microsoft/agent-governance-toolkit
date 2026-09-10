# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Integration tests against the Agent Learning 0.8.x lifecycle."""

from __future__ import annotations

import math
from types import SimpleNamespace
from typing import Any

import pytest

agent_learning = pytest.importorskip("agent_learning")
if not agent_learning.__version__.startswith("0.8."):
    pytest.skip("Agent Learning 0.8.x is required", allow_module_level=True)

from agent_learning import (
    Action,
    Episode,
    InMemoryStore,
    LearningRunner,
    PolicySnapshot,
    Reward,
    RewardSource,
    SoftmaxPolicy,
)

from agent_learning_gov import (
    GovernanceOutcome,
    GovernanceTelemetry,
    GovernanceViolation,
    GovernedLearningRunner,
    InMemoryAuditSink,
    PolicyDecisionRecord,
    RiskLevel,
)
from agent_learning_gov.provenance import sign_decision_certificate, verify_candidate

PROVENANCE_KEY = b"agent-learning-governance-test-key"


class _AllowPolicy:
    name = "allow-policy"

    def evaluate(self, action: str, context: dict[str, Any]) -> Any:
        del action, context
        return SimpleNamespace(allowed=True, reason="allowed")


def _episode(
    episode_id: str,
    *,
    policy: PolicySnapshot,
    action_id: str,
    selection_basis: str,
    reinforce_eligible: bool | None,
    action_logprob: float | None,
) -> Episode:
    decision_certificate = sign_decision_certificate(
        {
            "episode_id": episode_id,
            "agent_id": policy.agent_id,
            "task_id": policy.task_id,
            "policy_id": policy.id,
            "policy_version": policy.version,
            "status": "resolved",
            "selection_basis": selection_basis,
            "selected_action_id": action_id,
            "action_logprob": action_logprob,
            "action_probabilities": (
                {
                    action.id: math.exp(action_logprob) if action.id == action_id else 0.5
                    for action in policy.actions
                }
                if action_logprob is not None and math.isfinite(action_logprob)
                else {action.id: 0.5 for action in policy.actions}
            ),
        },
        PROVENANCE_KEY,
    )
    telemetry = GovernanceTelemetry(
        selection_basis=selection_basis,
        reinforce_eligible=reinforce_eligible,
        metadata={"decision_certificate": decision_certificate},
    )
    return Episode(
        id=episode_id,
        agent_id="agent-1",
        task_id="choose-action",
        user_input="choose",
        assistant_output="done",
        intent_summary="choose an action",
        expected_outcome="complete the choice",
        execution_status="completed",
        policy_id=policy.id,
        policy_version=policy.version,
        result_summary="choice completed",
        action_id=action_id,
        action_logprob=action_logprob,
        metadata=telemetry.merge_metadata(),
    )


def test_bayesian_episodes_are_scored_but_excluded_from_reinforce() -> None:
    store = InMemoryStore()
    policy = SoftmaxPolicy.from_actions(
        [Action(id="east"), Action(id="west")],
        agent_id="agent-1",
        task_id="choose-action",
    )
    parent = policy.snapshot()
    store.store_policy(parent)
    learned = _episode(
        "learned",
        policy=parent,
        action_id="east",
        selection_basis="learned_policy",
        reinforce_eligible=True,
        action_logprob=math.log(0.5),
    )
    bayesian = _episode(
        "bayesian",
        policy=parent,
        action_id="west",
        selection_basis="bayesian_decision",
        reinforce_eligible=False,
        action_logprob=None,
    )
    for episode in (learned, bayesian):
        store.store_episode(episode)
        store.store_reward(
            Reward(
                episode_id=episode.id,
                agent_id=episode.agent_id,
                source=RewardSource.AGGREGATE,
                value=0.8,
            )
        )

    audit = InMemoryAuditSink()
    runner = GovernedLearningRunner(
        _AllowPolicy(),
        LearningRunner(store=store, policy=policy, metrics=[]),
        audit_sink=audit,
        provenance_key=PROVENANCE_KEY,
    )

    run = runner.run_offline_batch(
        "agent-1",
        task_id="choose-action",
        score_missing=False,
    )

    assert run.status.value == "succeeded"
    assert run.metrics["episodes_used"] == 1
    report = run.metrics["governance"]
    assert report["episodes_considered"] == 2
    assert report["reinforce_eligible_episodes"] == 1
    assert report["bayesian_episodes"] == 1
    assert report["shaped_rewards"] == 2
    assert len(audit.query(agent_id="agent-1")) == 6


def test_candidate_policy_records_governance_lineage() -> None:
    store = InMemoryStore()
    policy = SoftmaxPolicy.from_actions(
        [Action(id="east"), Action(id="west")],
        agent_id="agent-1",
        task_id="choose-action",
    )
    parent = policy.snapshot()
    store.store_policy(parent)
    episode = _episode(
        "learned",
        policy=parent,
        action_id="east",
        selection_basis="learned_policy",
        reinforce_eligible=True,
        action_logprob=math.log(0.5),
    )
    store.store_episode(episode)
    store.store_reward(
        Reward(
            episode_id=episode.id,
            agent_id=episode.agent_id,
            source=RewardSource.AGGREGATE,
            value=0.8,
        )
    )
    runner = GovernedLearningRunner(
        _AllowPolicy(),
        LearningRunner(store=store, policy=policy, metrics=[]),
        provenance_key=PROVENANCE_KEY,
    )

    run = runner.run_offline_batch(
        "agent-1",
        task_id="choose-action",
        score_missing=False,
    )
    candidate = PolicySnapshot.from_dict(run.metadata["agent_governance"]["candidate_policy"])

    governance = candidate.metadata["agent_governance"]
    assert governance["lineage"]["parent_policy_id"] == parent.id
    assert governance["lineage"]["training_run_id"] == run.id
    assert governance["promotion_status"] == "pending_validation"
    assert verify_candidate(candidate, PROVENANCE_KEY)
    assert len(governance["decisions"]) == 2
    assert runner.last_candidate.to_dict() == candidate.to_dict()
    assert store.get_active_policy("agent-1", "choose-action").id == parent.id
    assert len(store.list_policies("agent-1", "choose-action")) == 1


def test_unannotated_episode_without_logprob_is_excluded_from_reinforce() -> None:
    store = InMemoryStore()
    policy = SoftmaxPolicy.from_actions(
        [Action(id="east"), Action(id="west")],
        agent_id="agent-1",
        task_id="choose-action",
    )
    store.store_policy(policy.snapshot())
    episode = Episode(
        id="unannotated",
        agent_id="agent-1",
        task_id="choose-action",
        user_input="choose",
        assistant_output="done",
        execution_status="completed",
        action_id="east",
        action_logprob=None,
    )
    store.store_episode(episode)
    store.store_reward(
        Reward(
            episode_id=episode.id,
            agent_id=episode.agent_id,
            source=RewardSource.AGGREGATE,
            value=0.8,
        )
    )
    runner = GovernedLearningRunner(
        _AllowPolicy(),
        LearningRunner(store=store, policy=policy, metrics=[]),
        provenance_key=PROVENANCE_KEY,
    )

    run = runner.run_offline_batch(
        "agent-1",
        task_id="choose-action",
        score_missing=False,
    )

    assert run.metrics["episodes_used"] == 0
    assert run.metrics["governance"]["reinforce_eligible_episodes"] == 0


@pytest.mark.parametrize(
    "malformation",
    [
        "missing_eligibility",
        "nonfinite_logprob",
        "wrong_policy",
        "wrong_action",
        "wrong_probability",
        "unsigned",
        "wrong_episode",
    ],
)
def test_malformed_decision_provenance_is_excluded_from_reinforce(
    malformation: str,
) -> None:
    store = InMemoryStore()
    policy = SoftmaxPolicy.from_actions(
        [Action(id="east"), Action(id="west")],
        agent_id="agent-1",
        task_id="choose-action",
    )
    parent = policy.snapshot()
    store.store_policy(parent)
    episode = _episode(
        "malformed",
        policy=parent,
        action_id="east",
        selection_basis="learned_policy",
        reinforce_eligible=True,
        action_logprob=math.log(0.5),
    )
    governance = episode.metadata["agent_governance"]
    certificate = governance["metadata"]["decision_certificate"]
    if malformation == "missing_eligibility":
        governance["reinforce_eligible"] = None
    elif malformation == "nonfinite_logprob":
        episode.action_logprob = float("nan")
        certificate["action_logprob"] = float("nan")
    elif malformation == "wrong_policy":
        episode.policy_id = "other-policy"
        certificate["policy_id"] = "other-policy"
    elif malformation == "wrong_action":
        certificate["selected_action_id"] = "west"
    elif malformation == "wrong_probability":
        certificate["action_probabilities"]["east"] = 0.75
    elif malformation == "unsigned":
        certificate.pop("provenance")
    else:
        certificate["episode_id"] = "another-episode"
    store.store_episode(episode)
    store.store_reward(
        Reward(
            episode_id=episode.id,
            agent_id=episode.agent_id,
            source=RewardSource.AGGREGATE,
            value=0.8,
        )
    )
    runner = GovernedLearningRunner(
        _AllowPolicy(),
        LearningRunner(store=store, policy=policy, metrics=[]),
        provenance_key=PROVENANCE_KEY,
    )

    run = runner.run_offline_batch(
        "agent-1",
        task_id="choose-action",
        score_missing=False,
    )

    assert run.metrics["episodes_used"] == 0
    assert run.metrics["governance"]["reinforce_eligible_episodes"] == 0


def test_signed_decision_certificate_cannot_be_replayed_for_another_episode() -> None:
    store = InMemoryStore()
    policy = SoftmaxPolicy.from_actions(
        [Action(id="east"), Action(id="west")],
        agent_id="agent-1",
        task_id="choose-action",
    )
    parent = policy.snapshot()
    store.store_policy(parent)
    original = _episode(
        "original",
        policy=parent,
        action_id="east",
        selection_basis="learned_policy",
        reinforce_eligible=True,
        action_logprob=math.log(0.5),
    )
    replay = Episode.from_dict(original.to_dict())
    replay.id = "replay"
    for episode in (original, replay):
        store.store_episode(episode)
        store.store_reward(
            Reward(
                episode_id=episode.id,
                agent_id=episode.agent_id,
                source=RewardSource.AGGREGATE,
                value=0.8,
            )
        )
    runner = GovernedLearningRunner(
        _AllowPolicy(),
        LearningRunner(store=store, policy=policy, metrics=[]),
        provenance_key=PROVENANCE_KEY,
    )

    run = runner.run_offline_batch(
        "agent-1",
        task_id="choose-action",
        score_missing=False,
    )

    assert run.metrics["episodes_used"] == 1
    assert run.metrics["governance"]["reinforce_eligible_episodes"] == 1


def test_blocked_episode_is_not_sent_to_missing_reward_scorer() -> None:
    store = InMemoryStore()
    policy = SoftmaxPolicy.from_actions(
        [Action(id="east"), Action(id="west")],
        agent_id="agent-1",
        task_id="choose-action",
    )
    store.store_policy(policy.snapshot())
    decision = PolicyDecisionRecord(
        policy_name="deny-policy",
        action_id="east",
        outcome=GovernanceOutcome.DENIED,
        risk_level=RiskLevel.HIGH,
    )
    violation = GovernanceViolation(
        policy_name="deny-policy",
        description="blocked",
        severity=RiskLevel.HIGH,
        action_id="east",
        blocked=True,
        decision_id=decision.id,
    )
    telemetry = GovernanceTelemetry(
        decisions=(decision,),
        violations=(violation,),
        selection_basis="learned_policy",
        reinforce_eligible=True,
    )
    episode = Episode(
        id="blocked",
        agent_id="agent-1",
        task_id="choose-action",
        user_input="private denied prompt",
        assistant_output="",
        execution_status="governance_denied",
        action_id="east",
        action_logprob=math.log(0.5),
        metadata=telemetry.merge_metadata(),
    )
    store.store_episode(episode)
    learning = LearningRunner(store=store, policy=policy, metrics=[])
    scored: list[str] = []
    learning.score_and_record = lambda item: scored.append(item.id)
    runner = GovernedLearningRunner(
        _AllowPolicy(),
        learning,
        provenance_key=PROVENANCE_KEY,
    )

    run = runner.run_offline_batch(
        "agent-1",
        task_id="choose-action",
        score_missing=True,
    )

    assert scored == []
    assert run.metrics["episodes_used"] == 0
