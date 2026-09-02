# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end Agent Learning 0.8 governance lifecycle without cloud services."""

from __future__ import annotations

import json
import math
import secrets

from agent_learning import (
    Action,
    CaptureConfig,
    DecisionAuthority,
    DecisionCriterion,
    DecisionFrame,
    DecisionOption,
    EvidencePoint,
    InMemoryStore,
    LearningRunner,
    Reward,
    RewardSource,
    SoftmaxPolicy,
    TaskPolicy,
)
from agent_os.lite import govern

from agent_learning_gov import (
    GovernedEpisodeCapture,
    GovernedLearningRunner,
    GovernedPolicyPromotion,
    InMemoryAuditSink,
    LearningGovernanceDashboardModel,
    PromotionStage,
)

AGENT_ID = "account-agent"
TASK_ID = "choose-summary-strategy"


def _capture_learned_episodes(
    capture: GovernedEpisodeCapture,
    store: InMemoryStore,
    policy: SoftmaxPolicy,
) -> None:
    for index in range(6):
        action_id = "grounded_summary" if index % 3 else "fast_summary"
        task_policy = TaskPolicy(policy.snapshot())
        decision = task_policy.adjudicate(
            task_policy.decide(selected_action_id=action_id),
            "accept",
        )
        context = capture.start(
            f"Summarize account {index}",
            decision_result=decision,
            intent_summary="summarize an account",
            action_type="workflow",
            expected_outcome="return a concise grounded summary",
        )
        authorization = capture.authorize_tool_call(
            context,
            "read_customer_profile",
            {"account_id": f"account-{index}"},
        )
        capture.record_tool_call(
            context,
            "read_customer_profile",
            {"account_id": f"account-{index}"},
            "profile loaded",
            authorization=authorization,
            cost=0.01,
        )
        grounded = context.action_id == "grounded_summary"
        episode = capture.end(
            context,
            "Grounded account summary" if grounded else "Fast account summary",
            execution_status="completed",
            result_summary="returned the requested summary",
        )
        store.store_reward(
            Reward(
                episode_id=episode.id,
                agent_id=episode.agent_id,
                source=RewardSource.AGGREGATE,
                value=0.85 if grounded else 0.25,
            )
        )


def _capture_bayesian_episode(
    capture: GovernedEpisodeCapture,
    store: InMemoryStore,
    policy: SoftmaxPolicy,
) -> None:
    snapshot = policy.snapshot()
    snapshot.metadata["decision_authority"] = DecisionAuthority.FULL.value
    actions = {action.id: action for action in snapshot.actions}
    frame = DecisionFrame(
        task="Choose a summary strategy for a regulated account",
        criteria=[
            DecisionCriterion(id="grounding", weight=0.7),
            DecisionCriterion(id="latency", weight=0.3),
        ],
        constraints=["data_residency"],
        options=[
            DecisionOption(
                action=actions["grounded_summary"],
                constraint_results={"data_residency": True},
                evidence=[
                    EvidencePoint(
                        criterion_id="grounding",
                        source="evaluation",
                        support=0.95,
                    ),
                    EvidencePoint(
                        criterion_id="latency",
                        source="telemetry",
                        support=0.70,
                    ),
                ],
            ),
            DecisionOption(
                action=actions["fast_summary"],
                constraint_results={"data_residency": True},
                evidence=[
                    EvidencePoint(
                        criterion_id="grounding",
                        source="evaluation",
                        support=0.45,
                    ),
                    EvidencePoint(
                        criterion_id="latency",
                        source="telemetry",
                        support=0.90,
                    ),
                ],
            ),
        ],
    )
    task_policy = TaskPolicy(snapshot)
    decision = task_policy.decide(frame)
    if decision.status.value != "resolved":
        decision = task_policy.adjudicate(decision, "accept")
    context = capture.start(
        "Summarize the regulated account",
        decision_result=decision,
        intent_summary="summarize a regulated account",
        action_type="workflow",
        expected_outcome="return a compliant grounded summary",
    )
    episode = capture.end(
        context,
        "Grounded regulated-account summary",
        execution_status="completed",
        result_summary="returned a compliant summary",
    )
    assert episode.action_logprob is None
    store.store_reward(
        Reward(
            episode_id=episode.id,
            agent_id=episode.agent_id,
            source=RewardSource.AGGREGATE,
            value=0.90,
        )
    )


def main() -> None:
    store = InMemoryStore()
    audit = InMemoryAuditSink()
    provenance_key = secrets.token_bytes(32)
    kernel = govern(deny=["delete_records"])
    policy = SoftmaxPolicy.from_actions(
        [
            Action(
                id="grounded_summary",
                parameters={"role": "user", "estimated_cost": 0.02},
            ),
            Action(
                id="fast_summary",
                parameters={"role": "user", "estimated_cost": 0.01},
            ),
        ],
        agent_id=AGENT_ID,
        task_id=TASK_ID,
    )
    store.store_policy(policy.snapshot())
    capture = GovernedEpisodeCapture(
        kernel,
        config=CaptureConfig(
            enabled=True,
            agent_id=AGENT_ID,
            task_id=TASK_ID,
        ),
        store=store,
        audit_sink=audit,
        provenance_key=provenance_key,
    )

    _capture_learned_episodes(capture, store, policy)
    _capture_bayesian_episode(capture, store, policy)

    learning = LearningRunner(store=store, policy=policy, metrics=[])
    governed = GovernedLearningRunner(
        kernel,
        learning,
        audit_sink=audit,
        provenance_key=provenance_key,
    )
    run = governed.run_offline_batch(
        AGENT_ID,
        task_id=TASK_ID,
        score_missing=False,
    )
    candidate = governed.last_candidate
    assert candidate is not None
    assert run.metrics["episodes_used"] == 6
    assert run.metrics["governance"]["bayesian_episodes"] == 1
    assert store.get_active_policy(AGENT_ID, TASK_ID).id != candidate.id

    promoter = GovernedPolicyPromotion(
        kernel,
        store=store,
        audit_sink=audit,
        provenance_key=provenance_key,
        deploy_callback=lambda snapshot, stage, context: {
            "policy_id": snapshot.id,
            "stage": stage.value,
            "traffic_percent": context.get("traffic_percent", 100),
        },
    )
    canary = promoter.promote_if_compliant(
        candidate,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
        deployment_context={"traffic_percent": 5},
    )
    production = promoter.promote_if_compliant(
        candidate.id,
        agent_id=AGENT_ID,
        task_id=TASK_ID,
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )
    assert canary.promoted and production.promoted
    assert store.get_active_policy(AGENT_ID, TASK_ID).id == candidate.id

    dashboard = LearningGovernanceDashboardModel(store, audit_sink=audit).snapshot(
        AGENT_ID,
        task_id=TASK_ID,
    )
    print(json.dumps(dashboard.summary, indent=2, sort_keys=True))
    print(
        "learned distribution:",
        {
            action.id: round(probability, 3)
            for action, probability in zip(
                candidate.actions,
                SoftmaxPolicy.from_snapshot(candidate).probabilities(),
            )
        },
    )
    assert math.isclose(sum(SoftmaxPolicy.from_snapshot(candidate).probabilities()), 1.0)


if __name__ == "__main__":
    main()
