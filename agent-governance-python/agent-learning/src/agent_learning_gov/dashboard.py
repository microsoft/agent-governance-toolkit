# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Read-only dashboard projections for governed Agent Learning artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .audit import AuditSink
from .models import GOVERNANCE_METADATA_KEY, GovernanceTelemetry


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class GovernanceDashboardSnapshot:
    """Privacy-conscious projection of one governed agent task."""

    agent_id: str
    task_id: str
    summary: Mapping[str, Any]
    episodes: tuple[Mapping[str, Any], ...]
    rewards: tuple[Mapping[str, Any], ...]
    policies: tuple[Mapping[str, Any], ...]
    training_runs: tuple[Mapping[str, Any], ...]
    promotion_events: tuple[Mapping[str, Any], ...]
    audit_events: tuple[Mapping[str, Any], ...]
    generated_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "summary": dict(self.summary),
            "episodes": [dict(item) for item in self.episodes],
            "rewards": [dict(item) for item in self.rewards],
            "policies": [dict(item) for item in self.policies],
            "training_runs": [dict(item) for item in self.training_runs],
            "promotion_events": [dict(item) for item in self.promotion_events],
            "audit_events": [dict(item) for item in self.audit_events],
            "generated_at": self.generated_at,
        }


class LearningGovernanceDashboardModel:
    """Aggregate governed episodes, rewards, runs, lineage, and promotions."""

    def __init__(self, store: Any, *, audit_sink: AuditSink | None = None) -> None:
        self.store = store
        self.audit_sink = audit_sink

    def snapshot(
        self,
        agent_id: str,
        *,
        task_id: str = "default",
        limit: int = 100,
    ) -> GovernanceDashboardSnapshot:
        if limit < 1:
            raise ValueError("limit must be at least one")
        episodes = self.store.query_episodes(
            agent_id,
            task_id=task_id,
            full_only=False,
            limit=limit,
        )
        episode_ids = {episode.id for episode in episodes}
        rewards = [
            reward
            for reward in self.store.query_rewards(agent_id, limit=max(limit * 10, 100))
            if reward.episode_id in episode_ids
        ]
        policies = self.store.list_policies(agent_id, task_id, limit=limit)
        runs = [
            run
            for run in self.store.list_training_runs(agent_id, limit=limit)
            if run.task_id == task_id
        ]
        candidate_policies = [
            candidate for run in runs if (candidate := _candidate_policy(run.metadata)) is not None
        ]
        known_policy_ids = {policy.id for policy in policies}
        policies = [
            *candidate_policies,
            *(
                policy
                for policy in policies
                if policy.id
                not in known_policy_ids.intersection(
                    {candidate.id for candidate in candidate_policies}
                )
            ),
        ]

        episode_rows = tuple(_episode_row(episode) for episode in episodes)
        reward_rows = tuple(_reward_row(reward) for reward in rewards)
        policy_rows = tuple(_policy_row(policy) for policy in policies)
        run_rows = tuple(_run_row(run) for run in runs)
        promotion_events = tuple(
            event for policy in policies for event in _policy_promotion_history(policy)
        )
        audit_events = tuple(
            event.to_dict()
            for event in (
                self.audit_sink.query(agent_id=agent_id, limit=limit)
                if self.audit_sink is not None
                else []
            )
            if event.task_id == task_id
        )

        governed = [row for row in episode_rows if row["governed"]]
        violation_count = sum(row["violation_count"] for row in episode_rows)
        violating_episodes = sum(row["violation_count"] > 0 for row in governed)
        denied_count = sum(row["denied_action_count"] for row in episode_rows)
        aggregate_rewards = [
            row["final_reward"] for row in reward_rows if row["source"] == "aggregate"
        ]
        summary = {
            "episodes": len(episode_rows),
            "governed_episodes": len(governed),
            "reinforce_eligible_episodes": sum(
                row["reinforce_eligible"] == True for row in episode_rows
            ),
            "bayesian_episodes": sum(
                row["selection_basis"] == "bayesian_decision" for row in episode_rows
            ),
            "violations": violation_count,
            "denied_actions": denied_count,
            "violation_rate": violating_episodes / len(governed) if governed else 0.0,
            "average_aggregate_reward": (
                sum(aggregate_rewards) / len(aggregate_rewards) if aggregate_rewards else 0.0
            ),
            "policy_versions": len(policy_rows),
            "training_runs": len(run_rows),
            "promotion_events": len(promotion_events),
        }
        return GovernanceDashboardSnapshot(
            agent_id=agent_id,
            task_id=task_id,
            summary=summary,
            episodes=episode_rows,
            rewards=reward_rows,
            policies=policy_rows,
            training_runs=run_rows,
            promotion_events=promotion_events,
            audit_events=audit_events,
        )


def _episode_row(episode: Any) -> dict[str, Any]:
    telemetry = GovernanceTelemetry.from_metadata(episode.metadata)
    return {
        "episode_id": episode.id,
        "created_at": episode.created_at,
        "policy_id": episode.policy_id,
        "policy_version": episode.policy_version,
        "action_id": episode.action_id,
        "execution_status": episode.execution_status,
        "selection_basis": telemetry.selection_basis,
        "reinforce_eligible": telemetry.reinforce_eligible,
        "governed": bool(telemetry.decisions or telemetry.violations or telemetry.tool_usage),
        "decision_count": len(telemetry.decisions),
        "violation_count": len(telemetry.violations),
        "denied_action_count": sum(violation.blocked for violation in telemetry.violations),
        "tool_call_count": len(telemetry.tool_usage),
        "risk_levels": sorted({violation.severity.value for violation in telemetry.violations}),
    }


def _reward_row(reward: Any) -> dict[str, Any]:
    source = getattr(reward.source, "value", reward.source)
    namespace = reward.metadata.get(GOVERNANCE_METADATA_KEY, {})
    shaping = namespace.get("reward_shaping", {}) if isinstance(namespace, Mapping) else {}
    return {
        "reward_id": reward.id,
        "episode_id": reward.episode_id,
        "source": source,
        "final_reward": reward.value,
        "base_reward": shaping.get("base_reward", reward.value),
        "governance_bonus": shaping.get("governance_bonus", 0.0),
        "violation_penalty": shaping.get("violation_penalty", 0.0),
        "created_at": reward.created_at,
    }


def _policy_row(policy: Any) -> dict[str, Any]:
    namespace = policy.metadata.get(GOVERNANCE_METADATA_KEY, {})
    promotion = namespace.get("promotion", {}) if isinstance(namespace, Mapping) else {}
    lineage = namespace.get("lineage", {}) if isinstance(namespace, Mapping) else {}
    return {
        "policy_id": policy.id,
        "version": policy.version,
        "created_at": policy.created_at,
        "episodes_seen": policy.episodes_seen,
        "updates_applied": policy.updates_applied,
        "action_count": len(policy.actions),
        "promotion_status": promotion.get(
            "status",
            namespace.get("promotion_status") if isinstance(namespace, Mapping) else None,
        ),
        "promotion_stage": promotion.get("stage"),
        "parent_policy_id": lineage.get("parent_policy_id"),
        "training_run_id": lineage.get("training_run_id"),
    }


def _run_row(run: Any) -> dict[str, Any]:
    status = getattr(run.status, "value", run.status)
    namespace = run.metadata.get(GOVERNANCE_METADATA_KEY, {})
    report = namespace.get("report", {}) if isinstance(namespace, Mapping) else {}
    return {
        "run_id": run.id,
        "policy_id": run.policy_id,
        "algorithm": run.algorithm,
        "status": status,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "episode_count": len(run.episode_ids),
        "reinforce_eligible_episodes": report.get("reinforce_eligible_episodes"),
        "candidate_policy_id": report.get("candidate_policy_id"),
        "candidate_policy_compliant": report.get("candidate_policy_compliant"),
    }


def _policy_promotion_history(policy: Any) -> list[dict[str, Any]]:
    namespace = policy.metadata.get(GOVERNANCE_METADATA_KEY, {})
    promotion = namespace.get("promotion", {}) if isinstance(namespace, Mapping) else {}
    history = promotion.get("history", []) if isinstance(promotion, Mapping) else []
    return [
        {"policy_id": policy.id, "policy_version": policy.version, **dict(item)}
        for item in history
        if isinstance(item, Mapping)
    ]


def _candidate_policy(metadata: Mapping[str, Any]) -> Any | None:
    namespace = metadata.get(GOVERNANCE_METADATA_KEY, {})
    candidate = namespace.get("candidate_policy") if isinstance(namespace, Mapping) else None
    if not isinstance(candidate, Mapping):
        return None
    try:
        from agent_learning import PolicySnapshot
    except ImportError:
        return None
    return PolicySnapshot.from_dict(dict(candidate))


__all__ = [
    "GovernanceDashboardSnapshot",
    "LearningGovernanceDashboardModel",
]
