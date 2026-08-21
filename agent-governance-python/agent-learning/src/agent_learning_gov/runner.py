# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governed offline learning orchestration for Agent Learning 0.8.x."""

from __future__ import annotations

import copy
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from .audit import AuditEvent, AuditEventType, AuditSink, emit_audit_event
from .models import (
    GOVERNANCE_METADATA_KEY,
    GovernanceTelemetry,
)
from .policy import GovernanceDeniedError, PolicyEvaluation, PolicyEvaluatorAdapter
from .provenance import (
    candidate_provenance,
    resolve_provenance_key,
    verify_decision_certificate,
)
from .reward import PolicyAwareRewardAdapter


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class LearningGovernanceReport:
    """Governance summary for one offline learning run."""

    run_id: str
    agent_id: str
    task_id: str
    episodes_considered: int
    reinforce_eligible_episodes: int
    bayesian_episodes: int
    excluded_episodes: int
    shaped_rewards: int
    episode_violations: int
    denied_episode_actions: int
    candidate_policy_id: str
    candidate_policy_version: int
    candidate_policy_compliant: bool
    candidate_policy_violations: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "episodes_considered": self.episodes_considered,
            "reinforce_eligible_episodes": self.reinforce_eligible_episodes,
            "bayesian_episodes": self.bayesian_episodes,
            "excluded_episodes": self.excluded_episodes,
            "shaped_rewards": self.shaped_rewards,
            "episode_violations": self.episode_violations,
            "denied_episode_actions": self.denied_episode_actions,
            "candidate_policy_id": self.candidate_policy_id,
            "candidate_policy_version": self.candidate_policy_version,
            "candidate_policy_compliant": self.candidate_policy_compliant,
            "candidate_policy_violations": self.candidate_policy_violations,
        }


class GovernedLearningRunner:
    """Run Agent Learning offline batches under AGT governance controls."""

    def __init__(
        self,
        kernel: Any,
        learning_runner: Any,
        *,
        store: Any | None = None,
        policy: Any | None = None,
        learner: Any | None = None,
        reward_adapter: PolicyAwareRewardAdapter | None = None,
        audit_sink: AuditSink | None = None,
        fail_closed: bool = True,
        fail_on_violation: bool = False,
        policy_name: str | None = None,
        provenance_key: bytes | str | None = None,
    ) -> None:
        self.learning_runner = learning_runner
        self.store = _resolve_component(store, learning_runner, "_store", "store")
        self.policy = _resolve_component(policy, learning_runner, "_policy", "policy")
        self.learner = _resolve_component(learner, learning_runner, "_learner", "learner")
        self.policy_evaluator = PolicyEvaluatorAdapter(
            kernel,
            fail_closed=fail_closed,
            policy_name=policy_name,
        )
        self.audit_sink = audit_sink
        self.reward_adapter = reward_adapter or PolicyAwareRewardAdapter(
            store=self.store,
            audit_sink=audit_sink,
        )
        if self.reward_adapter.store is None:
            self.reward_adapter.store = self.store
        if self.reward_adapter.audit_sink is None:
            self.reward_adapter.audit_sink = audit_sink
        self.fail_on_violation = fail_on_violation
        self._provenance_key = resolve_provenance_key(provenance_key)
        self._last_report: LearningGovernanceReport | None = None
        self._last_candidate: Any | None = None
        self._runs_completed = 0
        self._runs_failed = 0

    @property
    def last_report(self) -> LearningGovernanceReport | None:
        return self._last_report

    @property
    def last_candidate(self) -> Any | None:
        """Return an isolated copy of the most recent policy candidate."""
        return copy.deepcopy(self._last_candidate)

    def run_offline_batch(
        self,
        agent_id: str,
        *,
        task_id: str = "default",
        episode_limit: int = 200,
        start_date: str | None = None,
        end_date: str | None = None,
        score_missing: bool = True,
    ) -> Any:
        """Score all episodes, learn only from governance-eligible episodes."""
        if episode_limit < 1:
            raise ValueError("episode_limit must be at least one")
        try:
            from agent_learning import TrainingRun, TrainingStatus
        except ImportError as exc:
            raise ImportError(
                "Install agent-learning>=0.8.0,<0.9.0 to run offline learning"
            ) from exc

        parent_snapshot = self.policy.snapshot()
        if parent_snapshot.agent_id != agent_id or parent_snapshot.task_id != task_id:
            raise ValueError("The supplied policy must belong to the requested agent and task")

        run = TrainingRun(
            agent_id=agent_id,
            task_id=task_id,
            policy_id=parent_snapshot.id,
            algorithm=type(self.learner).__name__,
            status=TrainingStatus.RUNNING,
            started_at=_utcnow_iso(),
        )
        self.store.store_run(run)
        emit_audit_event(
            self.audit_sink,
            AuditEvent(
                event_type=AuditEventType.LEARNING_RUN_STARTED,
                agent_id=agent_id,
                task_id=task_id,
                artifact_type="training_run",
                artifact_id=run.id,
                outcome="running",
                policy_id=parent_snapshot.id,
                policy_version=parent_snapshot.version,
            ),
        )

        try:
            episodes = self.store.query_episodes(
                agent_id,
                limit=episode_limit,
                start_date=start_date,
                end_date=end_date,
                task_id=task_id,
                full_only=True,
            )
            governed_episodes = [self._ensure_governance(episode) for episode in episodes]
            blocked = [
                evaluation
                for _, evaluation in governed_episodes
                if evaluation is not None and not evaluation.allowed
            ]
            if blocked and self.fail_on_violation:
                raise GovernanceDeniedError(blocked[0])

            all_rewards: list[Any] = []
            shaped_rewards = 0
            for episode, _ in governed_episodes:
                blocked_episode = _has_blocking_violation(episode)
                if not blocked_episode and not self._has_usable_reward(episode) and score_missing:
                    self.learning_runner.score_and_record(episode)
                episode_rewards = self.store.get_rewards_for_episode(
                    episode.id,
                    agent_id,
                )
                adapted = self.reward_adapter.adapt_rewards(
                    episode,
                    episode_rewards,
                    persist=True,
                )
                shaped_rewards += sum(_is_aggregate(reward) for reward in adapted)
                all_rewards.extend(adapted)

            eligible = [
                episode
                for episode, _ in governed_episodes
                if _is_reinforce_eligible(
                    episode,
                    parent_snapshot,
                    self._provenance_key,
                )
            ]
            candidate_policy = copy.deepcopy(self.policy)
            result = self.learner.update(candidate_policy, eligible, all_rewards)
            candidate = candidate_policy.snapshot()
            candidate_evaluations = self._validate_candidate(candidate, run.id)
            candidate_violations = [
                evaluation.violation
                for evaluation in candidate_evaluations
                if evaluation.violation is not None
            ]
            if candidate_violations and self.fail_on_violation:
                denied = next(
                    evaluation
                    for evaluation in candidate_evaluations
                    if evaluation.violation is not None
                )
                raise GovernanceDeniedError(denied)

            candidate = self._attach_candidate_lineage(
                candidate,
                parent_snapshot=parent_snapshot,
                run_id=run.id,
                evaluations=candidate_evaluations,
                provenance_key=self._provenance_key,
            )

            telemetry = [
                GovernanceTelemetry.from_metadata(episode.metadata)
                for episode, _ in governed_episodes
            ]
            episode_violation_count = sum(len(item.violations) for item in telemetry)
            denied_episode_actions = sum(
                violation.blocked for item in telemetry for violation in item.violations
            )
            bayesian_episodes = sum(
                item.selection_basis == "bayesian_decision" for item in telemetry
            )
            report = LearningGovernanceReport(
                run_id=run.id,
                agent_id=agent_id,
                task_id=task_id,
                episodes_considered=len(episodes),
                reinforce_eligible_episodes=len(eligible),
                bayesian_episodes=bayesian_episodes,
                excluded_episodes=len(episodes) - len(eligible),
                shaped_rewards=shaped_rewards,
                episode_violations=episode_violation_count,
                denied_episode_actions=denied_episode_actions,
                candidate_policy_id=candidate.id,
                candidate_policy_version=candidate.version,
                candidate_policy_compliant=not candidate_violations,
                candidate_policy_violations=len(candidate_violations),
            )

            run.status = TrainingStatus.SUCCEEDED
            run.completed_at = _utcnow_iso()
            run.episode_ids = [episode.id for episode in episodes]
            run.metrics = _summarize_learner_result(result)
            run.metrics["governance"] = report.to_dict()
            run.metadata = _merge_namespace(
                run.metadata,
                {
                    "report": report.to_dict(),
                    "candidate_policy_id": candidate.id,
                    "candidate_policy_version": candidate.version,
                    "candidate_policy": candidate.to_dict(),
                    "promotion_status": "pending_validation",
                },
            )
            self.store.store_run(run)
            self._last_report = report
            self._last_candidate = copy.deepcopy(candidate)
            self._runs_completed += 1
            emit_audit_event(
                self.audit_sink,
                AuditEvent(
                    event_type=AuditEventType.LEARNING_RUN_COMPLETED,
                    agent_id=agent_id,
                    task_id=task_id,
                    artifact_type="training_run",
                    artifact_id=run.id,
                    outcome="succeeded",
                    policy_id=candidate.id,
                    policy_version=candidate.version,
                    details={
                        "episodes_considered": report.episodes_considered,
                        "reinforce_eligible_episodes": report.reinforce_eligible_episodes,
                        "bayesian_episodes": report.bayesian_episodes,
                        "candidate_policy_compliant": report.candidate_policy_compliant,
                    },
                ),
            )
            return run
        except Exception as exc:
            run.status = TrainingStatus.FAILED
            run.error_message = str(exc)
            run.completed_at = _utcnow_iso()
            self.store.store_run(run)
            self._runs_failed += 1
            emit_audit_event(
                self.audit_sink,
                AuditEvent(
                    event_type=AuditEventType.LEARNING_RUN_FAILED,
                    agent_id=agent_id,
                    task_id=task_id,
                    artifact_type="training_run",
                    artifact_id=run.id,
                    outcome="failed",
                    policy_id=parent_snapshot.id,
                    policy_version=parent_snapshot.version,
                    details={"error_type": type(exc).__name__},
                ),
            )
            raise

    def get_stats(self) -> dict[str, int]:
        return {
            "runs_completed": self._runs_completed,
            "runs_failed": self._runs_failed,
        }

    def _ensure_governance(self, episode: Any) -> tuple[Any, PolicyEvaluation | None]:
        telemetry = GovernanceTelemetry.from_metadata(episode.metadata)
        if not episode.action_id:
            return episode, None

        selection_basis = _selection_basis(episode.metadata)
        evaluation = self.policy_evaluator.evaluate(
            episode.action_id,
            context={
                "phase": "offline_learning",
                "agent_id": episode.agent_id,
                "task_id": episode.task_id,
                "policy_id": episode.policy_id,
                "policy_version": episode.policy_version,
            },
        )
        violations = telemetry.violations
        if evaluation.violation is not None:
            violations = (*violations, evaluation.violation)
        telemetry = replace(
            telemetry,
            decisions=(*telemetry.decisions, evaluation.decision),
            violations=violations,
            selection_basis=selection_basis,
            reinforce_eligible=(
                telemetry.reinforce_eligible
                if telemetry.reinforce_eligible is not None
                else _infer_reinforce_eligibility(
                    selection_basis,
                    episode.action_logprob,
                )
            ),
        )
        episode.metadata = telemetry.merge_metadata(episode.metadata)
        self.store.store_episode(episode)
        emit_audit_event(
            self.audit_sink,
            AuditEvent(
                event_type=AuditEventType.POLICY_EVALUATED,
                agent_id=episode.agent_id,
                task_id=episode.task_id,
                artifact_type="episode",
                artifact_id=episode.id,
                outcome=evaluation.decision.outcome.value,
                policy_id=episode.policy_id,
                policy_version=episode.policy_version,
                action_id=episode.action_id,
                details={
                    "policy_name": evaluation.decision.policy_name,
                    "risk_level": evaluation.decision.risk_level.value,
                },
            ),
        )
        return episode, evaluation

    def _has_usable_reward(self, episode: Any) -> bool:
        checker = getattr(self.learning_runner, "has_usable_reward", None)
        if callable(checker):
            return bool(checker(episode))
        return any(
            _is_aggregate(reward)
            for reward in self.store.get_rewards_for_episode(
                episode.id,
                episode.agent_id,
            )
        )

    def _validate_candidate(self, candidate: Any, run_id: str) -> list[PolicyEvaluation]:
        return [
            self.policy_evaluator.evaluate(
                action.id,
                context={
                    "phase": "candidate_policy_validation",
                    "agent_id": candidate.agent_id,
                    "task_id": candidate.task_id,
                    "policy_id": candidate.id,
                    "policy_version": candidate.version,
                    "training_run_id": run_id,
                    "action_parameters": dict(action.parameters),
                },
            )
            for action in candidate.actions
        ]

    @staticmethod
    def _attach_candidate_lineage(
        candidate: Any,
        *,
        parent_snapshot: Any,
        run_id: str,
        evaluations: Iterable[PolicyEvaluation],
        provenance_key: bytes,
    ) -> Any:
        evaluations = list(evaluations)
        telemetry = GovernanceTelemetry(
            decisions=tuple(evaluation.decision for evaluation in evaluations),
            violations=tuple(
                evaluation.violation
                for evaluation in evaluations
                if evaluation.violation is not None
            ),
        )
        candidate.metadata = telemetry.merge_metadata(candidate.metadata)
        candidate.metadata = _merge_namespace(
            candidate.metadata,
            {
                "lineage": {
                    "training_run_id": run_id,
                    "parent_policy_id": parent_snapshot.id,
                    "parent_policy_version": parent_snapshot.version,
                },
                "promotion_status": "pending_validation",
            },
        )
        candidate.metadata = _merge_namespace(
            candidate.metadata,
            {"candidate_provenance": candidate_provenance(candidate, provenance_key)},
        )
        return candidate


def _resolve_component(explicit: Any, owner: Any, attribute: str, label: str) -> Any:
    value = explicit if explicit is not None else getattr(owner, attribute, None)
    if value is None:
        raise ValueError(
            f"GovernedLearningRunner requires {label}; pass it explicitly for "
            "custom Agent Learning runners"
        )
    return value


def _selection_basis(metadata: Mapping[str, Any]) -> str | None:
    telemetry = GovernanceTelemetry.from_metadata(metadata)
    if telemetry.selection_basis:
        return telemetry.selection_basis
    direct = metadata.get("selection_basis")
    if isinstance(direct, str):
        return direct
    decision = metadata.get("decision_result", {})
    if isinstance(decision, Mapping) and isinstance(decision.get("selection_basis"), str):
        return decision["selection_basis"]
    return None


def _infer_reinforce_eligibility(
    selection_basis: str | None,
    action_logprob: float | None,
) -> bool | None:
    del action_logprob
    if selection_basis == "bayesian_decision":
        return False
    return None


def _is_reinforce_eligible(
    episode: Any,
    parent_snapshot: Any,
    provenance_key: bytes,
) -> bool:
    telemetry = GovernanceTelemetry.from_metadata(episode.metadata)
    if _has_blocking_violation(episode):
        return False
    if telemetry.selection_basis != "learned_policy":
        return False
    if telemetry.reinforce_eligible != True:
        return False
    if (
        episode.agent_id != parent_snapshot.agent_id
        or episode.task_id != parent_snapshot.task_id
        or episode.policy_id != parent_snapshot.id
        or episode.policy_version != parent_snapshot.version
    ):
        return False
    known_action_ids = {action.id for action in parent_snapshot.actions}
    if episode.action_id not in known_action_ids:
        return False
    expected_probabilities = _softmax_probabilities(parent_snapshot)
    if expected_probabilities is None:
        return False
    action_logprob = episode.action_logprob
    if (
        isinstance(action_logprob, bool)
        or not isinstance(action_logprob, (int, float))
        or not math.isfinite(action_logprob)
        or action_logprob > 0
        or not math.isclose(
            action_logprob,
            math.log(max(expected_probabilities[episode.action_id], 1e-12)),
            rel_tol=1e-9,
            abs_tol=1e-12,
        )
    ):
        return False
    certificate = telemetry.metadata.get("decision_certificate")
    if not isinstance(certificate, Mapping):
        return False
    if not verify_decision_certificate(certificate, provenance_key):
        return False
    expected_fields = {
        "episode_id": episode.id,
        "agent_id": episode.agent_id,
        "task_id": episode.task_id,
        "policy_id": episode.policy_id,
        "policy_version": episode.policy_version,
        "status": "resolved",
        "selection_basis": "learned_policy",
        "selected_action_id": episode.action_id,
    }
    if any(certificate.get(key) != value for key, value in expected_fields.items()):
        return False
    certificate_logprob = certificate.get("action_logprob")
    if (
        isinstance(certificate_logprob, bool)
        or not isinstance(certificate_logprob, (int, float))
        or not math.isclose(certificate_logprob, action_logprob, rel_tol=1e-12, abs_tol=1e-12)
    ):
        return False
    probabilities = certificate.get("action_probabilities")
    if not isinstance(probabilities, Mapping) or set(probabilities) != known_action_ids:
        return False
    return all(
        not isinstance(probabilities[action_id], bool)
        and isinstance(probabilities[action_id], (int, float))
        and math.isfinite(probabilities[action_id])
        and math.isclose(
            probabilities[action_id],
            expected_probability,
            rel_tol=1e-9,
            abs_tol=1e-12,
        )
        for action_id, expected_probability in expected_probabilities.items()
    )


def _softmax_probabilities(parent_snapshot: Any) -> dict[str, float] | None:
    try:
        logits = [float(parent_snapshot.logits[action.id]) for action in parent_snapshot.actions]
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    if not logits or any(not math.isfinite(logit) for logit in logits):
        return None
    maximum = max(logits)
    exponentials = [math.exp(logit - maximum) for logit in logits]
    denominator = sum(exponentials)
    if denominator <= 0 or not math.isfinite(denominator):
        return None
    return {
        action.id: exponential / denominator
        for action, exponential in zip(parent_snapshot.actions, exponentials, strict=True)
    }


def _has_blocking_violation(episode: Any) -> bool:
    telemetry = GovernanceTelemetry.from_metadata(episode.metadata)
    return any(violation.blocked for violation in telemetry.violations)


def _is_aggregate(reward: Any) -> bool:
    source = getattr(reward, "source", None)
    return getattr(source, "value", source) == "aggregate"


def _summarize_learner_result(result: Any) -> dict[str, Any]:
    return {
        "episodes_used": int(getattr(result, "episodes_used", 0)),
        "mean_reward": float(getattr(result, "mean_reward", 0.0)),
        "baseline_before": float(getattr(result, "baseline_before", 0.0)),
        "baseline_after": float(getattr(result, "baseline_after", 0.0)),
        "logit_deltas": dict(getattr(result, "logit_deltas", {})),
        "extra": dict(getattr(result, "extra", {})),
    }


def _merge_namespace(
    metadata: Mapping[str, Any] | None,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(metadata or {})
    existing = merged.get(GOVERNANCE_METADATA_KEY, {})
    namespace = dict(existing) if isinstance(existing, Mapping) else {}
    namespace.update(values)
    merged[GOVERNANCE_METADATA_KEY] = namespace
    return merged


__all__ = ["GovernedLearningRunner", "LearningGovernanceReport"]
