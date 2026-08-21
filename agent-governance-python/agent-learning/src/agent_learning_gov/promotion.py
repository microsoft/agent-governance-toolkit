# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governance gates for Agent Learning policy promotion and rollout."""

from __future__ import annotations

import copy
import inspect
import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from .audit import AuditEvent, AuditEventType, AuditSink, emit_audit_event
from .evaluation import GovernanceEvaluationPack, GovernanceEvaluationReport
from .models import GOVERNANCE_METADATA_KEY, GovernanceTelemetry
from .policy import PolicyEvaluation, PolicyEvaluatorAdapter
from .provenance import (
    resolve_provenance_key,
    sign_promotion_receipt,
    verify_candidate,
    verify_promotion_receipt,
)

logger = logging.getLogger(__name__)


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


class PromotionStage(str, Enum):
    """Supported rollout stages for an approved policy."""

    SHADOW = "shadow"
    CANARY = "canary"
    PRODUCTION = "production"


class PromotionStatus(str, Enum):
    """Outcome of a policy promotion attempt."""

    APPROVED = "approved"
    BLOCKED = "blocked"
    DEPLOYED = "deployed"
    FAILED = "failed"


@dataclass(frozen=True)
class PromotionValidation:
    """Policy authorization and evaluation certificate."""

    policy_id: str
    policy_version: int
    passed: bool
    policy_evaluations: tuple[PolicyEvaluation, ...]
    evaluation_report: GovernanceEvaluationReport
    validated_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "passed": self.passed,
            "policy_evaluations": [
                {
                    "decision": evaluation.decision.to_dict(),
                    "violation": (
                        evaluation.violation.to_dict() if evaluation.violation is not None else None
                    ),
                }
                for evaluation in self.policy_evaluations
            ],
            "evaluation_report": self.evaluation_report.to_dict(),
            "validated_at": self.validated_at,
        }


@dataclass(frozen=True)
class PromotionResult:
    """Persisted outcome of one staged promotion attempt."""

    policy_id: str
    policy_version: int
    stage: PromotionStage
    status: PromotionStatus
    validation: PromotionValidation
    reason: str = ""
    deployment_result: Any = None
    timestamp: str = field(default_factory=_utcnow_iso)

    @property
    def promoted(self) -> bool:
        return self.status in {PromotionStatus.APPROVED, PromotionStatus.DEPLOYED}

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "stage": self.stage.value,
            "status": self.status.value,
            "reason": self.reason,
            "validation": self.validation.to_dict(),
            "deployment_result": _json_safe_result(self.deployment_result),
            "timestamp": self.timestamp,
        }


class GovernedPolicyPromotion:
    """Validate and promote policy snapshots through governance gates."""

    def __init__(
        self,
        kernel: Any,
        *,
        store: Any,
        evaluation_pack: GovernanceEvaluationPack | None = None,
        audit_sink: AuditSink | None = None,
        deploy_callback: Callable[[Any, PromotionStage, Mapping[str, Any]], Any] | None = None,
        fail_closed: bool = True,
        enforce_stages: bool = True,
        policy_name: str | None = None,
        provenance_key: bytes | str | None = None,
    ) -> None:
        self.store = store
        self.policy_evaluator = PolicyEvaluatorAdapter(
            kernel,
            fail_closed=fail_closed,
            policy_name=policy_name,
        )
        self.evaluation_pack = evaluation_pack or GovernanceEvaluationPack()
        self.audit_sink = audit_sink
        self.deploy_callback = deploy_callback
        self.enforce_stages = enforce_stages
        self._provenance_key = resolve_provenance_key(provenance_key)
        self._candidates: dict[tuple[str, str], Any] = {}
        self._last_policy: Any | None = None
        self._last_audit_error: str | None = None

    @property
    def last_policy(self) -> Any | None:
        """Return an isolated copy of the last validated promotion candidate."""
        return copy.deepcopy(self._last_policy)

    @property
    def last_audit_error(self) -> str | None:
        """Return the most recent best-effort audit error type, if any."""
        return self._last_audit_error

    def validate(
        self,
        policy_version: Any,
        *,
        agent_id: str | None = None,
        task_id: str = "default",
        episodes: Iterable[Any] | None = None,
        baseline: Mapping[str, Any] | None = None,
    ) -> PromotionValidation:
        """Authorize every action and run the governance evaluation suite."""
        policy = self._resolve_policy(policy_version, agent_id=agent_id, task_id=task_id)
        if not verify_candidate(policy, self._provenance_key):
            raise ValueError("Policy candidate provenance is missing or invalid")
        evaluated_policy = copy.deepcopy(policy)
        policy_evaluations = tuple(
            self.policy_evaluator.evaluate(
                action.id,
                context={
                    "phase": "policy_promotion",
                    "agent_id": policy.agent_id,
                    "task_id": policy.task_id,
                    "policy_id": policy.id,
                    "policy_version": policy.version,
                    "action_parameters": dict(action.parameters),
                },
            )
            for action in policy.actions
        )
        telemetry = GovernanceTelemetry(
            decisions=tuple(evaluation.decision for evaluation in policy_evaluations),
            violations=tuple(
                evaluation.violation
                for evaluation in policy_evaluations
                if evaluation.violation is not None
            ),
        )
        evaluated_policy.metadata = telemetry.merge_metadata(evaluated_policy.metadata)
        episode_list = list(episodes if episodes is not None else self._candidate_episodes(policy))
        report = self.evaluation_pack.evaluate(
            evaluated_policy,
            episodes=episode_list,
            baseline=baseline,
        )
        passed = all(evaluation.allowed for evaluation in policy_evaluations) and report.passed
        validation = PromotionValidation(
            policy_id=policy.id,
            policy_version=policy.version,
            passed=passed,
            policy_evaluations=policy_evaluations,
            evaluation_report=report,
        )
        evaluated_policy.metadata = _merge_promotion_metadata(
            evaluated_policy.metadata,
            {
                "status": "validated" if passed else "blocked",
                "validation": validation.to_dict(),
            },
        )
        self._persist_candidate(evaluated_policy)
        emit_audit_event(
            self.audit_sink,
            AuditEvent(
                event_type=AuditEventType.POLICY_VALIDATED,
                agent_id=policy.agent_id,
                task_id=policy.task_id,
                artifact_type="policy",
                artifact_id=policy.id,
                outcome="passed" if passed else "failed",
                policy_id=policy.id,
                policy_version=policy.version,
                details={
                    "action_checks": len(policy_evaluations),
                    "finding_count": len(report.findings),
                },
            ),
        )
        return validation

    def promote_if_compliant(
        self,
        policy_version: Any,
        *,
        agent_id: str | None = None,
        task_id: str = "default",
        stage: PromotionStage | str = PromotionStage.CANARY,
        episodes: Iterable[Any] | None = None,
        baseline: Mapping[str, Any] | None = None,
        deployment_context: Mapping[str, Any] | None = None,
    ) -> PromotionResult:
        """Promote only when policy checks and evaluations pass."""
        resolved_stage = PromotionStage(stage)
        policy = self._resolve_policy(policy_version, agent_id=agent_id, task_id=task_id)
        validation = self.validate(
            policy,
            episodes=episodes,
            baseline=baseline,
        )
        policy = copy.deepcopy(self._candidates[(policy.agent_id, policy.id)])

        if not validation.passed:
            result = PromotionResult(
                policy_id=policy.id,
                policy_version=policy.version,
                stage=resolved_stage,
                status=PromotionStatus.BLOCKED,
                validation=validation,
                reason="Governance validation failed",
            )
            return self._record_result(policy, result)

        if self.enforce_stages and resolved_stage is PromotionStage.PRODUCTION:
            history = _promotion_history(policy.metadata)
            canary_complete = any(
                item.get("stage") == PromotionStage.CANARY.value
                and item.get("status") == PromotionStatus.DEPLOYED.value
                and verify_promotion_receipt(policy, item, self._provenance_key)
                for item in history
            )
            if not canary_complete:
                result = PromotionResult(
                    policy_id=policy.id,
                    policy_version=policy.version,
                    stage=resolved_stage,
                    status=PromotionStatus.BLOCKED,
                    validation=validation,
                    reason="Production promotion requires a completed canary stage",
                )
                return self._record_result(policy, result)

        if self.deploy_callback is None:
            result = PromotionResult(
                policy_id=policy.id,
                policy_version=policy.version,
                stage=resolved_stage,
                status=PromotionStatus.APPROVED,
                validation=validation,
                reason="Governance approved; no deployment callback was configured",
            )
            return self._record_result(policy, result)

        if inspect.iscoroutinefunction(self.deploy_callback):
            result = PromotionResult(
                policy_id=policy.id,
                policy_version=policy.version,
                stage=resolved_stage,
                status=PromotionStatus.FAILED,
                validation=validation,
                reason="Deployment failed (TypeError)",
            )
            return self._record_result(policy, result)

        if resolved_stage is PromotionStage.PRODUCTION:
            return self._deploy_production(
                policy,
                validation,
                dict(deployment_context or {}),
            )

        try:
            deployment_result = self.deploy_callback(
                policy,
                resolved_stage,
                dict(deployment_context or {}),
            )
            if inspect.isawaitable(deployment_result):
                close = getattr(deployment_result, "close", None)
                if callable(close):
                    close()
                raise TypeError(
                    "GovernedPolicyPromotion is synchronous; provide a synchronous "
                    "deployment callback"
                )
            deployed = deployment_result is not False
            result = PromotionResult(
                policy_id=policy.id,
                policy_version=policy.version,
                stage=resolved_stage,
                status=(PromotionStatus.DEPLOYED if deployed else PromotionStatus.FAILED),
                validation=validation,
                reason=(
                    "Policy deployed" if deployed else "Deployment callback rejected the policy"
                ),
                deployment_result=deployment_result,
            )
        except Exception as exc:  # noqa: BLE001
            result = PromotionResult(
                policy_id=policy.id,
                policy_version=policy.version,
                stage=resolved_stage,
                status=PromotionStatus.FAILED,
                validation=validation,
                reason=f"Deployment failed ({type(exc).__name__})",
            )
        return self._record_result(policy, result)

    def _record_result(self, policy: Any, result: PromotionResult) -> PromotionResult:
        policy = copy.deepcopy(policy)
        policy = _policy_with_promotion_result(
            policy,
            result,
            self._provenance_key,
        )
        self._persist_candidate(policy)
        self._emit_promotion_result(policy, result)
        if result.status is PromotionStatus.DEPLOYED:
            self._emit_policy_deployed(policy, result)
        return result

    def _deploy_production(
        self,
        policy: Any,
        validation: PromotionValidation,
        deployment_context: Mapping[str, Any],
    ) -> PromotionResult:
        result = PromotionResult(
            policy_id=policy.id,
            policy_version=policy.version,
            stage=PromotionStage.PRODUCTION,
            status=PromotionStatus.DEPLOYED,
            validation=validation,
            reason="Policy deployed",
        )
        prepared_policy = _policy_with_promotion_result(
            policy,
            result,
            self._provenance_key,
        )
        try:
            self._require_production_infrastructure(policy)
            get_active_policy = getattr(self.store, "get_active_policy", None)
            if not callable(get_active_policy):
                raise TypeError("Production activation requires get_active_policy support")
            previous_policy = get_active_policy(policy.agent_id, policy.task_id)
            if previous_policy is None:
                raise LookupError("Production activation requires an active rollback policy")
            self._persist_candidate(prepared_policy, require_durable=True)
            self._emit_promotion_result(prepared_policy, result)
            self.store.store_policy(prepared_policy)
        except Exception as exc:  # noqa: BLE001
            return self._record_activation_failure(policy, result, exc)

        try:
            deployment_result = self.deploy_callback(
                prepared_policy,
                PromotionStage.PRODUCTION,
                deployment_context,
            )
            if inspect.isawaitable(deployment_result):
                close = getattr(deployment_result, "close", None)
                if callable(close):
                    close()
                raise TypeError(
                    "GovernedPolicyPromotion is synchronous; provide a synchronous "
                    "deployment callback"
                )
            if deployment_result == False:
                raise RuntimeError("Deployment callback rejected the policy")
        except Exception as exc:  # noqa: BLE001
            try:
                self.store.store_policy(previous_policy)
            except Exception as rollback_exc:
                logger.exception("Production policy rollback failed")
                exc = RuntimeError(
                    f"{type(exc).__name__}; rollback failed ({type(rollback_exc).__name__})"
                )
            return self._record_activation_failure(policy, result, exc)

        result = replace(result, deployment_result=deployment_result)
        try:
            self._emit_policy_deployed(prepared_policy, result)
        except Exception as exc:
            self._last_audit_error = type(exc).__name__
            logger.exception("Policy deployed, but deployment audit emission failed")
        return result

    def _record_activation_failure(
        self,
        policy: Any,
        result: PromotionResult,
        error: Exception,
    ) -> PromotionResult:
        failed = replace(
            result,
            status=PromotionStatus.FAILED,
            reason=f"Policy activation failed ({type(error).__name__})",
        )
        failed_policy = _policy_with_promotion_result(
            policy,
            failed,
            self._provenance_key,
        )
        try:
            self._persist_candidate(failed_policy)
        except Exception:  # noqa: BLE001
            candidate = copy.deepcopy(failed_policy)
            self._candidates[(candidate.agent_id, candidate.id)] = candidate
            self._last_policy = candidate
        try:
            self._emit_promotion_result(failed_policy, failed)
        except Exception as exc:
            self._last_audit_error = type(exc).__name__
            logger.exception("Promotion failure audit emission failed")
        return failed

    def _emit_promotion_result(self, policy: Any, result: PromotionResult) -> None:
        event_types = {
            PromotionStatus.BLOCKED: AuditEventType.PROMOTION_BLOCKED,
            PromotionStatus.FAILED: AuditEventType.PROMOTION_FAILED,
        }
        event_type = event_types.get(result.status, AuditEventType.PROMOTION_APPROVED)
        emit_audit_event(
            self.audit_sink,
            AuditEvent(
                event_type=event_type,
                agent_id=policy.agent_id,
                task_id=policy.task_id,
                artifact_type="policy",
                artifact_id=policy.id,
                outcome=result.status.value,
                policy_id=policy.id,
                policy_version=policy.version,
                details={"stage": result.stage.value, "reason": result.reason},
            ),
        )

    def _emit_policy_deployed(self, policy: Any, result: PromotionResult) -> None:
        emit_audit_event(
            self.audit_sink,
            AuditEvent(
                event_type=AuditEventType.POLICY_DEPLOYED,
                agent_id=policy.agent_id,
                task_id=policy.task_id,
                artifact_type="policy",
                artifact_id=policy.id,
                outcome="deployed",
                policy_id=policy.id,
                policy_version=policy.version,
                details={"stage": result.stage.value},
            ),
        )

    def _require_production_infrastructure(self, policy: Any) -> None:
        if self.audit_sink is None or not callable(getattr(self.audit_sink, "emit", None)):
            raise RuntimeError("Production promotion requires a durable audit sink")
        run_id = _candidate_run_id(policy.metadata)
        get_run = getattr(self.store, "get_run", None)
        store_run = getattr(self.store, "store_run", None)
        if run_id is None or not callable(get_run) or not callable(store_run):
            raise RuntimeError("Production promotion requires run-backed candidate storage")
        if get_run(run_id, policy.agent_id) is None:
            raise LookupError("Production promotion candidate training run was not found")

    def _persist_candidate(self, policy: Any, *, require_durable: bool = False) -> None:
        """Persist candidate state without changing Agent Learning's active pointer."""
        candidate = copy.deepcopy(policy)
        self._candidates[(candidate.agent_id, candidate.id)] = candidate
        self._last_policy = candidate

        run_id = _candidate_run_id(candidate.metadata)
        get_run = getattr(self.store, "get_run", None)
        store_run = getattr(self.store, "store_run", None)
        if run_id is None or not callable(get_run) or not callable(store_run):
            if require_durable:
                raise RuntimeError("Candidate cannot be persisted to its training run")
            return
        run = get_run(run_id, candidate.agent_id)
        if run is None:
            if require_durable:
                raise LookupError("Candidate training run was not found")
            return
        run.metadata = _merge_candidate_metadata(run.metadata, candidate)
        store_run(run)

    def _resolve_policy(
        self,
        policy_version: Any,
        *,
        agent_id: str | None,
        task_id: str,
    ) -> Any:
        if hasattr(policy_version, "actions") and hasattr(policy_version, "id"):
            return copy.deepcopy(policy_version)
        if agent_id is None:
            raise ValueError("agent_id is required when resolving a policy id or version")
        if isinstance(policy_version, str):
            policy = self._candidates.get((agent_id, policy_version))
            if policy is None:
                policy = self._candidate_from_runs(
                    agent_id,
                    task_id,
                    policy_id=policy_version,
                )
            if policy is None:
                policy = self.store.get_policy(policy_version, agent_id)
        elif isinstance(policy_version, int):
            policy = next(
                (
                    candidate
                    for (candidate_agent, _), candidate in self._candidates.items()
                    if candidate_agent == agent_id
                    and candidate.task_id == task_id
                    and candidate.version == policy_version
                ),
                None,
            )
            if policy is None:
                policy = self._candidate_from_runs(
                    agent_id,
                    task_id,
                    version=policy_version,
                )
            if policy is None:
                policy = next(
                    (
                        candidate
                        for candidate in self.store.list_policies(
                            agent_id,
                            task_id,
                            limit=1000,
                        )
                        if candidate.version == policy_version
                    ),
                    None,
                )
        else:
            raise TypeError("policy_version must be a policy snapshot, id, or version")
        if policy is None:
            raise LookupError("Policy snapshot was not found")
        return copy.deepcopy(policy)

    def _candidate_from_runs(
        self,
        agent_id: str,
        task_id: str,
        *,
        policy_id: str | None = None,
        version: int | None = None,
    ) -> Any | None:
        list_runs = getattr(self.store, "list_training_runs", None)
        if not callable(list_runs):
            return None
        try:
            from agent_learning import PolicySnapshot
        except ImportError:
            return None
        for run in list_runs(agent_id, limit=1000):
            if run.task_id != task_id:
                continue
            candidate_data = _candidate_data(run.metadata)
            if candidate_data is None:
                continue
            candidate = PolicySnapshot.from_dict(candidate_data)
            if policy_id is not None and candidate.id == policy_id:
                return candidate
            if version is not None and candidate.version == version:
                return candidate
        return None

    def _candidate_episodes(self, policy: Any) -> list[Any]:
        run_id = _candidate_run_id(policy.metadata)
        get_run = getattr(self.store, "get_run", None)
        get_episode = getattr(self.store, "get_episode", None)
        if run_id and callable(get_run) and callable(get_episode):
            run = get_run(run_id, policy.agent_id)
            if run is not None:
                return [
                    episode
                    for episode_id in run.episode_ids
                    if (episode := get_episode(episode_id, policy.agent_id)) is not None
                ]
        parent_id = _candidate_parent_id(policy.metadata)
        return list(
            self.store.query_episodes(
                policy.agent_id,
                task_id=policy.task_id,
                policy_id=parent_id or policy.id,
                full_only=True,
                limit=1000,
            )
        )


def _policy_with_promotion_result(
    policy: Any,
    result: PromotionResult,
    provenance_key: bytes,
) -> Any:
    policy = copy.deepcopy(policy)
    history = _promotion_history(policy.metadata)
    entry = {
        "stage": result.stage.value,
        "status": result.status.value,
        "reason": result.reason,
        "timestamp": result.timestamp,
        "validation_passed": result.validation.passed,
    }
    entry["receipt"] = sign_promotion_receipt(policy, entry, provenance_key)
    history.append(entry)
    policy.metadata = _merge_promotion_metadata(
        policy.metadata,
        {
            "status": result.status.value,
            "stage": result.stage.value,
            "last_result": result.to_dict(),
            "history": history,
        },
    )
    return policy


def _merge_promotion_metadata(
    metadata: Mapping[str, Any] | None,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(metadata or {})
    existing = merged.get(GOVERNANCE_METADATA_KEY, {})
    namespace = dict(existing) if isinstance(existing, Mapping) else {}
    promotion = namespace.get("promotion", {})
    promotion_values = dict(promotion) if isinstance(promotion, Mapping) else {}
    promotion_values.update(values)
    namespace["promotion"] = promotion_values
    merged[GOVERNANCE_METADATA_KEY] = namespace
    return merged


def _promotion_history(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    namespace = metadata.get(GOVERNANCE_METADATA_KEY, {})
    promotion = namespace.get("promotion", {}) if isinstance(namespace, Mapping) else {}
    history = promotion.get("history", []) if isinstance(promotion, Mapping) else []
    return [dict(item) for item in history if isinstance(item, Mapping)]


def _candidate_run_id(metadata: Mapping[str, Any]) -> str | None:
    namespace = metadata.get(GOVERNANCE_METADATA_KEY, {})
    lineage = namespace.get("lineage", {}) if isinstance(namespace, Mapping) else {}
    run_id = lineage.get("training_run_id") if isinstance(lineage, Mapping) else None
    return str(run_id) if run_id else None


def _candidate_parent_id(metadata: Mapping[str, Any]) -> str | None:
    namespace = metadata.get(GOVERNANCE_METADATA_KEY, {})
    lineage = namespace.get("lineage", {}) if isinstance(namespace, Mapping) else {}
    policy_id = lineage.get("parent_policy_id") if isinstance(lineage, Mapping) else None
    return str(policy_id) if policy_id else None


def _candidate_data(metadata: Mapping[str, Any]) -> Mapping[str, Any] | None:
    namespace = metadata.get(GOVERNANCE_METADATA_KEY, {})
    candidate = namespace.get("candidate_policy") if isinstance(namespace, Mapping) else None
    return candidate if isinstance(candidate, Mapping) else None


def _merge_candidate_metadata(metadata: Mapping[str, Any], policy: Any) -> dict[str, Any]:
    merged = dict(metadata)
    namespace = merged.get(GOVERNANCE_METADATA_KEY, {})
    governance = dict(namespace) if isinstance(namespace, Mapping) else {}
    governance.update(
        {
            "candidate_policy_id": policy.id,
            "candidate_policy_version": policy.version,
            "candidate_policy": policy.to_dict(),
            "promotion_status": _promotion_status(policy.metadata),
        }
    )
    merged[GOVERNANCE_METADATA_KEY] = governance
    return merged


def _promotion_status(metadata: Mapping[str, Any]) -> str:
    namespace = metadata.get(GOVERNANCE_METADATA_KEY, {})
    promotion = namespace.get("promotion", {}) if isinstance(namespace, Mapping) else {}
    if isinstance(promotion, Mapping) and promotion.get("status"):
        return str(promotion["status"])
    return "pending_validation"


def _json_safe_result(value: Any) -> Any:
    if value is None or isinstance(value, (bool, float, int, str, list, dict)):
        return value
    return {"type": type(value).__name__}


__all__ = [
    "GovernedPolicyPromotion",
    "PromotionResult",
    "PromotionStage",
    "PromotionStatus",
    "PromotionValidation",
]
