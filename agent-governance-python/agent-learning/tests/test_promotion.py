# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for governance-gated policy promotion."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import pytest

from agent_learning_gov import (
    AuditEventType,
    GovernedPolicyPromotion,
    InMemoryAuditSink,
    PromotionStage,
    PromotionStatus,
)
from agent_learning_gov.provenance import candidate_provenance

PROVENANCE_KEY = b"agent-learning-governance-test-key"


class _Store:
    def __init__(self, policy: Any) -> None:
        self.policy = copy.deepcopy(policy)
        self.store_policy_calls = 0
        self.run = SimpleNamespace(metadata={})
        self.store_run_calls = 0

    def store_policy(self, policy: Any) -> str:
        self.store_policy_calls += 1
        self.policy = copy.deepcopy(policy)
        return policy.id

    def get_policy(self, policy_id: str, agent_id: str) -> Any:
        if self.policy.id == policy_id and self.policy.agent_id == agent_id:
            return copy.deepcopy(self.policy)
        return None

    def get_active_policy(self, agent_id: str, task_id: str) -> Any:
        if self.policy.agent_id == agent_id and self.policy.task_id == task_id:
            return copy.deepcopy(self.policy)
        return None

    def list_policies(self, agent_id: str, task_id: str, *, limit: int = 100):
        del limit
        if self.policy.agent_id == agent_id and self.policy.task_id == task_id:
            return [copy.deepcopy(self.policy)]
        return []

    def query_episodes(self, agent_id: str, **kwargs: Any) -> list[Any]:
        del agent_id, kwargs
        return []

    def get_run(self, run_id: str, agent_id: str) -> Any:
        del run_id, agent_id
        return self.run

    def store_run(self, run: Any) -> str:
        self.store_run_calls += 1
        self.run = run
        return "run-1"


class _PolicyEvaluator:
    name = "promotion-policy"

    def __init__(self, denied: set[str] | None = None) -> None:
        self.denied = denied or set()

    def evaluate(self, action: str, context: dict[str, Any]) -> Any:
        del context
        return SimpleNamespace(
            allowed=action not in self.denied,
            reason="restricted" if action in self.denied else "allowed",
        )


def _policy(*action_ids: str) -> Any:
    policy = SimpleNamespace(
        id="policy-2",
        agent_id="agent-1",
        task_id="task-1",
        version=2,
        actions=[SimpleNamespace(id=action_id, parameters={}) for action_id in action_ids],
        metadata={
            "agent_governance": {
                "lineage": {
                    "training_run_id": "run-1",
                    "parent_policy_id": "policy-1",
                    "parent_policy_version": 1,
                }
            }
        },
    )
    policy.metadata["agent_governance"]["candidate_provenance"] = candidate_provenance(
        policy,
        PROVENANCE_KEY,
    )
    policy.to_dict = lambda: {
        "id": policy.id,
        "agent_id": policy.agent_id,
        "task_id": policy.task_id,
        "version": policy.version,
    }
    return policy


def test_unsafe_policy_is_blocked_and_not_deployed() -> None:
    store = _Store(_policy("search", "delete"))
    deployed = []
    audit = InMemoryAuditSink()
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator({"delete"}),
        store=store,
        provenance_key=PROVENANCE_KEY,
        audit_sink=audit,
        deploy_callback=lambda policy, stage, context: deployed.append(policy.id),
    )

    result = promoter.promote_if_compliant(
        "policy-2",
        agent_id="agent-1",
        task_id="task-1",
    )

    assert result.status is PromotionStatus.BLOCKED
    assert result.validation.passed == False
    assert deployed == []
    assert promoter.last_policy.metadata["agent_governance"]["promotion"]["status"] == "blocked"
    assert store.store_policy_calls == 0
    assert len(audit.query(agent_id="agent-1")) == 2


def test_canary_deployment_records_promotion_history() -> None:
    store = _Store(_policy("search", "summarize"))
    calls = []
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        deploy_callback=lambda policy, stage, context: calls.append((policy.id, stage, context)),
    )

    result = promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
        deployment_context={"traffic_percent": 5},
    )

    assert result.status is PromotionStatus.DEPLOYED
    assert calls == [("policy-2", PromotionStage.CANARY, {"traffic_percent": 5})]
    history = promoter.last_policy.metadata["agent_governance"]["promotion"]["history"]
    assert history[-1]["stage"] == "canary"
    assert history[-1]["status"] == "deployed"
    assert store.store_policy_calls == 0


def test_production_requires_completed_canary() -> None:
    store = _Store(_policy("search", "summarize"))
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        deploy_callback=lambda policy, stage, context: True,
    )

    result = promoter.promote_if_compliant(
        2,
        agent_id="agent-1",
        task_id="task-1",
        stage="production",
        baseline={"violation_rate": 0.0},
    )

    assert result.status is PromotionStatus.BLOCKED
    assert "canary" in result.reason
    assert store.store_policy_calls == 0


def test_forged_canary_history_does_not_unlock_production() -> None:
    policy = _policy("search", "summarize")
    policy.metadata["agent_governance"]["promotion"] = {
        "history": [
            {
                "stage": "canary",
                "status": "deployed",
                "reason": "forged",
                "timestamp": "2026-08-10T00:00:00+00:00",
                "validation_passed": True,
            }
        ]
    }
    store = _Store(policy)
    deployed = []
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        deploy_callback=lambda policy, stage, context: deployed.append(stage),
    )

    result = promoter.promote_if_compliant(
        policy,
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )

    assert result.status is PromotionStatus.BLOCKED
    assert "canary" in result.reason
    assert deployed == []
    assert store.store_policy_calls == 0


def test_candidate_mutation_invalidates_promotion_provenance() -> None:
    policy = _policy("search", "summarize")
    policy.actions.append(SimpleNamespace(id="forged", parameters={}))
    store = _Store(policy)
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
    )

    with pytest.raises(ValueError, match="provenance"):
        promoter.promote_if_compliant(
            policy,
            stage=PromotionStage.CANARY,
            baseline={"violation_rate": 0.0},
        )

    assert store.store_policy_calls == 0


def test_behavior_metadata_mutation_invalidates_promotion_provenance() -> None:
    policy = _policy("search", "summarize")
    policy.metadata["decision_authority"] = "full"
    store = _Store(policy)
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
    )

    with pytest.raises(ValueError, match="provenance"):
        promoter.promote_if_compliant(
            policy,
            stage=PromotionStage.CANARY,
            baseline={"violation_rate": 0.0},
        )

    assert store.store_policy_calls == 0


def test_successful_production_deployment_activates_after_canary() -> None:
    store = _Store(_policy("search", "summarize"))
    callback_active_ids = []

    def deploy(policy: Any, stage: PromotionStage, context: Mapping[str, Any]) -> bool:
        del context
        if stage is PromotionStage.PRODUCTION:
            active = store.get_active_policy(policy.agent_id, policy.task_id)
            callback_active_ids.append(
                (
                    active.id,
                    active.metadata["agent_governance"]["promotion"]["stage"],
                )
            )
        return True

    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        audit_sink=InMemoryAuditSink(),
        deploy_callback=deploy,
    )
    promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
    )
    callback_active_ids.clear()

    result = promoter.promote_if_compliant(
        "policy-2",
        agent_id="agent-1",
        task_id="task-1",
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )

    assert result.status is PromotionStatus.DEPLOYED
    assert store.store_policy_calls == 1
    assert callback_active_ids == [("policy-2", "production")]
    history = store.policy.metadata["agent_governance"]["promotion"]["history"]
    assert [item["stage"] for item in history] == ["canary", "production"]


def test_approved_canary_without_deployment_does_not_unlock_production() -> None:
    store = _Store(_policy("search", "summarize"))
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
    )
    canary = promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
    )
    promoter.deploy_callback = lambda policy, stage, context: True

    production = promoter.promote_if_compliant(
        "policy-2",
        agent_id="agent-1",
        task_id="task-1",
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )

    assert canary.status is PromotionStatus.APPROVED
    assert production.status is PromotionStatus.BLOCKED
    assert store.store_policy_calls == 0


def test_async_deployment_callback_fails_without_activation() -> None:
    async def deploy(policy: Any, stage: PromotionStage, context: Mapping[str, Any]) -> bool:
        del policy, stage, context
        return True

    store = _Store(_policy("search", "summarize"))
    audit = InMemoryAuditSink()
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        audit_sink=audit,
        deploy_callback=deploy,
        enforce_stages=False,
    )

    result = promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )

    assert result.status is PromotionStatus.FAILED
    assert "TypeError" in result.reason
    assert result.deployment_result is None
    assert store.store_policy_calls == 0
    assert (
        audit.query(
            agent_id="agent-1",
            event_type=AuditEventType.PROMOTION_APPROVED,
        )
        == []
    )
    assert (
        len(
            audit.query(
                agent_id="agent-1",
                event_type=AuditEventType.PROMOTION_FAILED,
            )
        )
        == 1
    )


def test_activation_store_failure_returns_failed_without_deployed_candidate() -> None:
    class FailingStore(_Store):
        def store_policy(self, policy: Any) -> str:
            self.store_policy_calls += 1
            raise OSError("storage unavailable")

    store = FailingStore(_policy("search", "summarize"))
    audit = InMemoryAuditSink()
    callbacks = []
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        audit_sink=audit,
        deploy_callback=lambda policy, stage, context: callbacks.append(policy.id),
    )
    promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
    )
    callbacks.clear()

    result = promoter.promote_if_compliant(
        "policy-2",
        agent_id="agent-1",
        task_id="task-1",
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )

    assert result.status is PromotionStatus.FAILED
    assert result.reason == "Policy activation failed (OSError)"
    assert store.store_policy_calls == 1
    assert callbacks == []
    promotion = promoter.last_policy.metadata["agent_governance"]["promotion"]
    assert promotion["status"] == "failed"
    assert promotion["history"][-1]["status"] == "failed"
    deployment_events = audit.query(
        agent_id="agent-1",
        event_type=AuditEventType.POLICY_DEPLOYED,
    )
    assert [event.details["stage"] for event in deployment_events] == ["canary"]
    assert (
        len(
            audit.query(
                agent_id="agent-1",
                event_type=AuditEventType.PROMOTION_FAILED,
            )
        )
        == 1
    )


def test_run_persistence_failure_prevents_production_activation() -> None:
    class RunBackedStore(_Store):
        def __init__(self, policy: Any) -> None:
            super().__init__(policy)
            self.run = SimpleNamespace(metadata={})
            self.fail_run_writes = False

        def get_run(self, run_id: str, agent_id: str) -> Any:
            del run_id, agent_id
            return self.run

        def store_run(self, run: Any) -> str:
            if self.fail_run_writes:
                raise OSError("run storage unavailable")
            self.run = run
            return "run-1"

    policy = _policy("search", "summarize")
    policy.to_dict = lambda: {"id": policy.id, "version": policy.version}
    store = RunBackedStore(policy)
    audit = InMemoryAuditSink()
    callbacks = []
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        audit_sink=audit,
        deploy_callback=lambda policy, stage, context: callbacks.append(policy.id),
    )
    promoter.promote_if_compliant(
        policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
    )
    callbacks.clear()
    store.fail_run_writes = True

    with pytest.raises(OSError, match="run storage unavailable"):
        promoter.promote_if_compliant(
            "policy-2",
            agent_id="agent-1",
            task_id="task-1",
            stage=PromotionStage.PRODUCTION,
            baseline={"violation_rate": 0.0},
        )

    assert store.store_policy_calls == 0
    assert callbacks == []
    production_deployments = [
        event
        for event in audit.query(
            agent_id="agent-1",
            event_type=AuditEventType.POLICY_DEPLOYED,
        )
        if event.details["stage"] == "production"
    ]
    assert production_deployments == []


def test_production_approval_audit_failure_prevents_callback_and_activation() -> None:
    class FailingAuditSink:
        def emit(self, event: Any) -> None:
            if (
                event.event_type is AuditEventType.PROMOTION_APPROVED
                and event.details["stage"] == "production"
            ):
                raise OSError("audit unavailable")

    store = _Store(_policy("search", "summarize"))
    callbacks = []
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        audit_sink=FailingAuditSink(),
        deploy_callback=lambda policy, stage, context: callbacks.append(policy.id),
    )
    promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
    )
    callbacks.clear()

    result = promoter.promote_if_compliant(
        "policy-2",
        agent_id="agent-1",
        task_id="task-1",
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )

    assert result.status is PromotionStatus.FAILED
    assert result.reason == "Policy activation failed (OSError)"
    assert callbacks == []
    assert store.store_policy_calls == 0


def test_production_callback_rejection_rolls_back_active_policy() -> None:
    store = _Store(_policy("search", "summarize"))
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        audit_sink=InMemoryAuditSink(),
        deploy_callback=lambda policy, stage, context: stage is not PromotionStage.PRODUCTION,
    )
    promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
    )
    previous = store.get_active_policy("agent-1", "task-1")

    result = promoter.promote_if_compliant(
        "policy-2",
        agent_id="agent-1",
        task_id="task-1",
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )

    assert result.status is PromotionStatus.FAILED
    assert store.store_policy_calls == 2
    assert store.get_active_policy("agent-1", "task-1").metadata == previous.metadata


def test_post_activation_audit_failure_is_logged_and_exposed(caplog) -> None:
    class FailingDeploymentAuditSink:
        def emit(self, event: Any) -> None:
            if (
                event.event_type is AuditEventType.POLICY_DEPLOYED
                and event.details["stage"] == "production"
            ):
                raise OSError("audit unavailable")

    store = _Store(_policy("search", "summarize"))
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        audit_sink=FailingDeploymentAuditSink(),
        deploy_callback=lambda policy, stage, context: True,
    )
    promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
    )

    with caplog.at_level("ERROR"):
        result = promoter.promote_if_compliant(
            "policy-2",
            agent_id="agent-1",
            task_id="task-1",
            stage=PromotionStage.PRODUCTION,
            baseline={"violation_rate": 0.0},
        )

    assert result.status is PromotionStatus.DEPLOYED
    assert promoter.last_audit_error == "OSError"
    assert "deployment audit emission failed" in caplog.text


def test_missing_audit_sink_prevents_production_callback_and_activation() -> None:
    store = _Store(_policy("search", "summarize"))
    callbacks = []
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        deploy_callback=lambda policy, stage, context: callbacks.append(stage),
    )
    promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
    )
    callbacks.clear()

    result = promoter.promote_if_compliant(
        "policy-2",
        agent_id="agent-1",
        task_id="task-1",
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )

    assert result.status is PromotionStatus.FAILED
    assert result.reason == "Policy activation failed (RuntimeError)"
    assert callbacks == []
    assert store.store_policy_calls == 0


def test_missing_run_storage_prevents_production_callback_and_activation() -> None:
    class NoRunStore(_Store):
        get_run = None
        store_run = None

    store = NoRunStore(_policy("search", "summarize"))
    callbacks = []
    promoter = GovernedPolicyPromotion(
        _PolicyEvaluator(),
        store=store,
        provenance_key=PROVENANCE_KEY,
        audit_sink=InMemoryAuditSink(),
        deploy_callback=lambda policy, stage, context: callbacks.append(stage),
    )
    promoter.promote_if_compliant(
        store.policy,
        stage=PromotionStage.CANARY,
        baseline={"violation_rate": 0.0},
    )
    callbacks.clear()

    result = promoter.promote_if_compliant(
        "policy-2",
        agent_id="agent-1",
        task_id="task-1",
        stage=PromotionStage.PRODUCTION,
        baseline={"violation_rate": 0.0},
    )

    assert result.status is PromotionStatus.FAILED
    assert result.reason == "Policy activation failed (RuntimeError)"
    assert callbacks == []
    assert store.store_policy_calls == 0
