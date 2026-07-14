# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Host-control tests for the native A2A adapter."""

from __future__ import annotations

from typing import Any

from agt.policies import PolicyEvaluation

from agent_os.integrations.a2a_adapter import (
    A2AEvaluation,
    A2AGovernanceAdapter,
    A2APolicy,
)


class _AllowRuntime:
    manifest = None

    def evaluate(
        self, intervention_point: str, snapshot: dict[str, Any]
    ) -> PolicyEvaluation:
        return PolicyEvaluation(
            verdict="allow",
            intervention_point=intervention_point,
        )

    def close(self) -> None:
        pass


def _task(
    *,
    skill: str = "search",
    did: str = "did:mesh:agent-a",
    trust: int = 500,
    text: str = "Find weather",
) -> dict[str, Any]:
    return {
        "id": "task-1",
        "skill_id": skill,
        "x-agentmesh-trust": {
            "source_did": did,
            "source_trust_score": trust,
        },
        "messages": [{"parts": [{"text": text}]}],
    }


def _adapter(policy: A2APolicy | None = None) -> A2AGovernanceAdapter:
    return A2AGovernanceAdapter(
        policy=policy,
        runtime=_AllowRuntime(),
    )


def test_policy_defaults() -> None:
    policy = A2APolicy()

    assert policy.allowed_skills == []
    assert policy.blocked_skills == []
    assert policy.min_trust_score == 0
    assert policy.max_requests_per_minute == 100


def test_blocked_skill_is_denied_before_runtime() -> None:
    result = _adapter(A2APolicy(blocked_skills=["delete"])).evaluate_task(
        _task(skill="delete")
    )

    assert not result.allowed
    assert "blocked" in result.reason


def test_allowlist_rejects_unknown_skill() -> None:
    result = _adapter(A2APolicy(allowed_skills=["search"])).evaluate_task(
        _task(skill="translate")
    )

    assert not result.allowed
    assert "allowed list" in result.reason


def test_allowlist_accepts_known_skill() -> None:
    result = _adapter(A2APolicy(allowed_skills=["search"])).evaluate_task(_task())

    assert result.allowed


def test_trust_threshold_is_enforced() -> None:
    result = _adapter(A2APolicy(min_trust_score=600)).evaluate_task(
        _task(trust=500)
    )

    assert not result.allowed
    assert "below minimum" in result.reason


def test_required_trust_metadata_is_enforced() -> None:
    result = _adapter(A2APolicy(require_trust_metadata=True)).evaluate_task(
        _task(did="")
    )

    assert not result.allowed
    assert "source DID" in result.reason


def test_rate_limit_is_scoped_per_source() -> None:
    adapter = _adapter(A2APolicy(max_requests_per_minute=1))

    assert adapter.evaluate_task(_task(did="did:mesh:a")).allowed
    assert not adapter.evaluate_task(_task(did="did:mesh:a")).allowed
    assert adapter.evaluate_task(_task(did="did:mesh:b")).allowed


def test_evaluation_and_stats_are_recorded() -> None:
    adapter = _adapter(A2APolicy(blocked_skills=["delete"]))

    allowed = adapter.evaluate_task(_task())
    denied = adapter.evaluate_task(_task(skill="delete"))

    assert adapter.get_evaluations() == [allowed, denied]
    assert adapter.get_stats() == {"total": 2, "allowed": 1, "denied": 1}


def test_evaluation_to_dict_includes_native_verdict() -> None:
    result = _adapter().evaluate_task(_task())

    data = result.to_dict()
    assert data["allowed"] is True
    assert data["verdict"] == "allow"
    assert isinstance(result, A2AEvaluation)
