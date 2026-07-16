# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Human-approval scenario: a high-risk action escalates before executing.

This scenario is deterministic and does not require a model. It drives the
production ``agent_os`` escalation manager: a high-blast-radius action is
gated behind human approval, the approve path executes the action exactly
once, and the reject path blocks it. Both paths leave an escalation audit
trail.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from agent_os.escalation import (
    EscalationManager,
    EscalationPolicy,
    EscalationRequest,
)

from support import ScenarioResult, write_artifact


HIGH_RISK_ACTION = "delete_production_dataset"
DATASET_ID = "prod-events"


class MockDataStore:
    def __init__(self) -> None:
        self.deletions: list[str] = []

    def delete_dataset(self, dataset_id: str) -> None:
        self.deletions.append(dataset_id)


def _build_manager(approve: bool) -> EscalationManager:
    policy = EscalationPolicy(
        actions_requiring_approval=[HIGH_RISK_ACTION],
        timeout_seconds=5,
        default_on_timeout="deny",
    )

    async def handler(request: EscalationRequest) -> None:
        if approve:
            manager.approve(
                request.request_id, decided_by="oncall", reason="verified backup"
            )
        else:
            manager.deny(
                request.request_id, decided_by="oncall", reason="no backup on file"
            )

    manager = EscalationManager(policy, approval_handler=handler)
    return manager


def run_human_approval(
    approve: bool,
) -> tuple[ScenarioResult, MockDataStore, EscalationManager]:
    store = MockDataStore()
    manager = _build_manager(approve)

    decision = asyncio.run(
        manager.request_approval(
            agent_id="cleanup-agent",
            action=HIGH_RISK_ACTION,
            context={"dataset_id": DATASET_ID},
            reason="quarterly cleanup",
        )
    )
    if decision.approved:
        store.delete_dataset(DATASET_ID)

    return ScenarioResult(
        decision="allow" if decision.approved else "deny",
        executed_tools=["delete_dataset"] if decision.approved else [],
    ), store, manager


def test_high_risk_action_executes_after_approval(artifact_dir: Path) -> None:
    result, store, manager = run_human_approval(approve=True)

    assert result.decision == "allow"
    assert result.executed_tools == ["delete_dataset"]
    assert store.deletions == [DATASET_ID]
    assert "escalated" in {event["event_type"] for event in manager.audit_trail}

    write_artifact(result, artifact_dir, "human-approval-approved")


def test_high_risk_action_blocked_after_rejection(artifact_dir: Path) -> None:
    result, store, manager = run_human_approval(approve=False)

    assert result.decision == "deny"
    assert result.executed_tools == []
    assert store.deletions == []
    assert "escalated" in {event["event_type"] for event in manager.audit_trail}

    write_artifact(result, artifact_dir, "human-approval-rejected")
