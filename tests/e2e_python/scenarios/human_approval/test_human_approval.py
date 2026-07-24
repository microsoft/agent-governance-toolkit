# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Human-approval scenario: a high-risk action escalates before executing.

This scenario is deterministic and does not require a model. The ACS
``pre_tool_call`` intervention point escalates a high-blast-radius deletion to
a human approver instead of allowing or denying it outright. The host resolves
the escalation: the approve path executes the action exactly once, the reject
path blocks it, and both paths leave an escalation audit trail.
"""

from __future__ import annotations

from pathlib import Path

from support import (
    PolicyDecision,
    ScenarioResult,
    evaluate_pre_tool_call,
    load_acs_runtime,
    write_artifact,
)


POLICY_DIR = Path(__file__).parent
HIGH_RISK_ACTION = "delete_production_dataset"
DATASET_ID = "prod-events"


class MockDataStore:
    def __init__(self) -> None:
        self.deletions: list[str] = []

    def delete_dataset(self, dataset_id: str) -> None:
        self.deletions.append(dataset_id)


def run_human_approval(
    human_approval: bool,
) -> tuple[ScenarioResult, MockDataStore, list[dict[str, str]], PolicyDecision]:
    store = MockDataStore()
    runtime = load_acs_runtime(POLICY_DIR)
    decision = evaluate_pre_tool_call(
        runtime,
        agent_id="cleanup-agent",
        tool_name=HIGH_RISK_ACTION,
        arguments={"dataset_id": DATASET_ID},
    )

    audit_trail: list[dict[str, str]] = []
    approved = False
    if decision.verdict == "escalate":
        audit_trail.append(
            {"event_type": "escalated", "reason": decision.reason or ""}
        )
        approved = human_approval
        audit_trail.append(
            {
                "event_type": "approved" if human_approval else "rejected",
                "decided_by": "oncall",
                "reason": "verified backup" if human_approval else "no backup on file",
            }
        )

    if approved:
        store.delete_dataset(DATASET_ID)

    return ScenarioResult(
        decision="allow" if approved else "deny",
        executed_tools=[HIGH_RISK_ACTION] if approved else [],
    ), store, audit_trail, decision


def test_high_risk_action_executes_after_approval(artifact_dir: Path) -> None:
    result, store, audit_trail, policy_decision = run_human_approval(human_approval=True)

    # ACS escalates the high-risk deletion before any human decision.
    assert policy_decision.verdict == "escalate"
    assert policy_decision.reason == "approval.escalate-high-risk-delete"
    assert "escalated" in {event["event_type"] for event in audit_trail}

    # After approval the action runs exactly once.
    assert result.decision == "allow"
    assert result.executed_tools == [HIGH_RISK_ACTION]
    assert store.deletions == [DATASET_ID]

    write_artifact(result, artifact_dir, "human-approval-approved")


def test_high_risk_action_blocked_after_rejection(artifact_dir: Path) -> None:
    result, store, audit_trail, policy_decision = run_human_approval(human_approval=False)

    # ACS escalates the high-risk deletion before any human decision.
    assert policy_decision.verdict == "escalate"
    assert policy_decision.reason == "approval.escalate-high-risk-delete"
    assert "escalated" in {event["event_type"] for event in audit_trail}

    # After rejection the action is blocked.
    assert result.decision == "deny"
    assert result.executed_tools == []
    assert store.deletions == []

    write_artifact(result, artifact_dir, "human-approval-rejected")
