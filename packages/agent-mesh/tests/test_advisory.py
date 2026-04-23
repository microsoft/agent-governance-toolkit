# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for optional advisory policy checks."""

from __future__ import annotations

from agentmesh.governance import AuditLog, Policy, PolicyEngine, PolicyRule
from agentmesh.governance.advisory import AdvisoryResult

AGENT_DID = "did:agentmesh:test"


def _allowing_engine() -> PolicyEngine:
    engine = PolicyEngine()
    engine.load_policy(
        Policy(
            name="allow-safe-actions",
            agents=["*"],
            rules=[
                PolicyRule(
                    name="allow-tool",
                    condition="action.type == 'tool_call'",
                    action="allow",
                )
            ],
            default_action="deny",
        )
    )
    return engine


def test_advisory_block_tightens_deterministic_allow() -> None:
    audit_log = AuditLog()
    engine = _allowing_engine()

    def classifier(agent_did: str, context: dict, deterministic_decision):
        assert agent_did == AGENT_DID
        assert context["action"]["type"] == "tool_call"
        assert deterministic_decision.allowed is True
        return AdvisoryResult(
            action="block",
            reason="possible prompt injection",
            classifier="custom-reviewer",
            confidence=0.91,
        )

    engine.set_advisory_check(classifier, audit_log=audit_log)

    decision = engine.evaluate(AGENT_DID, {"action": {"type": "tool_call"}})

    assert decision.allowed is False
    assert decision.action == "deny"
    assert decision.matched_rule == "allow-tool"
    assert decision.metadata["advisory"]["deterministic"] is False
    assert decision.metadata["advisory"]["action"] == "block"

    entries = audit_log.get_entries_by_type("advisory_policy_evaluation")
    assert len(entries) == 1
    assert entries[0].data["deterministic"] is False
    assert entries[0].policy_decision == "block"


def test_advisory_flag_keeps_action_allowed_and_marks_for_review() -> None:
    audit_log = AuditLog()
    engine = _allowing_engine()
    engine.set_advisory_check(
        lambda *_: {
            "action": "flag_for_review",
            "reason": "possible social engineering",
            "classifier": "azure-content-safety",
        },
        audit_log=audit_log,
    )

    decision = engine.evaluate(AGENT_DID, {"action": {"type": "tool_call"}})

    assert decision.allowed is True
    assert decision.action == "warn"
    assert decision.metadata["advisory"]["deterministic"] is False
    assert decision.metadata["advisory"]["action"] == "flag_for_review"

    entries = audit_log.get_entries_by_type("advisory_policy_evaluation")
    assert len(entries) == 1
    assert entries[0].data["deterministic"] is False
    assert entries[0].policy_decision == "flag_for_review"


def test_advisory_failure_falls_through_to_deterministic_allow() -> None:
    audit_log = AuditLog()
    engine = _allowing_engine()

    def failing_classifier(*_):
        raise RuntimeError("classifier unavailable")

    engine.set_advisory_check(
        failing_classifier,
        classifier="custom-endpoint",
        audit_log=audit_log,
    )

    decision = engine.evaluate(AGENT_DID, {"action": {"type": "tool_call"}})

    assert decision.allowed is True
    assert decision.action == "allow"
    assert decision.matched_rule == "allow-tool"
    assert decision.metadata["advisory"]["deterministic"] is False
    assert decision.metadata["advisory"]["action"] == "allow"
    assert decision.metadata["advisory"]["metadata"]["error"] is True

    entries = audit_log.get_entries_by_type("advisory_policy_evaluation")
    assert len(entries) == 1
    assert entries[0].data["deterministic"] is False
    assert entries[0].policy_decision == "allow"


def test_advisory_never_overrides_deterministic_deny() -> None:
    audit_log = AuditLog()
    calls: list[str] = []
    engine = PolicyEngine()
    engine.load_policy(
        Policy(
            name="deny-export",
            agents=["*"],
            rules=[
                PolicyRule(
                    name="deny-export",
                    condition="action.type == 'export'",
                    action="deny",
                )
            ],
            default_action="allow",
        )
    )
    engine.set_advisory_check(
        lambda *_: calls.append("called") or {"action": "allow"},
        audit_log=audit_log,
    )

    decision = engine.evaluate(AGENT_DID, {"action": {"type": "export"}})

    assert decision.allowed is False
    assert decision.action == "deny"
    assert calls == []
    assert audit_log.get_entries_by_type("advisory_policy_evaluation") == []
