# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for optional advisory policy checks."""

from __future__ import annotations

import httpx
import pytest
from agentmesh.governance import AuditLog, Policy, PolicyEngine, PolicyRule
from agentmesh.governance.advisory import AdvisoryResult, EndpointAdvisoryCheck

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


def test_advisory_invalid_action_falls_through_to_deterministic_allow() -> None:
    audit_log = AuditLog()
    engine = _allowing_engine()
    engine.set_advisory_check(
        lambda *_: {
            "action": "unexpected",
            "reason": "malformed classifier response",
            "classifier": "custom-endpoint",
        },
        audit_log=audit_log,
    )

    decision = engine.evaluate(AGENT_DID, {"action": {"type": "tool_call"}})

    assert decision.allowed is True
    assert decision.action == "allow"
    assert decision.metadata["advisory"]["deterministic"] is False
    assert decision.metadata["advisory"]["action"] == "allow"

    entries = audit_log.get_entries_by_type("advisory_policy_evaluation")
    assert len(entries) == 1
    assert entries[0].data["deterministic"] is False
    assert entries[0].policy_decision == "allow"


def test_malformed_advisory_result_falls_through_to_deterministic_allow() -> None:
    audit_log = AuditLog()
    engine = _allowing_engine()
    engine.set_advisory_check(
        lambda *_: ["not", "a", "result"],
        audit_log=audit_log,
    )

    decision = engine.evaluate(AGENT_DID, {"action": {"type": "tool_call"}})

    assert decision.allowed is True
    assert decision.action == "allow"
    assert decision.metadata["advisory"]["deterministic"] is False
    assert decision.metadata["advisory"]["action"] == "allow"
    assert decision.metadata["advisory"]["metadata"]["malformed_result"] is True

    entries = audit_log.get_entries_by_type("advisory_policy_evaluation")
    assert len(entries) == 1
    assert entries[0].data["deterministic"] is False
    assert entries[0].policy_decision == "allow"


def test_endpoint_advisory_check_requires_https() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        EndpointAdvisoryCheck("http://classifier.example/check")


def test_endpoint_advisory_check_enforces_allowed_hosts() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        EndpointAdvisoryCheck(
            "https://untrusted.example/check",
            allowed_hosts=["classifier.example"],
        )


def test_endpoint_timeout_falls_through_to_deterministic_allow(monkeypatch) -> None:
    audit_log = AuditLog()
    engine = _allowing_engine()

    def timeout_post(*args, **kwargs):
        raise httpx.TimeoutException("classifier timed out")

    monkeypatch.setattr("agentmesh.governance.advisory.httpx.post", timeout_post)
    engine.set_advisory_check(
        EndpointAdvisoryCheck(
            "https://classifier.example/check",
            allowed_hosts=["classifier.example"],
            timeout=0.1,
        ),
        audit_log=audit_log,
    )

    decision = engine.evaluate(AGENT_DID, {"action": {"type": "tool_call"}})

    assert decision.allowed is True
    assert decision.action == "allow"
    assert decision.metadata["advisory"]["deterministic"] is False
    assert decision.metadata["advisory"]["action"] == "allow"
    assert decision.metadata["advisory"]["metadata"]["error"] is True

    entries = audit_log.get_entries_by_type("advisory_policy_evaluation")
    assert len(entries) == 1
    assert entries[0].data["deterministic"] is False
    assert entries[0].policy_decision == "allow"


def test_endpoint_advisory_check_retries_transient_http_errors(monkeypatch) -> None:
    calls = 0

    def flaky_post(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("temporary network failure")
        request = httpx.Request("POST", "https://classifier.example/check")
        return httpx.Response(
            200,
            json={"action": "block", "reason": "unsafe"},
            request=request,
        )

    monkeypatch.setattr("agentmesh.governance.advisory.httpx.post", flaky_post)
    check = EndpointAdvisoryCheck(
        "https://classifier.example/check",
        allowed_hosts=["classifier.example"],
        max_retries=1,
        retry_backoff=0,
    )

    result = check.evaluate(
        AGENT_DID,
        {"action": {"type": "tool_call"}},
        _allowing_engine().evaluate(AGENT_DID, {"action": {"type": "tool_call"}}),
    )

    assert calls == 2
    assert result.action == "block"
    assert result.classifier == "classifier-endpoint"


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
