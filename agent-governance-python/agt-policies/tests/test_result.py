# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the native v5 evaluation result."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agt.policies import PolicyAuditRecord, PolicyEvaluation


def test_policy_evaluation_normalizes_reason_and_builds_audit_record() -> None:
    result = PolicyEvaluation(
        verdict="deny",
        reason_code="blocked_tool",
        message="restricted internal detail",
        intervention_point="pre_tool_call",
        result_labels=("security",),
        input_identity="sha256:input",
        enforced_identity="sha256:input",
    )

    assert result.reason_code == "policy:blocked_tool"
    assert result.public_error_message() == "Request blocked by policy."
    audit = result.audit_record()
    assert audit["schema"] == "agt.policy_evaluation.v1"
    assert audit["message"] == "restricted internal detail"
    assert audit["result_labels"] == ["security"]


def test_policy_audit_record_exposes_versioned_json_schema() -> None:
    schema = PolicyAuditRecord.model_json_schema()

    assert schema["properties"]["schema"]["const"] == "agt.policy_evaluation.v1"
    assert "verdict" in schema["required"]


def test_runtime_error_uses_fail_closed_public_message() -> None:
    result = PolicyEvaluation(
        verdict="deny",
        reason_code="runtime_error:dispatcher_failed",
        message="secret stack detail",
    )

    assert result.public_error_message() == "Policy evaluation failed closed."


def test_policy_evaluation_is_immutable() -> None:
    result = PolicyEvaluation(verdict="allow")

    with pytest.raises(ValidationError):
        result.verdict = "deny"  # type: ignore[misc]
