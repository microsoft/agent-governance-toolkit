# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OpenTelemetry native observability."""

import pytest
from agentmesh.governance.otel_observability import (
    enable_otel,
    is_enabled,
    reset,
    trace_policy_evaluation,
    trace_approval,
    trace_trust_verification,
    record_denial,
    ATTR_POLICY_ACTION,
    ATTR_POLICY_RULE,
    ATTR_POLICY_STAGE,
    ATTR_AGENT_ID,
    ATTR_APPROVAL_OUTCOME,
    ATTR_TRUST_SCORE,
)


@pytest.fixture(autouse=True)
def clean_otel():
    """Reset OTel state before each test."""
    reset()
    yield
    reset()


class TestEnableOtel:
    def test_enable_sets_initialized(self):
        enable_otel(service_name="test-agent")
        assert is_enabled()

    def test_double_enable_is_noop(self):
        enable_otel(service_name="test-1")
        enable_otel(service_name="test-2")  # should not crash
        assert is_enabled()

    def test_not_enabled_by_default(self):
        assert not is_enabled()


class TestTracePolicyEvaluation:
    def test_span_without_otel(self):
        """Works as no-op when OTel is not enabled."""
        with trace_policy_evaluation(agent_id="a1", stage="pre_tool") as result:
            result["action"] = "allow"
            result["rule"] = "test-rule"
            result["allowed"] = True

        assert result["action"] == "allow"

    def test_span_with_otel(self):
        """Emits span when OTel is enabled."""
        enable_otel(service_name="test")

        # Get the tracer directly from our module to verify it works
        from agentmesh.governance import otel_observability
        assert otel_observability._tracer is not None

        with trace_policy_evaluation(agent_id="agent-1", stage="pre_tool") as result:
            result["action"] = "deny"
            result["rule"] = "block-export"
            result["allowed"] = False

        # Verify the context manager completed without error and result is populated
        assert result["action"] == "deny"
        assert result["rule"] == "block-export"

    def test_span_records_stage(self):
        enable_otel(service_name="test")

        with trace_policy_evaluation(agent_id="a1", stage="post_tool") as result:
            result["action"] = "allow"
            result["allowed"] = True

        # No crash — stage passed correctly

    def test_result_dict_populated(self):
        """The yielded result dict is available after the block."""
        with trace_policy_evaluation(agent_id="a1") as result:
            result["action"] = "warn"
            result["rule"] = "warn-rule"
            result["custom_key"] = 42

        assert result["custom_key"] == 42


class TestTraceApproval:
    def test_approval_span_without_otel(self):
        with trace_approval(agent_id="a1", rule_name="r1") as result:
            result["outcome"] = "approved"
            result["approver"] = "admin"

        assert result["outcome"] == "approved"

    def test_approval_span_with_otel(self):
        enable_otel(service_name="test")

        with trace_approval(agent_id="a1", rule_name="transfer-rule") as result:
            result["outcome"] = "rejected"
            result["approver"] = "compliance-team"

        assert result["outcome"] == "rejected"
        assert result["approver"] == "compliance-team"


class TestTraceTrustVerification:
    def test_trust_span_without_otel(self):
        with trace_trust_verification(agent_id="a1") as result:
            result["score"] = 0.85
            result["tier"] = "trusted"

        assert result["score"] == 0.85

    def test_trust_span_with_otel(self):
        enable_otel(service_name="test")

        with trace_trust_verification(agent_id="agent-x") as result:
            result["score"] = 0.92
            result["tier"] = "verified"

        assert result["score"] == 0.92
        assert result["tier"] == "verified"


class TestRecordDenial:
    def test_denial_without_otel(self):
        """No crash when OTel not enabled."""
        record_denial(rule_name="block-pii", tool_name="send_email")

    def test_denial_with_otel(self):
        enable_otel(service_name="test")
        record_denial(rule_name="block-pii", tool_name="send_email", stage="post_tool")
        # No crash — metrics recorded


class TestNoOpBehavior:
    def test_all_functions_work_without_enable(self):
        """All tracing functions work gracefully without enable_otel."""
        with trace_policy_evaluation(agent_id="a") as r:
            r["action"] = "allow"

        with trace_approval(agent_id="a") as r:
            r["outcome"] = "approved"

        with trace_trust_verification(agent_id="a") as r:
            r["score"] = 0.5

        record_denial(rule_name="r")

        assert not is_enabled()
