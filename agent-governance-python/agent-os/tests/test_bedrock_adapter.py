# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the AWS Bedrock Agent governance adapter.

All tests are fully offline, no real AWS credentials or boto3 network
calls are made.  The boto3 client is replaced by a MagicMock throughout.

Coverage:
- BedrockKernel construction and defaults
- wrap() / unwrap() round-trip
- health_check()
- Blocked-pattern enforcement on inputText
- PII detection on inputText (SSN, email, credit card)
- Tool allowlist enforcement on streaming action-group events
- Explicitly blocked_tools enforcement
- max_tool_calls limit
- Rate limiting per agent ARN
- Clean invocation passes through end-to-end
- audit summary reflects session state
- PolicyViolationError is raised (not swallowed)
- Cedar/OPA gate delegation
- Graceful ImportError when boto3 is absent
- GovernedBedrockClient __repr__
- _GovernedEventStream passthrough for non-action events
- _GovernedEventStream proxies unknown attributes to underlying stream
"""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import agent_os.integrations.bedrock_adapter as _bmod

# Pretend boto3 is installed for all tests that call wrap().
_bmod._HAS_BOTO3 = True

from agent_os.integrations.base import GovernancePolicy, PolicyViolationError
from agent_os.integrations.bedrock_adapter import (
    BedrockContext,
    BedrockKernel,
    GovernedBedrockClient,
    _GovernedEventStream,
)

# Helper functions
def _mock_client(events: list[dict] | None = None) -> MagicMock:
    """Return a mock boto3 bedrock-agent-runtime client."""
    client = MagicMock()
    stream = iter(events or [])
    client.invoke_agent.return_value = {
        "ResponseMetadata": {"RequestId": "req-test-001"},
        "completion": stream,
    }
    return client


def _kernel(**kw) -> BedrockKernel:
    return BedrockKernel(policy=GovernancePolicy(**kw))


def _action_event(tool_name: str) -> dict:
    return {
        "returnControl": {
            "invocationInputs": [
                {
                    "actionGroupInvocationInput": {
                        "actionGroupName": tool_name,
                        "function": tool_name,
                    }
                }
            ]
        }
    }


# Construction & defaults
class TestBedrockKernelInit:
    def test_default_policy(self):
        k = BedrockKernel()
        assert isinstance(k.policy, GovernancePolicy)

    def test_custom_policy(self):
        p = GovernancePolicy(max_tool_calls=5)
        k = BedrockKernel(policy=p)
        assert k.policy.max_tool_calls == 5

    def test_blocked_tools_stored_as_set(self):
        k = BedrockKernel(blocked_tools=["delete_bucket", "terminate"])
        assert "delete_bucket" in k._blocked_tools
        assert "terminate" in k._blocked_tools

    def test_no_rate_limiter_by_default(self):
        assert BedrockKernel()._rate_limiter is None

    def test_rate_limiter_created_when_nonzero(self):
        k = BedrockKernel(rate_limit_per_minute=30)
        assert k._rate_limiter is not None



# wrap() / unwrap()
class TestWrapUnwrap:
    def test_wrap_returns_governed_client(self):
        k = BedrockKernel()
        governed = k.wrap(_mock_client())
        assert isinstance(governed, GovernedBedrockClient)

    def test_unwrap_returns_original_client(self):
        k = BedrockKernel()
        raw = _mock_client()
        governed = k.wrap(raw)
        assert k.unwrap(governed) is raw

    def test_unwrap_passthrough_for_non_governed(self):
        k = BedrockKernel()
        obj = object()
        assert k.unwrap(obj) is obj

    def test_wrap_registers_context(self):
        k = BedrockKernel()
        k.wrap(_mock_client())
        assert len(k.contexts) == 1

    def test_wrap_raises_without_boto3(self):
        _bmod._HAS_BOTO3 = False
        try:
            with pytest.raises(ImportError, match="boto3"):
                BedrockKernel().wrap(_mock_client())
        finally:
            _bmod._HAS_BOTO3 = True



# health_check()
class TestHealthCheck:
    def test_healthy_by_default(self):
        h = BedrockKernel().health_check()
        assert h["status"] == "healthy"
        assert h["backend"] == "aws-bedrock"
        assert h["last_error"] is None

    def test_degraded_after_error(self):
        k = BedrockKernel()
        k._last_error = "connection timeout"
        assert k.health_check()["status"] == "degraded"

    def test_uptime_is_positive(self):
        assert BedrockKernel().health_check()["uptime_seconds"] >= 0


# Input scanning, blocked patterns
class TestBlockedPatterns:
    def test_blocked_pattern_in_input_raises(self):
        k = _kernel(blocked_patterns=["DROP TABLE"])
        governed = k.wrap(_mock_client())
        with pytest.raises(PolicyViolationError, match="matched pattern"):
            governed.invoke_agent(
                agentId="A", agentAliasId="L", sessionId="s",
                inputText="DROP TABLE users",
            )

    def test_clean_input_passes_through(self):
        k = _kernel(blocked_patterns=["DROP TABLE"])
        governed = k.wrap(_mock_client())
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s",
            inputText="Summarize this quarter",
        )
        assert "completion" in resp

    def test_multiple_blocked_patterns_any_match_blocks(self):
        k = _kernel(blocked_patterns=["secret", "password"])
        governed = k.wrap(_mock_client())
        with pytest.raises(PolicyViolationError):
            governed.invoke_agent(
                agentId="A", agentAliasId="L", sessionId="s",
                inputText="my password is 1234",
            )


# PII detection
class TestPIIDetection:
    @pytest.mark.parametrize("bad_input", [
        "SSN: 123-45-6789",
        "email me at test.user@example.com",
        "card: 4111111111111111",
    ])
    def test_pii_in_input_raises(self, bad_input):
        k = BedrockKernel()
        governed = k.wrap(_mock_client())
        with pytest.raises(PolicyViolationError, match="PII"):
            governed.invoke_agent(
                agentId="A", agentAliasId="L", sessionId="s",
                inputText=bad_input,
            )

    def test_clean_input_no_pii_passes(self):
        k = BedrockKernel()
        governed = k.wrap(_mock_client())
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s",
            inputText="List this week's orders",
        )
        assert resp is not None


# Tool allowlist, streaming events
class TestToolAllowlist:
    def test_allowed_tool_passes(self):
        k = _kernel(allowed_tools=["query_db"])
        events = [_action_event("query_db"), {"chunk": {"bytes": b"ok"}}]
        governed = k.wrap(_mock_client(events))
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s",
            inputText="run report",
        )
        consumed = list(resp["completion"])
        assert len(consumed) == 2

    def test_disallowed_tool_in_stream_raises(self):
        k = _kernel(allowed_tools=["query_db"])
        events = [_action_event("delete_records")]
        governed = k.wrap(_mock_client(events))
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s",
            inputText="run report",
        )
        with pytest.raises(PolicyViolationError, match="not in the allowed_tools"):
            list(resp["completion"])

    def test_empty_allowed_tools_permits_anything(self):
        k = _kernel(allowed_tools=[])
        events = [_action_event("any_tool")]
        governed = k.wrap(_mock_client(events))
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s",
            inputText="go",
        )
        consumed = list(resp["completion"])
        assert len(consumed) == 1


# Explicitly blocked tools
class TestBlockedTools:
    def test_blocked_tool_raises_even_if_in_allowlist(self):
        k = BedrockKernel(
            policy=GovernancePolicy(allowed_tools=["delete_bucket"]),
            blocked_tools=["delete_bucket"],
        )
        events = [_action_event("delete_bucket")]
        governed = k.wrap(_mock_client(events))
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s",
            inputText="run",
        )
        with pytest.raises(PolicyViolationError, match="explicitly blocked"):
            list(resp["completion"])

    def test_blocked_tool_increments_blocked_events(self):
        k = BedrockKernel(blocked_tools=["rm_rf"])
        events = [_action_event("rm_rf")]
        governed = k.wrap(_mock_client(events))
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s", inputText="go",
        )
        with pytest.raises(PolicyViolationError):
            list(resp["completion"])
        assert governed.get_context().blocked_events == 1


# max_tool_calls limit
class TestMaxToolCalls:
    def test_exceeding_limit_raises(self):
        k = _kernel(max_tool_calls=2)
        events = [_action_event("tool_a"), _action_event("tool_b"), _action_event("tool_c")]
        governed = k.wrap(_mock_client(events))
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s", inputText="go",
        )
        with pytest.raises(PolicyViolationError, match="Tool call limit"):
            list(resp["completion"])

    def test_at_limit_raises_not_below(self):
        k = _kernel(max_tool_calls=1)
        events = [_action_event("tool_a"), _action_event("tool_b")]
        governed = k.wrap(_mock_client(events))
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s", inputText="go",
        )
        with pytest.raises(PolicyViolationError):
            list(resp["completion"])


# Rate limiting
class TestRateLimiting:
    def test_rate_limit_exceeded_raises(self, monkeypatch):
        from agent_os.integrations.rate_limiter import RateLimitStatus
        k = BedrockKernel(rate_limit_per_minute=1)
        mock_status = RateLimitStatus(allowed=False, remaining_calls=0, reset_at=0.0, wait_seconds=1.0)
        monkeypatch.setattr(k._rate_limiter, "check", lambda _arn: mock_status)
        governed = k.wrap(_mock_client())
        with pytest.raises(PolicyViolationError, match="Rate limit"):
            governed.invoke_agent(
                agentId="A", agentAliasId="L", sessionId="s", inputText="go",
            )

    def test_rate_limit_allowed_passes(self, monkeypatch):
        from agent_os.integrations.rate_limiter import RateLimitStatus
        k = BedrockKernel(rate_limit_per_minute=10)
        mock_status = RateLimitStatus(allowed=True, remaining_calls=9, reset_at=0.0, wait_seconds=0.0)
        monkeypatch.setattr(k._rate_limiter, "check", lambda _arn: mock_status)
        governed = k.wrap(_mock_client())
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s", inputText="go",
        )
        assert resp is not None


# Audit summary
class TestAuditSummary:
    def test_audit_summary_structure(self):
        k = BedrockKernel()
        governed = k.wrap(_mock_client())
        governed.invoke_agent(
            agentId="AGENT1", agentAliasId="ALIAS1", sessionId="s1",
            inputText="Hello",
        )
        summary = governed.get_audit_summary()
        assert "agent_arn" in summary
        assert "invocation_ids" in summary
        assert "action_groups_invoked" in summary
        assert "tool_call_count" in summary
        assert "blocked_events" in summary
        assert "session_id" in summary

    def test_invocation_id_recorded(self):
        k = BedrockKernel()
        governed = k.wrap(_mock_client())
        governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s", inputText="go",
        )
        assert "req-test-001" in governed.get_audit_summary()["invocation_ids"]

    def test_action_groups_recorded_after_stream(self):
        k = _kernel(allowed_tools=["my_tool"])
        events = [_action_event("my_tool")]
        governed = k.wrap(_mock_client(events))
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s", inputText="go",
        )
        list(resp["completion"])
        assert "my_tool" in governed.get_audit_summary()["action_groups_invoked"]


# Cedar/OPA gate
class TestCedarGate:
    def test_cedar_deny_raises(self):
        k = BedrockKernel()
        mock_evaluator = MagicMock()
        mock_evaluator.evaluate.return_value = SimpleNamespace(
            allowed=False, reason="cedar denied"
        )
        k._evaluator = mock_evaluator
        governed = k.wrap(_mock_client())
        with pytest.raises(PolicyViolationError, match="Cedar/OPA"):
            governed.invoke_agent(
                agentId="A", agentAliasId="L", sessionId="s", inputText="go",
            )

    def test_cedar_allow_passes_through(self):
        k = BedrockKernel()
        mock_evaluator = MagicMock()
        mock_evaluator.evaluate.return_value = SimpleNamespace(allowed=True, reason="")
        k._evaluator = mock_evaluator
        governed = k.wrap(_mock_client())
        resp = governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s", inputText="go",
        )
        assert resp is not None


# Client error propagation
class TestErrorPropagation:
    def test_boto3_error_propagates_and_sets_last_error(self):
        k = BedrockKernel()
        raw = _mock_client()
        raw.invoke_agent.side_effect = RuntimeError("Throttling")
        governed = k.wrap(raw)
        with pytest.raises(RuntimeError, match="Throttling"):
            governed.invoke_agent(
                agentId="A", agentAliasId="L", sessionId="s", inputText="go",
            )
        assert k._last_error == "Throttling"


# Attribute proxy
class TestAttributeProxy:
    def test_getattr_proxies_to_underlying_client(self):
        k = BedrockKernel()
        raw = _mock_client()
        raw.some_custom_method = lambda: "custom"
        governed = k.wrap(raw)
        assert governed.some_custom_method() == "custom"

    def test_get_context_returns_bedrock_context(self):
        k = BedrockKernel()
        governed = k.wrap(_mock_client())
        assert isinstance(governed.get_context(), BedrockContext)


# GovernedBedrockClient __repr__
class TestRepr:
    def test_repr_contains_agent_arn_and_calls(self):
        k = BedrockKernel()
        governed = k.wrap(_mock_client())
        governed.invoke_agent(
            agentId="MYAGENT", agentAliasId="ALIAS", sessionId="s", inputText="go",
        )
        r = repr(governed)
        assert "MYAGENT" in r
        assert "calls=" in r


# _GovernedEventStream

class TestGovernedEventStream:
    def test_non_action_events_pass_through(self):
        k = BedrockKernel()
        ctx = BedrockContext(agent_id="a", session_id="s", policy=k.policy)
        events = [{"chunk": {"bytes": b"hello"}}, {"trace": {}}]
        stream = _GovernedEventStream(iter(events), k, ctx)
        result = list(stream)
        assert result == events

    def test_proxies_unknown_attrs_to_stream(self):
        k = BedrockKernel()
        ctx = BedrockContext(agent_id="a", session_id="s", policy=k.policy)
        inner = MagicMock()
        inner.close = lambda: "closed"
        stream = _GovernedEventStream(inner, k, ctx)
        assert stream.close() == "closed"

    def test_action_event_recorded_in_context(self):
        k = _kernel(allowed_tools=["my_action"])
        ctx = BedrockContext(agent_id="a", session_id="s", policy=k.policy)
        stream = _GovernedEventStream(iter([_action_event("my_action")]), k, ctx)
        list(stream)
        assert "my_action" in ctx.action_groups_invoked
        assert ctx.call_count == 1


# boto3 absent
class TestMissingBoto3:
    def test_import_error_message_is_helpful(self):
        _bmod._HAS_BOTO3 = False
        try:
            with pytest.raises(ImportError) as exc_info:
                BedrockKernel().wrap(MagicMock())
            assert "pip install boto3" in str(exc_info.value)
        finally:
            _bmod._HAS_BOTO3 = True


# BedrockContext fields
class TestBedrockContext:
    def test_default_fields(self):
        ctx = BedrockContext(agent_id="a", session_id="s", policy=GovernancePolicy())
        assert ctx.agent_arn == ""
        assert ctx.invocation_ids == []
        assert ctx.action_groups_invoked == []
        assert ctx.blocked_events == 0

    def test_agent_arn_set_on_invoke(self):
        k = BedrockKernel()
        governed = k.wrap(_mock_client())
        governed.invoke_agent(
            agentId="MYID", agentAliasId="MYALIAS", sessionId="s", inputText="go",
        )
        assert "MYID" in governed.get_context().agent_arn
        assert "MYALIAS" in governed.get_context().agent_arn
