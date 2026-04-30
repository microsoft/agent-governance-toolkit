# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Xfail parity harness for adapter denial-string sanitization."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import pytest

from agent_os.exceptions import PolicyViolationError
from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernancePolicy,
    PolicyInterceptor,
    ToolCallRequest,
)
from agent_os.policies.bridge import governance_to_document


@dataclass(frozen=True)
class _DenialSnapshot:
    """Observed public and audit strings for one denial path."""

    public_message: str
    audit_text: str


@dataclass(frozen=True)
class _LeakCase:
    """Inventory entry for one leaky denial surface."""

    name: str
    trigger: Callable[[], _DenialSnapshot]
    forbidden_fragments: tuple[str, ...]
    audit_fragment: str
    xfail_reason: str


class _TestKernel(BaseIntegration):
    """Minimal concrete integration for in-process denial checks."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


def _from_exception(exc: BaseException) -> _DenialSnapshot:
    details = getattr(exc, "details", {}) or {}
    detail = str(details.get("detail", ""))
    check_result = getattr(exc, "check_result", None)
    audit_entry = getattr(check_result, "audit_entry", {}) or {}
    audit_text = " ".join([detail, str(audit_entry)])
    return _DenialSnapshot(public_message=str(exc), audit_text=audit_text)


def _from_legacy_reason(reason: str) -> _DenialSnapshot:
    try:
        raise PolicyViolationError(reason)
    except PolicyViolationError as exc:
        return _from_exception(exc)


def _from_tool_result(reason: str | None) -> _DenialSnapshot:
    assert reason is not None
    return _from_legacy_reason(reason)


def _base_context(policy: GovernancePolicy, *, call_count: int = 0) -> tuple[_TestKernel, ExecutionContext]:
    kernel = _TestKernel(policy=policy)
    ctx = kernel.create_context("agent-parity")
    ctx.call_count = call_count
    return kernel, ctx


def _policy_interceptor_allowed_tool() -> _DenialSnapshot:
    result = PolicyInterceptor(GovernancePolicy(allowed_tools=["safe_tool"])).intercept(
        ToolCallRequest(tool_name="danger_tool", arguments={})
    )
    return _from_tool_result(result.reason)


def _policy_interceptor_blocked_pattern() -> _DenialSnapshot:
    result = PolicyInterceptor(GovernancePolicy(blocked_patterns=[r"\b\d{3}-\d{2}-\d{4}\b"])).intercept(
        ToolCallRequest(tool_name="lookup", arguments={"value": "123-45-6789"})
    )
    return _from_tool_result(result.reason)


def _policy_interceptor_max_tool_calls() -> _DenialSnapshot:
    policy = GovernancePolicy(max_tool_calls=3)
    _, ctx = _base_context(policy, call_count=3)
    result = PolicyInterceptor(policy, ctx).intercept(ToolCallRequest(tool_name="lookup", arguments={}))
    return _from_tool_result(result.reason)


def _base_pre_execute_max_tool_calls() -> _DenialSnapshot:
    kernel, ctx = _base_context(GovernancePolicy(max_tool_calls=5), call_count=5)
    allowed, reason = kernel.pre_execute(ctx, "safe input")
    assert allowed is False
    return _from_tool_result(reason)


def _base_pre_execute_timeout() -> _DenialSnapshot:
    kernel, ctx = _base_context(GovernancePolicy(timeout_seconds=1))
    ctx.start_time = datetime.now() - timedelta(seconds=2)
    allowed, reason = kernel.pre_execute(ctx, "safe input")
    assert allowed is False
    return _from_tool_result(reason)


def _base_pre_execute_blocked_pattern() -> _DenialSnapshot:
    kernel, ctx = _base_context(GovernancePolicy(blocked_patterns=[r"\b\d{3}-\d{2}-\d{4}\b"]))
    allowed, reason = kernel.pre_execute(ctx, "customer ssn 123-45-6789")
    assert allowed is False
    return _from_tool_result(reason)


def _bridge_message(rule_name: str, policy: GovernancePolicy) -> _DenialSnapshot:
    document = governance_to_document(policy)
    rule = next(rule for rule in document.rules if rule.name == rule_name)
    return _from_legacy_reason(rule.message or "")


def _langchain_allow_list() -> _DenialSnapshot:
    from agent_os.integrations import langchain_adapter as adapter

    kernel = adapter.LangChainKernel(policy=GovernancePolicy(allowed_tools=["safe_tool"]))
    try:
        kernel._check_tool_policy("danger_tool", (), {}, None)
    except adapter.PolicyViolationError as exc:
        return _from_exception(exc)
    raise AssertionError("expected LangChain policy violation")


def _langchain_blocked_pattern_args() -> _DenialSnapshot:
    from agent_os.integrations import langchain_adapter as adapter

    kernel = adapter.LangChainKernel(policy=GovernancePolicy(blocked_patterns=[r"\b\d{3}-\d{2}-\d{4}\b"]))
    try:
        kernel._check_tool_policy("lookup", ("customer ssn 123-45-6789",), {}, None)
    except adapter.PolicyViolationError as exc:
        return _from_exception(exc)
    raise AssertionError("expected LangChain policy violation")


def _langchain_blocked_pattern_tool_name() -> _DenialSnapshot:
    from agent_os.integrations import langchain_adapter as adapter

    kernel = adapter.LangChainKernel(policy=GovernancePolicy(blocked_patterns=["delete"]))
    try:
        kernel._check_tool_policy("delete_records", (), {}, None)
    except adapter.PolicyViolationError as exc:
        return _from_exception(exc)
    raise AssertionError("expected LangChain policy violation")


def _openai_agents_allow_list() -> _DenialSnapshot:
    from agent_os.integrations.openai_agents_sdk import GovernancePolicy as OaiPolicy
    from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel

    kernel = OpenAIAgentsKernel(policy=OaiPolicy(allowed_tools=["safe_tool"]))
    allowed, reason = kernel._check_tool_allowed("danger_tool")
    assert allowed is False
    return _from_tool_result(reason)


def _openai_agents_blocked_pattern() -> _DenialSnapshot:
    from agent_os.integrations.openai_agents_sdk import GovernancePolicy as OaiPolicy
    from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel

    kernel = OpenAIAgentsKernel(policy=OaiPolicy(blocked_patterns=["secret_code"]))
    allowed, reason = kernel._check_content("contains secret_code")
    assert allowed is False
    return _from_tool_result(reason)


def _google_adk_allow_list() -> _DenialSnapshot:
    from agent_os.integrations.google_adk_adapter import GoogleADKKernel

    kernel = GoogleADKKernel(allowed_tools=["safe_tool"])
    allowed, reason = kernel._check_tool_allowed("danger_tool")
    assert allowed is False
    return _from_tool_result(reason)


def _google_adk_blocked_pattern() -> _DenialSnapshot:
    from agent_os.integrations.google_adk_adapter import GoogleADKKernel

    kernel = GoogleADKKernel(blocked_patterns=["secret_code"])
    allowed, reason = kernel._check_content("contains secret_code")
    assert allowed is False
    return _from_tool_result(reason)


def _smolagents_allow_list() -> _DenialSnapshot:
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel

    kernel = SmolagentsKernel(allowed_tools=["safe_tool"])
    allowed, reason = kernel._check_tool_allowed("danger_tool")
    assert allowed is False
    return _from_tool_result(reason)


def _smolagents_blocked_pattern() -> _DenialSnapshot:
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel

    kernel = SmolagentsKernel(blocked_patterns=["secret_code"])
    allowed, reason = kernel._check_content("contains secret_code")
    assert allowed is False
    return _from_tool_result(reason)


def _a2a_blocked_pattern() -> _DenialSnapshot:
    from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter

    adapter = A2AGovernanceAdapter(blocked_patterns=["secret_code"])
    allowed, reason = adapter._check_content(["contains secret_code"])
    assert allowed is False
    return _from_tool_result(reason)


def _a2a_allowed_skill() -> _DenialSnapshot:
    from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter

    adapter = A2AGovernanceAdapter(allowed_skills=["safe_skill"])
    evaluation = adapter.evaluate_task({"skill_id": "danger_skill", "messages": []})
    assert evaluation.allowed is False
    return _from_tool_result(evaluation.reason)


def _guardrails_regex_validator() -> _DenialSnapshot:
    from agent_os.integrations.guardrails_adapter import RegexValidator

    outcome = RegexValidator([r"\b\d{3}-\d{2}-\d{4}\b"]).validate("customer ssn 123-45-6789")
    assert outcome.passed is False
    return _from_legacy_reason(outcome.error_message or "")


def _pydantic_ai_human_approval() -> _DenialSnapshot:
    from agent_os.integrations.pydantic_ai_adapter import HumanApprovalRequired

    try:
        raise HumanApprovalRequired("delete_records", {"id": "123"})
    except PolicyViolationError as exc:
        return _from_exception(exc)


def _trust_root_allowed_tool() -> _DenialSnapshot:
    from agent_os.trust_root import TrustRoot

    decision = TrustRoot([GovernancePolicy(allowed_tools=["safe_tool"])]).validate_action(
        {"tool": "danger_tool", "arguments": {}}
    )
    assert decision.allowed is False
    return _from_tool_result(decision.reason)


def _trust_root_blocked_pattern() -> _DenialSnapshot:
    from agent_os.trust_root import TrustRoot

    decision = TrustRoot([GovernancePolicy(blocked_patterns=[r"\b\d{3}-\d{2}-\d{4}\b"])]).validate_action(
        {"tool": "lookup", "arguments": {"value": "123-45-6789"}}
    )
    assert decision.allowed is False
    return _from_tool_result(decision.reason)


def _xfail(case: _LeakCase) -> Any:
    return pytest.param(case, marks=pytest.mark.xfail(reason=case.xfail_reason, strict=True), id=case.name)


def _skip(name: str, reason: str) -> Any:
    case = _LeakCase(name, lambda: _DenialSnapshot("", ""), (), "", reason)
    return pytest.param(case, marks=pytest.mark.skip(reason=reason), id=name)


LEAK_CASES = [
    _xfail(
        _LeakCase(
            "base-policy-interceptor-allow-list",
            _policy_interceptor_allowed_tool,
            ("safe_tool", "danger_tool"),
            "safe_tool",
            "Pending PR (eᵢ) for base PolicyInterceptor",
        )
    ),
    _xfail(
        _LeakCase(
            "base-policy-interceptor-blocked-pattern",
            _policy_interceptor_blocked_pattern,
            (r"\b", r"\d", "{3}", "123-45-6789"),
            r"\d{3}",
            "Pending PR (eᵢ) for base PolicyInterceptor",
        )
    ),
    _xfail(
        _LeakCase(
            "base-policy-interceptor-max-tool-calls",
            _policy_interceptor_max_tool_calls,
            ("3",),
            "3",
            "Pending PR (eᵢ) for base PolicyInterceptor",
        )
    ),
    _xfail(
        _LeakCase(
            "base-pre-execute-max-tool-calls",
            _base_pre_execute_max_tool_calls,
            ("5",),
            "5",
            "Pending PR (eᵢ) for base pre_execute conversion",
        )
    ),
    _xfail(
        _LeakCase(
            "base-pre-execute-timeout",
            _base_pre_execute_timeout,
            ("1s", "1"),
            "1",
            "Pending PR (eᵢ) for base pre_execute conversion",
        )
    ),
    _xfail(
        _LeakCase(
            "base-pre-execute-blocked-pattern",
            _base_pre_execute_blocked_pattern,
            (r"\b", r"\d", "{3}", "123-45-6789"),
            r"\d{3}",
            "Pending PR (eᵢ) for base pre_execute conversion",
        )
    ),
    _xfail(
        _LeakCase(
            "bridge-max-tokens",
            lambda: _bridge_message("max_tokens", GovernancePolicy(max_tokens=4096)),
            ("4096",),
            "4096",
            "Pending PR (eᵢ) for policy bridge",
        )
    ),
    _xfail(
        _LeakCase(
            "bridge-max-tool-calls",
            lambda: _bridge_message("max_tool_calls", GovernancePolicy(max_tool_calls=7)),
            ("7",),
            "7",
            "Pending PR (eᵢ) for policy bridge",
        )
    ),
    _xfail(
        _LeakCase(
            "bridge-blocked-pattern",
            lambda: _bridge_message("blocked_pattern_0", GovernancePolicy(blocked_patterns=["secret_code"])),
            ("secret_code",),
            "secret_code",
            "Pending PR (eᵢ) for policy bridge",
        )
    ),
    _xfail(
        _LeakCase(
            "bridge-confidence-threshold",
            lambda: _bridge_message("confidence_threshold", GovernancePolicy(confidence_threshold=0.82)),
            ("0.82",),
            "0.82",
            "Pending PR (eᵢ) for policy bridge",
        )
    ),
    _xfail(
        _LeakCase(
            "langchain-allow-list",
            _langchain_allow_list,
            ("safe_tool", "danger_tool"),
            "safe_tool",
            "Pending PR (d) for langchain",
        )
    ),
    _xfail(
        _LeakCase(
            "langchain-blocked-pattern-args",
            _langchain_blocked_pattern_args,
            (r"\b", r"\d", "{3}", "123-45-6789"),
            r"\d{3}",
            "Pending PR (d) for langchain",
        )
    ),
    _xfail(
        _LeakCase(
            "langchain-blocked-pattern-tool-name",
            _langchain_blocked_pattern_tool_name,
            ("delete", "delete_records"),
            "delete",
            "Pending PR (d) for langchain",
        )
    ),
    _xfail(
        _LeakCase(
            "openai-agents-allow-list",
            _openai_agents_allow_list,
            ("danger_tool",),
            "danger_tool",
            "Pending PR (eᵢ) for openai_agents_sdk",
        )
    ),
    _xfail(
        _LeakCase(
            "openai-agents-blocked-pattern",
            _openai_agents_blocked_pattern,
            ("secret_code",),
            "secret_code",
            "Pending PR (eᵢ) for openai_agents_sdk",
        )
    ),
    _xfail(
        _LeakCase(
            "google-adk-allow-list",
            _google_adk_allow_list,
            ("danger_tool",),
            "danger_tool",
            "Pending PR (eᵢ) for google_adk_adapter",
        )
    ),
    _xfail(
        _LeakCase(
            "google-adk-blocked-pattern",
            _google_adk_blocked_pattern,
            ("secret_code",),
            "secret_code",
            "Pending PR (eᵢ) for google_adk_adapter",
        )
    ),
    _xfail(
        _LeakCase(
            "smolagents-allow-list",
            _smolagents_allow_list,
            ("danger_tool",),
            "danger_tool",
            "Pending PR (eᵢ) for smolagents_adapter",
        )
    ),
    _xfail(
        _LeakCase(
            "smolagents-blocked-pattern",
            _smolagents_blocked_pattern,
            ("secret_code",),
            "secret_code",
            "Pending PR (eᵢ) for smolagents_adapter",
        )
    ),
    _xfail(
        _LeakCase(
            "a2a-blocked-pattern",
            _a2a_blocked_pattern,
            ("secret_code",),
            "secret_code",
            "Pending PR (eᵢ) for a2a_adapter",
        )
    ),
    _xfail(
        _LeakCase(
            "a2a-allowed-skill",
            _a2a_allowed_skill,
            ("danger_skill",),
            "danger_skill",
            "Pending PR (eᵢ) for a2a_adapter",
        )
    ),
    _xfail(
        _LeakCase(
            "guardrails-regex-validator",
            _guardrails_regex_validator,
            (r"\b", r"\d", "{3}", "123-45-6789"),
            r"\d{3}",
            "Pending PR (eᵢ) for guardrails_adapter",
        )
    ),
    _xfail(
        _LeakCase(
            "pydantic-ai-human-approval",
            _pydantic_ai_human_approval,
            ("delete_records",),
            "delete_records",
            "Pending PR (eᵢ) for pydantic_ai_adapter",
        )
    ),
    _xfail(
        _LeakCase(
            "trust-root-allow-list",
            _trust_root_allowed_tool,
            ("safe_tool", "danger_tool"),
            "safe_tool",
            "Pending PR (eᵢ) for trust_root",
        )
    ),
    _xfail(
        _LeakCase(
            "trust-root-blocked-pattern",
            _trust_root_blocked_pattern,
            (r"\b", r"\d", "{3}", "123-45-6789"),
            r"\d{3}",
            "Pending PR (eᵢ) for trust_root",
        )
    ),
    _skip("openai-adapter-human-approval", "requires PR (eᵢ) refactor to inject OpenAI client seam"),
    _skip("anthropic-adapter-human-approval", "requires PR (eᵢ) refactor to inject Anthropic response seam"),
    _skip("gemini-adapter-human-approval", "requires PR (eᵢ) refactor to inject Gemini response seam"),
    _skip("mistral-adapter-tool-policy", "requires PR (eᵢ) refactor to inject Mistral response seam"),
    _skip("semantic-kernel-memory-save", "requires PR (eᵢ) refactor to inject async Semantic Kernel memory seam"),
    _skip("crewai-adapter-memory-and-task", "requires PR (eᵢ) refactor to inject CrewAI task/memory seams"),
    _skip("autogen-adapter-function-hook", "requires PR (eᵢ) refactor to inject AutoGen function-call seam"),
    _skip("finance-soc2-example", "example denial uses app-local ToolCallResult; convert in PR (eᵢ) before asserting exception details"),
]


@pytest.mark.parametrize("case", LEAK_CASES)
def test_adapter_denial_string_does_not_leak_policy_internals(case: _LeakCase) -> None:
    """Denial public text stays safe while audit details retain raw evidence."""
    snapshot = case.trigger()

    for forbidden in case.forbidden_fragments:
        assert forbidden not in snapshot.public_message
    assert case.audit_fragment in snapshot.audit_text
