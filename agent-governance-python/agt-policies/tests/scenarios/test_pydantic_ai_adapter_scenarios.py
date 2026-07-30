# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""PydanticAI adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the native :class:`PydanticAIKernel` and
:class:`GovernanceCapability` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._native_adapter_runtime.NativeAdapterRuntime`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
expose through its native surface:

- ``allow`` -> the PydanticAI tool / prompt is forwarded verbatim.
- ``deny`` -> the adapter raises
  :class:`PolicyViolationError` with its native evaluation attached.
- ``transform`` -> the adapter rewrites the outbound tool arguments or
  prompt with the AGT D1.1 ``{path, value}`` payload before invoking
  the wrapped agent.
- ``escalate`` (resolver approves) -> the adapter forwards the call.
- ``escalate`` (no resolver) -> the adapter raises a deny.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
import pytest
pytest.importorskip('agent_control_specification')
pytest.importorskip('agent_os')
from agt.policies import PolicyEvaluation
from agt.policies.runtime import AgtRuntime, ApprovalDecision
_MANIFEST = 'agent_control_specification_version: 0.3.0-alpha-agt\nmetadata:\n  name: pydantic_ai_adapter_scenarios\nextends: []\npolicies:\n  scenario_policy:\n    type: custom\n    adapter: pydantic_ai_adapter_scenarios_adapter\nintervention_points:\n  input:\n    policy_target: $.input.body\n    policy_target_kind: user_input\n    policy:\n      id: scenario_policy\n  pre_tool_call:\n    policy_target: $.tool_call.args\n    policy_target_kind: tool_args\n    tool_name_from: $.tool_call.name\n    policy:\n      id: scenario_policy\ntools:\n  search:\n    clearance: public\n'

class _ScriptedPolicy:
    """Tiny ACS PolicyDispatcher that returns a scripted verdict per call."""

    def __init__(self, verdicts: list[dict[str, Any]]):
        self._verdicts = list(verdicts)
        self.invocations: list[dict[str, Any]] = []

    def evaluate(self, invocation):
        self.invocations.append(dict(invocation))
        if not self._verdicts:
            raise AssertionError('ScriptedPolicy ran out of verdicts; test wired too few.')
        return self._verdicts.pop(0)

def _write_manifest(tmp_path: Path) -> Path:
    path = tmp_path / 'manifest.yaml'
    path.write_text(_MANIFEST, encoding='utf-8')
    return path

def _build_runtime(tmp_path: Path, verdicts: list[dict[str, Any]], *, approval_resolver=None) -> tuple[AgtRuntime, _ScriptedPolicy]:
    policy = _ScriptedPolicy(verdicts)
    runtime = AgtRuntime(_write_manifest(tmp_path), policy_dispatcher=policy, approval_resolver=approval_resolver)
    return (runtime, policy)

def test_before_run_allow_path_forwards_prompt(tmp_path: Path) -> None:
    """An ``allow`` verdict on input returns the original prompt unchanged."""
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel
    runtime, policy = _build_runtime(tmp_path, [{'decision': 'allow'}])
    kernel = PydanticAIKernel(runtime=runtime)
    capability = kernel.as_capability()
    result = capability.before_run('what is the weather today?')
    assert result == 'what is the weather today?'
    assert len(policy.invocations) == 1

def test_before_run_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`PolicyViolationError`."""
    from agent_os.integrations.pydantic_ai_adapter import PolicyViolationError, PydanticAIKernel
    runtime, _policy = _build_runtime(tmp_path, [{'decision': 'deny', 'reason': 'user_blocked_topic', 'message': 'topic is off limits'}])
    kernel = PydanticAIKernel(runtime=runtime)
    capability = kernel.as_capability()
    with pytest.raises(PolicyViolationError) as excinfo:
        capability.before_run('tell me about secrets')
    assert excinfo.value.evaluation_result.reason_code == 'policy:user_blocked_topic'

def test_before_run_transform_path_rewrites_prompt(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the outbound prompt."""
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel
    runtime, _policy = _build_runtime(tmp_path, [{'decision': 'transform', 'reason': 'pii_redaction', 'transform': {'path': '$policy_target', 'value': 'Customer SSN is [REDACTED]'}}])
    kernel = PydanticAIKernel(runtime=runtime)
    capability = kernel.as_capability()
    rewritten = capability.before_run('Customer SSN is 123-45-6789')
    assert rewritten == 'Customer SSN is [REDACTED]'

def test_before_run_escalate_with_approving_resolver_forwards(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the prompt."""
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel
    captured: dict[str, Any] = {}

    def resolver(ip: str, result: PolicyEvaluation) -> ApprovalDecision:
        captured['ip'] = ip
        captured['enforced_identity'] = result.enforced_identity
        return ApprovalDecision.allow(result.enforced_identity)
    runtime, _policy = _build_runtime(tmp_path, [{'decision': 'escalate', 'reason': 'human_approval_required'}], approval_resolver=resolver)
    kernel = PydanticAIKernel(runtime=runtime)
    capability = kernel.as_capability()
    result = capability.before_run('approve this please')
    assert captured['ip'] == 'input'
    assert captured['enforced_identity'] is not None
    assert result == 'approve this please'

def test_before_run_escalate_with_no_resolver_denies(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.pydantic_ai_adapter import PolicyViolationError, PydanticAIKernel
    runtime, _policy = _build_runtime(tmp_path, [{'decision': 'escalate', 'reason': 'human_approval_required'}], approval_resolver=None)
    kernel = PydanticAIKernel(runtime=runtime)
    capability = kernel.as_capability()
    with pytest.raises(PolicyViolationError):
        capability.before_run('needs approval')

def test_before_tool_execute_transform_rewrites_arguments(tmp_path: Path) -> None:
    """A ``transform`` verdict at pre_tool_call rewrites tool arguments."""
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel
    runtime, _policy = _build_runtime(tmp_path, [{'decision': 'transform', 'reason': 'query_sanitized', 'transform': {'path': '$policy_target', 'value': {'query': '[SANITIZED]'}}}])
    kernel = PydanticAIKernel(runtime=runtime)
    capability = kernel.as_capability()
    rewritten = capability.before_tool_execute('search', {'query': 'drop table users;'})
    assert rewritten == {'query': '[SANITIZED]'}
