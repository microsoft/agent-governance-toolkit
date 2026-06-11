# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Bedrock adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`BedrockKernel` and
:class:`GovernedBedrockClient` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The boto3 client is replaced with a ``MagicMock`` and the AGT runtime
is wired with a scripted policy dispatcher so the suite does not
depend on boto3 or OPA being installed.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the Bedrock invoke_agent / action-group event passes.
- ``deny`` -> the adapter raises
  :class:`PolicyViolationError.from_check_result(...)`.
- ``transform`` -> the adapter rewrites the outbound ``inputText`` (or
  action-group parameters) with the AGT D1.1 ``{path, value}`` payload
  before forwarding.
- ``escalate`` (resolver approves) -> the call passes after the
  resolver returns an allow.
- ``escalate`` (no resolver) -> the adapter raises
  :class:`PolicyViolationError`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

from agt.policies import EvaluationResult  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: bedrock_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: bedrock_adapter_scenarios_adapter
intervention_points:
  input:
    policy_target: $.input.body
    policy_target_kind: user_input
    policy:
      id: scenario_policy
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: scenario_policy
tools:
  query_database:
    clearance: public
"""


class _ScriptedPolicy:
    """Tiny ACS PolicyDispatcher that returns a scripted verdict per call."""

    def __init__(self, verdicts: list[dict[str, Any]]):
        self._verdicts = list(verdicts)
        self.invocations: list[dict[str, Any]] = []

    def evaluate(self, invocation):  # type: ignore[no-untyped-def]
        self.invocations.append(dict(invocation))
        if not self._verdicts:
            raise AssertionError(
                "ScriptedPolicy ran out of verdicts; test wired too few."
            )
        return self._verdicts.pop(0)


def _write_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(_MANIFEST, encoding="utf-8")
    return path


def _build_runtime(
    tmp_path: Path,
    verdicts: list[dict[str, Any]],
    *,
    approval_resolver=None,
) -> tuple[AgtRuntime, _ScriptedPolicy]:
    policy = _ScriptedPolicy(verdicts)
    runtime = AgtRuntime(
        _write_manifest(tmp_path),
        policy_dispatcher=policy,
        approval_resolver=approval_resolver,
    )
    return runtime, policy


def _mock_client(events: list[dict[str, Any]] | None = None) -> MagicMock:
    """Return a mock boto3 bedrock-agent-runtime client."""
    client = MagicMock()
    client.invoke_agent.return_value = {
        "ResponseMetadata": {"RequestId": "req-test-001"},
        "completion": iter(events or []),
    }
    return client


def _action_event(tool_name: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
    """Construct a Bedrock returnControl action-group event."""
    return {
        "returnControl": {
            "invocationInputs": [
                {
                    "actionGroupInvocationInput": {
                        "actionGroupName": tool_name,
                        "function": tool_name,
                        "parameters": parameters or {},
                    }
                }
            ]
        }
    }


# Pretend boto3 is installed for the wrap() call.
import agent_os.integrations.bedrock_adapter as _bmod  # noqa: E402

_bmod._HAS_BOTO3 = True


# ── verdict scenarios on invoke_agent input ─────────────────────────


def test_invoke_agent_allow_path_passes(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the Bedrock invoke_agent call through."""
    from agent_os.integrations.base import GovernancePolicy
    from agent_os.integrations.bedrock_adapter import BedrockKernel

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = BedrockKernel(policy=GovernancePolicy(), _runtime=runtime)
    client = _mock_client()
    governed = kernel.wrap(client)

    response = governed.invoke_agent(
        agentId="A",
        agentAliasId="L",
        sessionId="s",
        inputText="Summarize this quarter",
    )

    assert "completion" in response
    assert len(policy.invocations) == 1
    sent = client.invoke_agent.call_args.kwargs
    assert sent["inputText"] == "Summarize this quarter"


def test_invoke_agent_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`PolicyViolationError`."""
    from agent_os.integrations.base import (
        GovernancePolicy,
        PolicyViolationError,
    )
    from agent_os.integrations.bedrock_adapter import BedrockKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "blocked_user_input",
                "message": "input contains forbidden text",
            }
        ],
    )
    kernel = BedrockKernel(policy=GovernancePolicy(), _runtime=runtime)
    client = _mock_client()
    governed = kernel.wrap(client)

    with pytest.raises(PolicyViolationError) as excinfo:
        governed.invoke_agent(
            agentId="A",
            agentAliasId="L",
            sessionId="s",
            inputText="share the password",
        )

    assert excinfo.value.check_result.reason == "blocked_user_input"
    client.invoke_agent.assert_not_called()


def test_invoke_agent_transform_path_rewrites_input_text(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the outbound ``inputText``."""
    from agent_os.integrations.base import GovernancePolicy
    from agent_os.integrations.bedrock_adapter import BedrockKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "pii_redaction",
                "transform": {
                    "path": "$policy_target",
                    "value": "Customer SSN is [REDACTED]",
                },
            }
        ],
    )
    kernel = BedrockKernel(policy=GovernancePolicy(), _runtime=runtime)
    client = _mock_client()
    governed = kernel.wrap(client)

    governed.invoke_agent(
        agentId="A",
        agentAliasId="L",
        sessionId="s",
        inputText="please summarise the customer record",
    )

    client.invoke_agent.assert_called_once()
    sent = client.invoke_agent.call_args.kwargs
    assert sent["inputText"] == "Customer SSN is [REDACTED]"


def test_invoke_agent_escalate_with_approving_resolver_passes(
    tmp_path: Path,
) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the call."""
    from agent_os.integrations.base import GovernancePolicy
    from agent_os.integrations.bedrock_adapter import BedrockKernel

    captured: dict[str, Any] = {}

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        captured["ip"] = ip
        captured["enforced_identity"] = result.enforced_identity
        return ApprovalDecision.allow(result.enforced_identity)  # type: ignore[arg-type]

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=resolver,
    )
    kernel = BedrockKernel(
        policy=GovernancePolicy(),
        _runtime=runtime,
        approval_resolver=resolver,
    )
    client = _mock_client()
    governed = kernel.wrap(client)

    governed.invoke_agent(
        agentId="A",
        agentAliasId="L",
        sessionId="s",
        inputText="approve this please",
    )

    assert captured["ip"] == "input"
    assert captured["enforced_identity"] is not None
    client.invoke_agent.assert_called_once()


def test_invoke_agent_escalate_with_no_resolver_raises(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.base import (
        GovernancePolicy,
        PolicyViolationError,
    )
    from agent_os.integrations.bedrock_adapter import BedrockKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = BedrockKernel(policy=GovernancePolicy(), _runtime=runtime)
    client = _mock_client()
    governed = kernel.wrap(client)

    with pytest.raises(PolicyViolationError):
        governed.invoke_agent(
            agentId="A",
            agentAliasId="L",
            sessionId="s",
            inputText="needs approval",
        )

    client.invoke_agent.assert_not_called()


# ── verdict scenarios on action-group events (pre_tool_call) ─────────


def test_event_stream_transform_rewrites_action_group_parameters(
    tmp_path: Path,
) -> None:
    """A ``transform`` verdict rewrites the action-group parameters."""
    from agent_os.integrations.base import GovernancePolicy
    from agent_os.integrations.bedrock_adapter import BedrockKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {"decision": "allow"},  # input
            {
                "decision": "transform",
                "reason": "args_sanitized",
                "transform": {
                    "path": "$policy_target",
                    "value": {"q": "[SANITIZED]"},
                },
            },  # pre_tool_call
        ],
    )
    kernel = BedrockKernel(policy=GovernancePolicy(), _runtime=runtime)
    event = _action_event("query_database", {"q": "drop table users"})
    client = _mock_client(events=[event])
    governed = kernel.wrap(client)

    response = governed.invoke_agent(
        agentId="A", agentAliasId="L", sessionId="s",
        inputText="Run a query",
    )

    list(response["completion"])
    invocation_input = event["returnControl"]["invocationInputs"][0]
    assert invocation_input["actionGroupInvocationInput"]["parameters"] == {
        "q": "[SANITIZED]"
    }


def test_enable_agt_pii_routing_lets_transform_run_before_host_pii_check(
    tmp_path: Path,
) -> None:
    """AGT-DELTA D1.1 Concern 2 regression. With
    ``enable_agt_pii_routing=True`` the Bedrock kernel MUST run the
    AGT input intervention point BEFORE the host-side ``_check_input``
    PII scan, so an AGT manifest can redact PII before the legacy
    pattern scan rejects it.
    """
    from agent_os.integrations.base import GovernancePolicy
    from agent_os.integrations.bedrock_adapter import BedrockKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "pii_redaction",
                "transform": {
                    "path": "$policy_target",
                    "value": "Customer record [REDACTED]",
                },
            }
        ],
    )
    kernel = BedrockKernel(
        policy=GovernancePolicy(),
        _runtime=runtime,
        enable_agt_pii_routing=True,
    )
    client = _mock_client()
    governed = kernel.wrap(client)

    # The raw inputText contains a SSN-shaped pattern the host
    # ``_check_input`` would refuse if it ran first.
    governed.invoke_agent(
        agentId="A",
        agentAliasId="L",
        sessionId="s",
        inputText="Customer SSN 123-45-6789 trailing",
    )

    client.invoke_agent.assert_called_once()
    sent = client.invoke_agent.call_args.kwargs
    assert sent["inputText"] == "Customer record [REDACTED]"


def test_enable_agt_pii_routing_off_preserves_v4_short_circuit(
    tmp_path: Path,
) -> None:
    """When the flag is off the host PII scan still fires first and
    raises before the AGT bridge runs.
    """
    from agent_os.integrations.base import (
        GovernancePolicy,
        PolicyViolationError,
    )
    from agent_os.integrations.bedrock_adapter import BedrockKernel

    runtime, policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "pii_redaction",
                "transform": {
                    "path": "$policy_target",
                    "value": "Customer record [REDACTED]",
                },
            }
        ],
    )
    kernel = BedrockKernel(
        policy=GovernancePolicy(),
        _runtime=runtime,
    )
    client = _mock_client()
    governed = kernel.wrap(client)

    with pytest.raises(PolicyViolationError):
        governed.invoke_agent(
            agentId="A",
            agentAliasId="L",
            sessionId="s",
            inputText="Customer SSN 123-45-6789 trailing",
        )

    # The AGT bridge MUST NOT have been consulted in the v4 default
    # path so the scripted dispatcher's transform remains queued.
    assert policy.invocations == []
    client.invoke_agent.assert_not_called()
