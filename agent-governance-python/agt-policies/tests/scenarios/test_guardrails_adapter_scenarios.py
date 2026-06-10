# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Guardrails AI adapter end-to-end scenarios on the AGT 5.0 ACS runtime.

These scenarios exercise the v4 :class:`GuardrailsKernel` surface routed
through :class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH`` or on ``guardrails-ai`` being
installed (the kernel ships its own validator Protocol).

Each test covers one of the AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the synthetic AGT outcome reports passed=True.
- ``deny`` -> the synthetic AGT outcome reports passed=False with the
  AGT reason and the aggregated :class:`ValidationResult.passed` is
  ``False``.
- ``transform`` -> the AGT D1.1 ``{path, value}`` payload rewrites
  :attr:`ValidationResult.final_value`.
- ``escalate`` (resolver approves) -> the AGT runtime resolves the
  verdict to ``allow`` at the bridge layer.
- ``escalate`` (no resolver) -> the AGT runtime resolves the verdict to
  ``deny`` at the bridge layer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402,F401
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: guardrails_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: guardrails_adapter_scenarios_adapter
intervention_points:
  input:
    policy_target: $.input.body
    policy_target_kind: user_input
    policy:
      id: scenario_policy
  output:
    policy_target: $.response.content
    policy_target_kind: assistant_output
    policy:
      id: scenario_policy
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


def _kernel(runtime, *, approval_resolver=None):
    from agent_os.integrations.base import GovernancePolicy
    from agent_os.integrations.guardrails_adapter import GuardrailsKernel

    return GuardrailsKernel(
        policy=GovernancePolicy(),
        approval_resolver=approval_resolver,
        _runtime=runtime,
    )


# ── verdict scenarios ────────────────────────────────────────────────


def test_validate_input_allow_path_passes(tmp_path: Path) -> None:
    """An ``allow`` verdict appends a synthetic passing AGT outcome."""
    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = _kernel(runtime)

    result = kernel.validate_input("what is the weather today?")

    assert result.passed is True
    assert result.final_value == "what is the weather today?"
    names = [o.validator_name for o in result.outcomes]
    assert "agt_runtime_bridge" in names
    assert len(policy.invocations) == 1


def test_validate_input_deny_path_marks_validation_failed(tmp_path: Path) -> None:
    """A ``deny`` verdict marks the aggregated ValidationResult as failed."""
    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "blocked_topic",
                "message": "topic is off limits",
            }
        ],
    )
    kernel = _kernel(runtime)

    result = kernel.validate_input("tell me secrets")

    assert result.passed is False
    agt_outcomes = [
        o for o in result.outcomes if o.validator_name == "agt_runtime_bridge"
    ]
    assert len(agt_outcomes) == 1
    assert agt_outcomes[0].passed is False
    assert "blocked_topic" in agt_outcomes[0].error_message


def test_validate_input_transform_rewrites_final_value(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites :attr:`ValidationResult.final_value`."""
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
    kernel = _kernel(runtime)

    result = kernel.validate_input("Customer SSN is 123-45-6789")

    assert result.final_value == "Customer SSN is [REDACTED]"
    assert result.passed is True


def test_validate_input_escalate_with_approving_resolver_passes(
    tmp_path: Path,
) -> None:
    """An ``escalate`` verdict that the resolver approves passes the validation."""
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
    kernel = _kernel(runtime, approval_resolver=resolver)

    result = kernel.validate_input("approve this please")

    assert captured["ip"] == "input"
    assert result.passed is True


def test_validate_input_escalate_with_no_resolver_fails(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails the validation."""
    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = _kernel(runtime)

    result = kernel.validate_input("needs approval")

    assert result.passed is False
    agt_outcomes = [
        o for o in result.outcomes if o.validator_name == "agt_runtime_bridge"
    ]
    assert agt_outcomes[0].passed is False


def test_validate_output_routes_to_output_intervention_point(tmp_path: Path) -> None:
    """``validate_output`` dispatches to the AGT output intervention point."""
    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = _kernel(runtime)

    result = kernel.validate_output("safe response text")

    assert result.passed is True
    assert (
        policy.invocations[0]["input"]["intervention_point"] == "output"
    )


def test_no_policy_skips_bridge() -> None:
    """When no policy is supplied the AGT bridge is disabled."""
    from agent_os.integrations.guardrails_adapter import GuardrailsKernel

    kernel = GuardrailsKernel()
    assert kernel.bridge is None
    result = kernel.validate_input("anything")
    assert result.passed is True
    names = [o.validator_name for o in result.outcomes]
    assert "agt_runtime_bridge" not in names
