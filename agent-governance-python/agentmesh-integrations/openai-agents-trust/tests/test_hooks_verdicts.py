# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the verdict handling in GovernanceHooks and the input guardrail.

The hooks observe a run; they cannot rewrite the payload the agent is about to
use. That makes ``transform`` the interesting verdict: it permits, so a naive
check lets the run continue with content the policy expected to be rewritten.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agent_control_specification import Decision, InterventionPointResult, Verdict

# hooks imports the openai-agents SDK at module level. CI installs it; skip
# rather than fail where it is absent or version-skewed.
pytest.importorskip("agents", reason="openai-agents SDK not installed")

from openai_agents_trust.hooks import GovernanceHooks  # noqa: E402


_DECISIONS = {
    "allow": Decision.ALLOW,
    "warn": Decision.WARN,
    "deny": Decision.DENY,
    "escalate": Decision.ESCALATE,
    "transform": Decision.TRANSFORM,
}


def _evaluation(verdict: str, **kw: Any) -> InterventionPointResult:
    return InterventionPointResult(
        verdict=Verdict(decision=_DECISIONS[verdict], **kw)
    )


class TestRequireAllowed:
    def test_allow_passes(self) -> None:
        GovernanceHooks._require_allowed(_evaluation("allow"))

    def test_warn_passes(self) -> None:
        """warn permits, and the hooks have nothing to apply, so it proceeds."""
        GovernanceHooks._require_allowed(_evaluation("warn"))

    def test_deny_raises(self) -> None:
        with pytest.raises(PermissionError):
            GovernanceHooks._require_allowed(
                _evaluation("deny", reason="blocked")
            )

    def test_escalate_raises(self) -> None:
        with pytest.raises(PermissionError):
            GovernanceHooks._require_allowed(_evaluation("escalate"))

    def test_transform_raises_rather_than_running_unredacted_content(self) -> None:
        """A transform must not proceed just because the verdict permits.

        These hooks cannot apply the replacement, so continuing would run the
        original content while the policy believed it had been rewritten.
        """
        with pytest.raises(PermissionError) as excinfo:
            GovernanceHooks._require_allowed(
                _evaluation("transform", reason="redact")
            )

        assert "transform" in str(excinfo.value)

    def test_deny_message_does_not_fall_back_to_an_empty_string(self) -> None:
        error = None
        try:
            GovernanceHooks._require_allowed(_evaluation("deny"))
        except PermissionError as exc:  # noqa: PERF203 - asserting on the raise
            error = exc

        assert error is not None
        assert str(error)


class TestGuardrailBody:
    """The input guardrail must hand HostSession.input a JSON-serializable body."""

    def test_a_list_of_input_items_stays_json_serializable(self) -> None:
        """HostSession.input takes a JsonValue, so a list passes through, but every
        non-dict item must be stringified or the native SDK cannot serialize it."""
        from openai_agents_trust import guardrails

        captured: dict[str, Any] = {}

        class _Session:
            def input(self, body: Any) -> Any:
                captured["body"] = body
                return _evaluation("allow")

        class _Config:
            audit_log = None

            def session(self, _name: str) -> Any:
                return _Session()

        guard = guardrails.governance_input_guardrail(_Config())
        agent = type("A", (), {"name": "a"})()
        guard.guardrail_function(
            None, agent, [{"role": "user", "content": "hi"}, object()]
        )

        body = captured["body"]
        assert isinstance(body, list)
        assert body[0] == {"role": "user", "content": "hi"}
        assert isinstance(body[1], str), "non-dict items must be stringified"
        json.dumps(body)


class TestGuardrailTripsOnTransform:
    def test_transform_trips_the_wire(self) -> None:
        """A guardrail cannot apply a replacement, so a transform must stop the run."""
        from openai_agents_trust import guardrails

        assert guardrails._should_trip(_evaluation("transform")) is True

    def test_permitting_verdicts_do_not_trip(self) -> None:
        from openai_agents_trust import guardrails

        assert guardrails._should_trip(_evaluation("allow")) is False
        assert guardrails._should_trip(_evaluation("warn")) is False

    def test_deny_trips(self) -> None:
        from openai_agents_trust import guardrails

        assert guardrails._should_trip(_evaluation("deny")) is True
