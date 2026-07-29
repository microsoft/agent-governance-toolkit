# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""An unconfigured intervention point is not a denial.

The engine answers a request naming a point the manifest does not configure
with ``runtime_error:intervention_point_unknown``. That is the right answer to
a request naming an unknown point, but an adapter does not name points on the
host's behalf: it evaluates output after every call whether or not the
manifest asked for output governance. Reading the error as a denial blocked
every response under any manifest binding only ``input`` or ``pre_tool_call``.

The permit lives on ``NativeAdapterResult`` and is switched on only by
``NativeAdapterRuntime.evaluate_output``, so every adapter gets it rather than
just the ones routing through ``BaseIntegration.post_execute``. Roughly a
dozen adapters call ``evaluate_output`` directly.

The risk in relaxing this is that output enforcement quietly stops working, so
these pin every direction: an unconfigured output point permits, an
unconfigured input or tool-call point still denies, and a configured output
point still denies, transforms, and records completion the way it did.
"""

from __future__ import annotations

import types

import pytest

from agent_os.integrations._native_adapter_runtime import (
    POINT_NOT_CONFIGURED,
    NativeAdapterResult,
    NativeAdapterRuntime,
)
from agent_os.integrations.base import BaseIntegration

STATE = types.SimpleNamespace(agent_id="a", session_id="s")


class _Evaluation:
    """Stand-in for the native ``PolicyEvaluation`` a session returns.

    Deliberately *not* a stand-in for ``NativeAdapterResult``: the permit
    lives on that class, so faking it would test the fake, not the fix.
    """

    def __init__(self, allowed: bool, reason_code: str | None = None, transform=None):
        self._allowed = allowed
        self.reason_code = reason_code
        self.verdict = "allow" if allowed else "deny"
        self.transform = transform
        self.input_identity = None
        self.enforced_identity = None

    def is_allowed(self) -> bool:
        return self._allowed


def _output_result(allowed: bool, reason_code: str | None = None, transform=None):
    """Build the real result object ``evaluate_output`` returns."""
    return NativeAdapterResult(
        _Evaluation(allowed, reason_code, transform), permit_if_unconfigured=True
    )


class _Runtime:
    def __init__(self, result) -> None:
        self._result = result
        self.calls = 0

    def evaluate_output(self, state, *, content):
        self.calls += 1
        return self._result


def _adapter(result):
    """Build a bare adapter bound to a scripted runtime."""
    adapter = object.__new__(BaseIntegration)
    adapter._adapter_runtime = _Runtime(result)
    adapter.completed = []
    adapter.record_host_completion = lambda state, **kw: adapter.completed.append(kw)
    return adapter


class TestTheCarveOutIsScopedToOutput:
    """The permit is a property of the intervention point, not the caller."""

    def test_output_permits_an_unconfigured_point(self):
        result = _output_result(allowed=False, reason_code=POINT_NOT_CONFIGURED)

        assert result.point_not_configured is True
        assert result.allowed is True

    def test_input_still_denies_an_unconfigured_point(self):
        """pre_execute must stay fail-closed; the whole fix leans on it.

        A manifest omitting ``input`` or ``pre_tool_call`` omits governance of
        an action about to happen, which has to be loud.
        """
        result = NativeAdapterResult(
            _Evaluation(False, POINT_NOT_CONFIGURED)
        )

        assert result.point_not_configured is True
        assert result.allowed is False

    def test_a_real_denial_is_never_permitted(self):
        result = _output_result(
            allowed=False, reason_code="policy:blocked_pattern_output"
        )

        assert result.point_not_configured is False
        assert result.allowed is False

    @pytest.mark.parametrize(
        "reason",
        ["runtime_error:manifest_invalid", "runtime_error:path_missing"],
    )
    def test_other_runtime_errors_still_deny(self, reason):
        """Only the unconfigured-point reason is relaxed."""
        result = _output_result(allowed=False, reason_code=reason)

        assert result.point_not_configured is False
        assert result.allowed is False


class TestEveryAdapterGetsIt:
    """Haroon's finding: ~11 adapters bypass ``post_execute`` entirely.

    langchain, semantic_kernel, smolagents, pydantic_ai, agentshield,
    google_adk, guardrails, crewai, llamaindex, openai and openai_agents_sdk
    all call ``evaluate_output`` directly. They reach the same runtime method,
    so the permit is pinned there rather than at each call site.
    """

    @staticmethod
    def _runtime(evaluation):
        runtime = object.__new__(NativeAdapterRuntime)
        runtime._sessions = {}
        runtime._unconfigured_logged = set()
        runtime._session_for = lambda ctx: types.SimpleNamespace(
            evaluate_output=lambda **kw: evaluation,
            evaluate_post_tool_call=lambda **kw: evaluation,
            evaluate_post_model_call=lambda **kw: evaluation,
            evaluate_input=lambda **kw: evaluation,
            evaluate_pre_tool_call=lambda **kw: evaluation,
        )
        return runtime

    def test_direct_evaluate_output_permits(self):
        runtime = self._runtime(_Evaluation(False, POINT_NOT_CONFIGURED))

        result = runtime.evaluate_output(STATE, content="an answer")

        assert result.allowed is True
        assert result.point_not_configured is True

    def test_direct_evaluate_output_still_denies_a_real_verdict(self):
        runtime = self._runtime(_Evaluation(False, "policy:blocked_pattern_output"))

        result = runtime.evaluate_output(STATE, content="a leaked secret")

        assert result.allowed is False

    def test_the_skip_is_announced_once(self, caplog):
        """A silent skip hides that output enforcement is off."""
        runtime = self._runtime(_Evaluation(False, POINT_NOT_CONFIGURED))

        with caplog.at_level("WARNING"):
            runtime.evaluate_output(STATE, content="a")
            runtime.evaluate_output(STATE, content="b")

        warned = [r for r in caplog.records if "no 'output' intervention" in r.message]
        assert len(warned) == 1, "warn once per runtime, not once per call"


class TestPostExecuteBookkeeping:
    """``post_execute`` reads ``allowed``, so it inherits the permit."""

    def test_unconfigured_point_records_completion(self):
        adapter = _adapter(
            _output_result(allowed=False, reason_code=POINT_NOT_CONFIGURED)
        )

        allowed, reason = adapter.post_execute(STATE, "the model's answer")

        assert (allowed, reason) == (True, None)
        # Completion still has to be recorded, or budgets drift on every
        # manifest that does not bind output.
        assert adapter.completed == [{"output_data": "the model's answer"}]

    def test_denial_blocks_and_records_nothing(self):
        adapter = _adapter(
            _output_result(allowed=False, reason_code="policy:blocked_pattern_output")
        )

        allowed, reason = adapter.post_execute(STATE, "leaked secret")

        assert allowed is False
        assert reason == "blocked_pattern_output"
        assert adapter.completed == []

    def test_transform_is_still_refused(self):
        """A transform carries a replacement this contract cannot return."""
        adapter = _adapter(_output_result(allowed=True, transform=object()))

        allowed, reason = adapter.post_execute(STATE, "card 4111111111111111")

        assert allowed is False
        assert reason == "transform_not_applicable"

    def test_allow_passes(self):
        adapter = _adapter(_output_result(allowed=True))

        allowed, reason = adapter.post_execute(STATE, "fine")

        assert (allowed, reason) == (True, None)
        assert adapter.completed == [{"output_data": "fine"}]


class TestEveryPostHocPointPermits:
    """The line is pre-point versus post-hoc point, not output versus rest.

    Thirteen scenario manifests bind ``pre_tool_call`` and none bind
    ``post_tool_call``, so ``openai_agents_sdk`` raised on the configuration
    every scenario uses. Nothing caught it because that adapter has no
    scenario test.
    """

    def _runtime(self):
        return TestEveryAdapterGetsIt._runtime(
            _Evaluation(False, POINT_NOT_CONFIGURED)
        )

    def test_post_tool_call_permits(self):
        result = self._runtime().evaluate_post_tool_call(
            STATE, tool_name="t", args={}, result="r"
        )

        assert result.allowed is True

    def test_post_model_call_permits(self):
        result = self._runtime().evaluate_post_model_call(
            STATE, model_name="m", response={}
        )

        assert result.allowed is True

    def test_pre_points_still_deny(self):
        """The action has not happened yet, so refusing still protects it."""
        runtime = self._runtime()

        assert runtime.evaluate_input(STATE, body="x").allowed is False
        assert (
            runtime.evaluate_pre_tool_call(
                STATE, tool_name="t", args={}
            ).allowed
            is False
        )

    def test_each_point_warns_separately(self, caplog):
        runtime = self._runtime()
        with caplog.at_level("WARNING"):
            runtime.evaluate_output(STATE, content="a")
            runtime.evaluate_output(STATE, content="b")
            runtime.evaluate_post_tool_call(
                STATE, tool_name="t", args={}, result="r"
            )

        points = {
            p
            for p in ("output", "post_tool_call")
            for r in caplog.records
            if f"no '{p}' intervention" in r.message
        }
        assert points == {"output", "post_tool_call"}
        assert len(caplog.records) == 2, "once per point, not once per call"
