# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""A manifest must bind every intervention point the adapter evaluates.

The engine answers a request naming a point the manifest does not configure
with ``runtime_error:intervention_point_unknown``, and that verdict does not
permit. These pin that the adapters leave it that way.

It is tempting to read the reason as "no policy here, carry on", because an
adapter evaluates a fixed set of points and a manifest binding only ``input``
then denies on every other path. That reading is wrong. A ``post_*`` block
still prevents the result from propagating even though the guarded action
already ran, which the SDK states directly in ``AgentControlBlocked``:

    For a ``post_*`` intervention point the guarded action has already
    executed; a block prevents the result from propagating, it does not undo
    the side effect.

So permitting an unconfigured ``output`` or ``post_tool_call`` would forward
model responses and tool results that no policy was ever consulted about,
which is the exfiltration boundary this toolkit exists to hold. The remedy is
to bind the point, which is what ``agentmesh/MIGRATION_V5.md`` tells Rust
callers to do and what the scenario manifests here now do.

``point_not_configured`` exists only so a host can say *which* point is
missing rather than reporting a bare denial.
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
    """Stand-in for the native ``PolicyEvaluation`` a session returns."""

    def __init__(self, allowed: bool, reason_code: str | None = None, transform=None):
        self._allowed = allowed
        self.reason_code = reason_code
        self.verdict = "allow" if allowed else "deny"
        self.transform = transform
        self.input_identity = None
        self.enforced_identity = None

    def is_allowed(self) -> bool:
        return self._allowed


def _unconfigured() -> _Evaluation:
    return _Evaluation(False, POINT_NOT_CONFIGURED)


class _Runtime:
    def __init__(self, result) -> None:
        self._result = result

    def evaluate_output(self, state, *, content):
        return self._result


def _adapter(result):
    adapter = object.__new__(BaseIntegration)
    adapter._adapter_runtime = _Runtime(result)
    adapter.completed = []
    adapter.record_host_completion = lambda state, **kw: adapter.completed.append(kw)
    return adapter


def _runtime(evaluation):
    """A runtime whose session returns one fixed evaluation for every point."""
    runtime = object.__new__(NativeAdapterRuntime)
    runtime._sessions = {}
    runtime._session_for = lambda ctx: types.SimpleNamespace(
        evaluate_output=lambda **kw: evaluation,
        evaluate_post_tool_call=lambda **kw: evaluation,
        evaluate_post_model_call=lambda **kw: evaluation,
        evaluate_input=lambda **kw: evaluation,
        evaluate_pre_tool_call=lambda **kw: evaluation,
    )
    return runtime


class TestAnUnconfiguredPointDenies:
    """Uniformly, at every point. No point is exempt."""

    def test_result_does_not_permit(self):
        result = NativeAdapterResult(_unconfigured())

        assert result.allowed is False

    def test_it_reports_which_kind_of_denial_it_is(self):
        """So a host can name the missing point instead of a bare refusal."""
        assert NativeAdapterResult(_unconfigured()).point_not_configured is True

    def test_a_real_denial_is_not_mistaken_for_a_missing_point(self):
        result = NativeAdapterResult(
            _Evaluation(False, "policy:blocked_pattern_output")
        )

        assert result.point_not_configured is False
        assert result.allowed is False

    def test_an_allow_is_not_mistaken_for_a_missing_point(self):
        result = NativeAdapterResult(_Evaluation(True))

        assert result.point_not_configured is False
        assert result.allowed is True

    @pytest.mark.parametrize(
        "point,call",
        [
            ("output", lambda r: r.evaluate_output(STATE, content="x")),
            (
                "post_tool_call",
                lambda r: r.evaluate_post_tool_call(
                    STATE, tool_name="t", args={}, result="r"
                ),
            ),
            (
                "post_model_call",
                lambda r: r.evaluate_post_model_call(
                    STATE, model_name="m", response={}
                ),
            ),
            ("input", lambda r: r.evaluate_input(STATE, body="x")),
            (
                "pre_tool_call",
                lambda r: r.evaluate_pre_tool_call(STATE, tool_name="t", args={}),
            ),
        ],
    )
    def test_every_point_denies(self, point, call):
        """post_* included: a block there still stops the result propagating."""
        result = call(_runtime(_unconfigured()))

        assert result.allowed is False, f"{point} permitted an unconfigured point"
        assert result.point_not_configured is True


class TestPostExecuteHonoursIt:
    """``post_execute`` reads ``allowed``, so it inherits the refusal."""

    def test_unconfigured_output_blocks_and_records_nothing(self):
        adapter = _adapter(NativeAdapterResult(_unconfigured()))

        allowed, reason = adapter.post_execute(STATE, "the model's answer")

        assert allowed is False
        assert reason == POINT_NOT_CONFIGURED
        assert adapter.completed == []

    def test_transform_is_refused_because_it_cannot_be_applied(self):
        adapter = _adapter(
            NativeAdapterResult(_Evaluation(True, transform=object()))
        )

        allowed, reason = adapter.post_execute(STATE, "card 4111111111111111")

        assert allowed is False
        assert reason == "transform_not_applicable"

    def test_allow_passes_and_records_completion(self):
        adapter = _adapter(NativeAdapterResult(_Evaluation(True)))

        allowed, reason = adapter.post_execute(STATE, "fine")

        assert (allowed, reason) == (True, None)
        assert adapter.completed == [{"output_data": "fine"}]
