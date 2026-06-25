# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for :class:`agt.policies.result.EvaluationResult`.

These pin the invariant that the v4 back-compat ``allowed`` view is
always derived from the v5 ``verdict`` source of truth and can never
drift from :meth:`EvaluationResult.is_allowed`, regardless of how the
result is constructed.
"""

from __future__ import annotations

import typing

import pytest

from agt.policies.result import _PERMITTING_VERDICTS, EvaluationResult, Verdict

_ALL_VERDICTS = typing.get_args(Verdict)


@pytest.mark.parametrize("verdict", _ALL_VERDICTS)
def test_allowed_is_derived_from_verdict(verdict: str) -> None:
    result = EvaluationResult(verdict=verdict)  # type: ignore[arg-type]
    assert result.allowed is (verdict in _PERMITTING_VERDICTS)


@pytest.mark.parametrize("verdict", _ALL_VERDICTS)
def test_allowed_matches_is_allowed(verdict: str) -> None:
    result = EvaluationResult(verdict=verdict)  # type: ignore[arg-type]
    assert result.allowed == result.is_allowed()


def test_default_verdict_is_allowed() -> None:
    assert EvaluationResult().verdict == "allow"
    assert EvaluationResult().allowed is True


def test_model_copy_re_derives_allowed_without_explicit_update() -> None:
    """Updating only ``verdict`` via ``model_copy`` re-derives ``allowed``.

    This is the structural guarantee method A buys: the runtime never has
    to pair ``allowed`` with ``verdict`` again.
    """
    denied = EvaluationResult(verdict="deny")
    assert denied.allowed is False

    flipped = denied.model_copy(update={"verdict": "allow"})
    assert flipped.allowed is True

    blocked = flipped.model_copy(update={"verdict": "escalate"})
    assert blocked.allowed is False


def test_allowed_serialized_for_v4_wire_compat() -> None:
    dumped = EvaluationResult(verdict="deny").model_dump()
    assert dumped["allowed"] is False
    assert EvaluationResult(verdict="warn").model_dump()["allowed"] is True


def test_allowed_is_not_an_input_field() -> None:
    """``allowed`` is a derived view, so it is rejected as constructor input."""
    with pytest.raises(Exception):
        EvaluationResult(allowed=False)  # type: ignore[call-arg]
