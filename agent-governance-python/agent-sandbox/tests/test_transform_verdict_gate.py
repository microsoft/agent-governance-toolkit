# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Every sandbox provider must refuse a ``transform`` verdict.

``transform`` permits the call, but it permits a *rewritten* one: the verdict
carries the replacement the caller is expected to apply. The sandbox gate runs
against code it has already been handed and cannot apply a replacement, so
treating ``transform`` as allowed would execute the original text while the
policy believed it had been rewritten. A policy that redacts a credential out
of a snippet would not redact it.

These drive the real ``execute_code`` gate with a real ACS ``Verdict``
against providers whose session state is pre-seeded, so no daemon, VM, or
cloud backend is needed to reach the branch under test. The five providers
carry the evaluator two different ways (an ``_evaluators`` map keyed by session
versus a field on the session object), so the seeding is per provider.
"""

from __future__ import annotations

import threading
import types

import pytest

from agent_control_specification import (
    Decision,
    InterventionPointResult,
    Verdict,
)


def _result(decision: Decision, **kwargs: object) -> InterventionPointResult:
    return InterventionPointResult(verdict=Verdict(decision=decision, **kwargs))


class _StubEvaluator:
    """Return one fixed verdict, recording whether the gate consulted it."""

    def __init__(self, result: InterventionPointResult) -> None:
        self._result = result
        self.calls: list[str] = []

    def pre_tool_call(self, **kwargs: object) -> InterventionPointResult:
        self.calls.append(str(kwargs.get("tool_name")))
        return self._result


def _seed_map_style(cls, evaluator, *session_attrs: str):
    """Providers holding evaluators in ``self._evaluators`` keyed by session.

    Each provider checks a different set of session maps before the gate, so
    the caller names every map that must be populated for the call to reach it.
    """
    provider = object.__new__(cls)
    key = ("agent-1", "session-1")
    provider._state_lock = threading.RLock()
    for attr in session_attrs:
        setattr(provider, attr, {key: object()})
    provider._evaluators = {key: evaluator}
    provider._session_configs = {key: None}
    return provider


def _seed_session_style(cls, evaluator):
    """Providers reading ``session.evaluator`` off the session object."""
    provider = object.__new__(cls)
    key = ("agent-1", "session-1")
    provider._state_lock = threading.RLock()
    session = types.SimpleNamespace(
        evaluator=evaluator, interpreter="python3", config=None
    )
    provider._sessions = {key: session}
    return provider


def _cases():
    """Return (name, seeder) for every provider exposing the execute gate."""
    from agent_sandbox.aca_sandbox_provider.aca_sandbox_provider import (
        ACASandboxProvider,
    )
    from agent_sandbox.docker_provider.provider import DockerSandboxProvider
    from agent_sandbox.hyperlight_provider.provider import (
        HyperLightSandboxProvider,
    )
    from agent_sandbox.mxc_sandbox_provider.provider import MxcSandboxProvider
    from agent_sandbox.nono_sandbox_provider.provider import NonoSandboxProvider

    return [
        ("docker", lambda e: _seed_map_style(DockerSandboxProvider, e, "_containers")),
        (
            "hyperlight",
            lambda e: _seed_map_style(
                HyperLightSandboxProvider, e, "_sandboxes", "_workers"
            ),
        ),
        ("aca", lambda e: _seed_map_style(ACASandboxProvider, e, "_sandboxes")),
        ("mxc", lambda e: _seed_session_style(MxcSandboxProvider, e)),
        ("nono", lambda e: _seed_session_style(NonoSandboxProvider, e)),
    ]


CASES = _cases()
IDS = [c[0] for c in CASES]


@pytest.mark.parametrize("name,seed", CASES, ids=IDS)
def test_transform_verdict_is_refused(name, seed):
    evaluator = _StubEvaluator(_result(Decision.TRANSFORM))
    provider = seed(evaluator)

    with pytest.raises(PermissionError) as excinfo:
        provider.execute_code("agent-1", "session-1", "print(SECRET)")

    # Refused for the right reason, not by accidentally failing elsewhere.
    assert "transform" in str(excinfo.value).lower()
    assert evaluator.calls == ["sandbox_execute"], f"{name} never reached the gate"


@pytest.mark.parametrize("name,seed", CASES, ids=IDS)
def test_deny_verdict_is_still_refused(name, seed):
    evaluator = _StubEvaluator(_result(Decision.DENY, reason="tool_denied"))
    provider = seed(evaluator)

    with pytest.raises(PermissionError) as excinfo:
        provider.execute_code("agent-1", "session-1", "print(1)")

    assert "denied" in str(excinfo.value).lower()
    assert evaluator.calls == ["sandbox_execute"]


@pytest.mark.parametrize("name,seed", CASES, ids=IDS)
def test_allow_verdict_passes_the_gate(name, seed):
    """The guard must reject only transform, not every permitting verdict."""
    evaluator = _StubEvaluator(_result(Decision.ALLOW))
    provider = seed(evaluator)

    # Past the gate the call fails on the absent backend, which is the point:
    # it proves the guard let an ``allow`` through rather than short-circuiting.
    with pytest.raises(Exception) as excinfo:
        provider.execute_code("agent-1", "session-1", "print(1)")

    assert "transform" not in str(excinfo.value).lower()
    assert "governance denied" not in str(excinfo.value).lower()
    assert evaluator.calls == ["sandbox_execute"]
