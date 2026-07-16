# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Circuit-breaker scenario: repeated tool failures open the breaker.

This scenario is deterministic and does not require a model. It drives a
governed tool through the production ``agent_os`` circuit breaker until the
failure threshold trips it OPEN, then verifies that the next call is blocked
before the unstable tool is invoked again.
"""

from __future__ import annotations

from pathlib import Path

from agent_os.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitOpenError,
    CircuitState,
)

from support import ScenarioResult, write_artifact


FAILURE_THRESHOLD = 3


class MockUnstableTool:
    def __init__(self) -> None:
        self.invocations = 0

    def __call__(self) -> None:
        self.invocations += 1
        raise RuntimeError("downstream tool failure")


def run_circuit_breaker() -> tuple[ScenarioResult, CircuitBreaker, MockUnstableTool]:
    tool = MockUnstableTool()
    breaker = CircuitBreaker(
        "runaway-agent",
        CircuitBreakerConfig(
            failure_threshold=FAILURE_THRESHOLD,
            recovery_timeout_seconds=60.0,
        ),
    )

    failures = 0
    for _ in range(FAILURE_THRESHOLD):
        try:
            breaker.call(tool)
        except RuntimeError:
            failures += 1

    invocations_before_block = tool.invocations
    blocked = False
    try:
        breaker.call(tool)
    except CircuitOpenError:
        blocked = True

    return ScenarioResult(
        decision="deny" if blocked else "allow",
        executed_tools=[],
        tool_arguments=[
            {"failures": failures, "invocations": invocations_before_block}
        ],
    ), breaker, tool


def test_runaway_tool_calls_trip_circuit_breaker(artifact_dir: Path) -> None:
    result, breaker, tool = run_circuit_breaker()

    assert result.decision == "deny"
    assert breaker.get_state() is CircuitState.OPEN
    # The breaker blocked the follow-up call before the tool ran again.
    assert tool.invocations == FAILURE_THRESHOLD

    write_artifact(result, artifact_dir, "circuit-breaker")
