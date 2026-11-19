"""The ACS runtime can be closed and used as a context manager (#4372)."""

from __future__ import annotations

import unittest
from collections import deque
from pathlib import Path

from agent_control_specification import (
    AgentControl,
    Decision,
    InterventionPoint,
    InterventionPointResult,
    Verdict,
)

REPO_ROOT = Path(__file__).resolve().parents[4]


class QueueRuntime:
    def __init__(self, results):
        self.results = deque(results)
        self.requests = []
        self.closed = 0

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        return self.results.popleft()

    def close(self):
        self.closed += 1


def _allow():
    return InterventionPointResult(Verdict(Decision.ALLOW))


class CloseTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_releases_the_runtime(self):
        runtime = QueueRuntime([_allow(), _allow()])
        control = AgentControl(runtime)

        control.close()

        self.assertEqual(runtime.closed, 1)

    async def test_close_twice_is_not_an_error(self):
        # A `finally` block runs on the normal path and on the error path, and
        # the caller may close again: closing twice must not raise.
        runtime = QueueRuntime([_allow(), _allow()])
        control = AgentControl(runtime)

        control.close()
        control.close()

        self.assertEqual(runtime.closed, 2)

    async def test_close_is_optional(self):
        # A runtime client without a close() (the pure-Python stub) must not
        # break the examples.
        runtime = QueueRuntime([_allow(), _allow()])
        control = AgentControl(runtime)

        control.close()

        result = await control.run({"text": "hi"}, lambda value: {"answer": "ok"})

        self.assertEqual(result.value, {"answer": "ok"})

    async def test_the_runtime_works_as_a_context_manager(self):
        runtime = QueueRuntime([_allow(), _allow()])

        with AgentControl(runtime) as control:
            result = await control.run({"text": "hi"}, lambda value: {"answer": "ok"})

        self.assertEqual(result.value, {"answer": "ok"})
        self.assertEqual(runtime.closed, 1)

    async def test_the_context_manager_closes_on_an_error(self):
        runtime = QueueRuntime([_allow(), _allow()])

        with self.assertRaises(ValueError):
            with AgentControl(runtime) as control:
                await control.run({"text": "hi"}, lambda value: {"answer": "ok"})
                raise ValueError("boom")

        self.assertEqual(runtime.closed, 1)


class ExampleRuntimeCloseTests(unittest.TestCase):
    """The examples close the runtime, so the method has to exist."""

    EXAMPLES = [
        "examples/openai-agents-governed/getting_started.py",
        "examples/crewai-governed/getting_started.py",
        "examples/smolagents-governed/getting_started.py",
        "examples/maf-integration/01-loan-processing/python/main.py",
        "examples/maf-integration/02-customer-service/python/main.py",
        "examples/maf-integration/03-healthcare/python/main.py",
        "examples/maf-integration/04-it-helpdesk/python/main.py",
        "examples/maf-integration/05-devops-deploy/python/main.py",
        "examples/deerflow-governed/provider/deerflow_agt_guardrail.py",
    ]

    def test_agent_control_exposes_close(self):
        self.assertTrue(callable(getattr(AgentControl, "close", None)))
        self.assertTrue(callable(getattr(AgentControl, "__enter__", None)))
        self.assertTrue(callable(getattr(AgentControl, "__exit__", None)))

    def test_every_example_closes_the_runtime(self):
        for relative in self.EXAMPLES:
            path = REPO_ROOT / relative
            self.assertTrue(path.exists(), f"{relative} is missing")
            source = path.read_text(encoding="utf-8")
            self.assertIn(
                ".close()",
                source,
                f"{relative} does not close the runtime it created",
            )


if __name__ == "__main__":
    unittest.main()
