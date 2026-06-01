from __future__ import annotations

import unittest
from collections import deque

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    Decision,
    NativeRuntimeClient,
    InterventionPoint,
    InterventionPointRequest,
    InterventionPointResult,
    Verdict,
)


class QueueRuntime:
    def __init__(self, results):
        self.results = deque(results)
        self.requests = []

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        return self.results.popleft()


class OrchestrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_enforces_input_and_output(self):
        # AGT D1: only Decision.TRANSFORM applies the engine's
        # transformed_policy_target. Pre-AGT the SDK gated on
        # applies_effects (allow|warn|escalate), so this fixture used
        # ALLOW/WARN. Migrate to TRANSFORM so the SDK propagates the
        # rewrite per AGT D1.1.
        runtime = QueueRuntime(
            [
                InterventionPointResult(Verdict(Decision.TRANSFORM), transformed_policy_target={"text": "rewritten"}),
                InterventionPointResult(Verdict(Decision.TRANSFORM), transformed_policy_target={"answer": "redacted"}),
            ]
        )
        control = AgentControl(runtime)
        seen_inputs = []

        async def execute(value):
            seen_inputs.append(value)
            return {"answer": "raw"}

        result = await control.run({"text": "original"}, execute)

        self.assertEqual(seen_inputs, [{"text": "rewritten"}])
        self.assertEqual(result.value, {"answer": "redacted"})
        self.assertEqual([request.intervention_point for request in runtime.requests], [InterventionPoint.INPUT, InterventionPoint.OUTPUT])
        self.assertEqual(runtime.requests[1].snapshot["output"], {"answer": "raw"})

    async def test_run_splices_nested_output_transform_into_original_shape(self):
        runtime = QueueRuntime(
            [
                InterventionPointResult(Verdict(Decision.ALLOW)),
                InterventionPointResult(
                    Verdict(Decision.TRANSFORM),
                    transformed_policy_target="token [REDACTED]",
                    transformed_policy_target_applied=True,
                    policy_input={
                        "policy_target": {
                            "path": "$.output.raw",
                        }
                    },
                ),
            ]
        )
        control = AgentControl(runtime)

        async def execute(_value):
            return {"raw": "token CAMP-ABCDEFGH", "metadata": {"shape": "campaign"}}

        result = await control.run({"topic": "launch"}, execute)

        self.assertEqual(
            result.value,
            {"raw": "token [REDACTED]", "metadata": {"shape": "campaign"}},
        )

    async def test_protect_tool_enforces_pre_and_post_tool_call(self):
        # AGT D1: TRANSFORM is the only mutating decision.
        runtime = QueueRuntime(
            [
                InterventionPointResult(Verdict(Decision.TRANSFORM), transformed_policy_target={"x": 2}),
                InterventionPointResult(Verdict(Decision.TRANSFORM), transformed_policy_target={"sum": 4}),
            ]
        )
        control = AgentControl(runtime)
        seen_args = []

        async def tool(args):
            seen_args.append(args)
            return {"sum": args["x"] + 1}

        protected = control.protect_tool("adder", tool)
        result = await protected({"x": 1}, tool_call_id="call-1")

        self.assertEqual(seen_args, [{"x": 2}])
        self.assertEqual(result.value, {"sum": 4})
        self.assertEqual([request.intervention_point for request in runtime.requests], [InterventionPoint.PRE_TOOL_CALL, InterventionPoint.POST_TOOL_CALL])
        self.assertEqual(runtime.requests[0].snapshot["tool_call"], {"id": "call-1", "name": "adder", "args": {"x": 1}})
        self.assertEqual(runtime.requests[1].snapshot["tool_call"]["id"], "call-1")

    async def test_run_tool_omits_tool_call_id_when_absent(self):
        runtime = QueueRuntime([InterventionPointResult(Verdict(Decision.ALLOW)), InterventionPointResult(Verdict(Decision.ALLOW))])
        control = AgentControl(runtime)
        executed = False

        async def tool(args):
            nonlocal executed
            executed = True
            return args

        await control.run_tool("adder", {"x": 1}, tool)

        self.assertTrue(executed)
        self.assertNotIn("id", runtime.requests[0].snapshot["tool_call"])
        self.assertNotIn("id", runtime.requests[1].snapshot["tool_call"])

    async def test_run_tool_rejects_blank_tool_call_id(self):
        runtime = QueueRuntime([])
        control = AgentControl(runtime)

        with self.assertRaisesRegex(ValueError, "non-empty"):
            await control.run_tool("adder", {"x": 1}, lambda args: args, tool_call_id="")
        self.assertEqual(runtime.requests, [])

    async def test_run_tool_preserves_non_empty_whitespace_tool_call_id(self):
        runtime = QueueRuntime([InterventionPointResult(Verdict(Decision.ALLOW)), InterventionPointResult(Verdict(Decision.ALLOW))])
        control = AgentControl(runtime)

        await control.run_tool("adder", {"x": 1}, lambda args: args, tool_call_id=" ")

        self.assertEqual(runtime.requests[0].snapshot["tool_call"]["id"], " ")
        self.assertEqual(runtime.requests[1].snapshot["tool_call"]["id"], " ")

    async def test_protect_tool_omits_tool_call_id_when_absent(self):
        runtime = QueueRuntime([InterventionPointResult(Verdict(Decision.ALLOW)), InterventionPointResult(Verdict(Decision.ALLOW))])
        control = AgentControl(runtime)
        executed = False

        async def tool(args):
            nonlocal executed
            executed = True
            return args

        protected = control.protect_tool("adder", tool)
        await protected({"x": 1})

        self.assertTrue(executed)
        self.assertNotIn("id", runtime.requests[0].snapshot["tool_call"])

    async def test_deny_blocks_before_execute(self):
        runtime = QueueRuntime([InterventionPointResult(Verdict(Decision.DENY, reason="blocked"))])
        control = AgentControl(runtime)
        executed = False

        async def execute(value):
            nonlocal executed
            executed = True
            return value

        with self.assertRaises(AgentControlBlocked):
            await control.run("blocked input", execute)

        self.assertFalse(executed)

    async def test_tool_callback_exceptions_propagate_without_post_tool_mediation(self):
        runtime = QueueRuntime([InterventionPointResult(Verdict(Decision.ALLOW))])
        control = AgentControl(runtime)
        callback_error = RuntimeError("disk failed")

        async def execute(_value):
            raise callback_error

        with self.assertRaises(RuntimeError) as caught:
            await control.run_tool("shell", {"command": "echo safe"}, execute, tool_call_id="call-1")

        self.assertIs(caught.exception, callback_error)
        self.assertNotIsInstance(caught.exception, AgentControlBlocked)
        self.assertEqual(
            [request.intervention_point for request in runtime.requests],
            [InterventionPoint.PRE_TOOL_CALL],
        )

    async def test_native_runtime_client_and_from_native_fail_loudly(self):
        client = NativeRuntimeClient({}, object(), object())

        with self.assertRaisesRegex(NotImplementedError, "Native Agent Control Specification Python bindings are not implemented yet"):
            await client.evaluate_intervention_point(InterventionPointRequest(InterventionPoint.INPUT, {"input": "raw"}))

        control = AgentControl.from_native({}, object(), object())

        with self.assertRaisesRegex(NotImplementedError, "Native Agent Control Specification Python bindings are not implemented yet"):
            await control.evaluate_intervention_point(InterventionPoint.INPUT, {"input": "raw"})

    async def test_unknown_intervention_point_reaches_runtime_client(self):
        runtime = QueueRuntime([InterventionPointResult(Verdict(Decision.DENY, reason="runtime_error:intervention_point_unknown"))])
        control = AgentControl(runtime)

        result = await control.evaluate_intervention_point("not_a_real_point", {"input": "raw"})

        self.assertEqual(result.verdict.reason, "runtime_error:intervention_point_unknown")
        self.assertEqual(runtime.requests[0].intervention_point, "not_a_real_point")


if __name__ == "__main__":
    unittest.main()
