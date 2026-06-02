from __future__ import annotations

import unittest
from collections import deque

from dataclasses import replace

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    AgentControlSuspended,
    ApprovalOutcome,
    ApprovalResolution,
    Decision,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    Transform,
    Verdict,
    mcp_approval_resolver,
    action_identity,
)


class QueueRuntime:
    def __init__(self, results):
        self.results = deque(results)
        self.requests = []

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        result = self.results.popleft()
        if result.policy_input is not None and result.enforced_identity is not None:
            return result
        policy_input = {"intervention_point": request.intervention_point.value, "snapshot": dict(request.snapshot)}
        identity = action_identity(policy_input)
        # AGT D1.4: non-transform fixtures keep input_identity ==
        # enforced_identity; the property action_identity aliases enforced.
        return replace(
            result,
            policy_input=policy_input,
            input_identity=identity,
            enforced_identity=identity,
        )


def _escalate():
    return InterventionPointResult(Verdict(Decision.ESCALATE, reason="needs approval"))


def _allow():
    return InterventionPointResult(Verdict(Decision.ALLOW))


class EscalationConformanceTests(unittest.IsolatedAsyncioTestCase):
    async def test_deny_does_not_consult_resolver(self):
        runtime = QueueRuntime([InterventionPointResult(Verdict(Decision.DENY))])
        consulted = False

        async def resolver(intervention_point, result):
            nonlocal consulted
            consulted = True
            return ApprovalResolution.allow(result.action_identity)

        control = AgentControl(runtime, approval_resolver=resolver)

        with self.assertRaises(AgentControlBlocked):
            await control.run({"text": "x"}, _noop_execute())

        self.assertFalse(consulted)

    async def test_escalate_without_resolver_fails_closed(self):
        runtime = QueueRuntime([_escalate()])
        control = AgentControl(runtime)
        executed = False

        async def execute(value):
            nonlocal executed
            executed = True
            return value

        with self.assertRaises(AgentControlBlocked):
            await control.run({"text": "x"}, execute)

        self.assertFalse(executed)

    async def test_resolver_failure_fails_closed_with_resolver_failed_reason(self):
        async def raising(intervention_point, result):
            raise RuntimeError("resolver boom")

        async def returns_none(intervention_point, result):
            return None

        async def returns_malformed(intervention_point, result):
            return "not-a-resolution"

        for bad_resolver in (raising, returns_none, returns_malformed):
            runtime = QueueRuntime([_escalate(), _allow()])
            control = AgentControl(runtime, approval_resolver=bad_resolver)

            async def execute(value):
                return {"answer": "ok"}

            with self.assertRaises(AgentControlBlocked) as caught:
                await control.run({"text": "x"}, execute)
            self.assertEqual(
                caught.exception.result.verdict.reason,
                "runtime_error:approval_resolver_failed",
            )
            self.assertEqual(
                caught.exception.result.verdict.message,
                "Approval resolver failed closed.",
            )
            self.assertIsNotNone(caught.exception.result.policy_input)
            self.assertEqual(
                caught.exception.result.action_identity,
                action_identity(caught.exception.result.policy_input),
            )

    async def test_transform_verdict_routes_through_transformed_policy_target(self):
        """AGT D1: Decision.TRANSFORM is the canonical mutation path.

        Pre-AGT, this case exercised an ``escalate`` verdict that also
        carried a transformed_policy_target (legacy effects[] semantics).
        Per AGT D1.1 only TRANSFORM can produce a transformed_policy_target,
        so the test now drives a TRANSFORM verdict end to end and asserts
        the SDK uses the engine's transform value as the effective input
        without consulting any approval resolver.
        """

        transform = Transform(path="$policy_target.text", value="redacted")
        runtime = QueueRuntime(
            [
                InterventionPointResult(
                    Verdict(
                        Decision.TRANSFORM,
                        reason="redacted_for_demo",
                        transform=transform,
                    ),
                    transformed_policy_target={"text": "redacted"},
                ),
                _allow(),
            ]
        )

        consulted = False

        async def resolver(intervention_point, result):
            nonlocal consulted
            consulted = True
            return ApprovalResolution.allow(result.action_identity)

        control = AgentControl(runtime, approval_resolver=resolver)
        seen = []

        async def execute(value):
            seen.append(value)
            return {"answer": "ok"}

        result = await control.run({"text": "original"}, execute)

        self.assertFalse(consulted, "transform must not consult an approval resolver")
        self.assertEqual(seen, [{"text": "redacted"}])
        self.assertEqual(result.value, {"answer": "ok"})


    async def test_approval_receives_stable_action_identity(self):
        runtime = QueueRuntime([_escalate(), _escalate(), _escalate(), _allow()])
        seen_identity = None

        async def resolver(intervention_point, result):
            nonlocal seen_identity
            seen_identity = result.action_identity
            self.assertEqual(result.action_identity, action_identity(result.policy_input))
            return ApprovalResolution.allow(result.action_identity)

        control = AgentControl(runtime, approval_resolver=resolver)
        first = await control.evaluate_intervention_point(
            InterventionPoint.INPUT,
            {"input": "hi"},
            EnforcementMode.ENFORCE,
        )
        second = await control.evaluate_intervention_point(
            InterventionPoint.INPUT,
            {"input": "hi"},
            EnforcementMode.ENFORCE,
        )
        self.assertEqual(first.action_identity, second.action_identity)
        await control.run("hi", _noop_execute())
        self.assertEqual(seen_identity, first.action_identity)

    async def test_approval_action_mismatch_fails_closed(self):
        runtime = QueueRuntime([_escalate()])

        async def resolver(intervention_point, result):
            approved = result.action_identity
            result.policy_input["snapshot"]["input"] = "mutated"
            return ApprovalResolution.allow(approved)

        control = AgentControl(runtime, approval_resolver=resolver)
        with self.assertRaises(AgentControlBlocked) as caught:
            await control.run("hi", _noop_execute())
        self.assertEqual(caught.exception.result.verdict.reason, "runtime_error:approval_action_mismatch")

    async def test_escalate_deny_blocks(self):
        runtime = QueueRuntime([_escalate()])

        async def resolver(intervention_point, result):
            return ApprovalResolution.deny()

        control = AgentControl(runtime, approval_resolver=resolver)

        with self.assertRaises(AgentControlBlocked):
            await control.run({"text": "x"}, _noop_execute())

    async def test_escalate_suspend_raises_suspended_with_handle(self):
        runtime = QueueRuntime([_escalate()])

        async def resolver(intervention_point, result):
            return ApprovalResolution.suspend({"ticket": "abc"}, result.action_identity)

        control = AgentControl(runtime, approval_resolver=resolver)

        with self.assertRaises(AgentControlSuspended) as caught:
            await control.run({"text": "x"}, _noop_execute())

        self.assertEqual(caught.exception.intervention_point, InterventionPoint.INPUT)
        self.assertEqual(caught.exception.handle, {"ticket": "abc"})

    async def test_evaluate_only_does_not_consult_resolver_or_raise(self):
        runtime = QueueRuntime([_escalate(), _escalate()])
        consulted = False

        async def resolver(intervention_point, result):
            nonlocal consulted
            consulted = True
            return ApprovalResolution.allow(result.action_identity)

        control = AgentControl(runtime, approval_resolver=resolver)

        async def execute(value):
            return {"answer": "ok"}

        result = await control.run({"text": "x"}, execute, mode=EnforcementMode.EVALUATE_ONLY)

        self.assertFalse(consulted)
        self.assertEqual(result.value, {"answer": "ok"})

    async def test_post_tool_escalate_runs_tool_but_blocks_result(self):
        runtime = QueueRuntime([_allow(), _escalate()])
        control = AgentControl(runtime)
        executed = False

        async def tool(args):
            nonlocal executed
            executed = True
            return {"sum": 2}

        with self.assertRaises(AgentControlBlocked):
            await control.run_tool("adder", {"x": 1}, tool, tool_call_id="call-1")

        self.assertTrue(executed)

    async def test_per_call_resolver_overrides_instance_resolver(self):
        runtime = QueueRuntime([_escalate()])

        async def instance_resolver(intervention_point, result):
            return ApprovalResolution.deny()

        async def per_call_resolver(intervention_point, result):
            return ApprovalResolution.allow(result.action_identity)

        control = AgentControl(runtime, approval_resolver=instance_resolver)

        runtime.results.append(_allow())
        result = await control.run(
            {"text": "x"}, _echo_execute(), approval_resolver=per_call_resolver
        )

        self.assertEqual(result.value, {"answer": "ok"})

    async def test_bare_allow_outcome_is_accepted(self):
        runtime = QueueRuntime([_escalate(), _allow()])

        async def resolver(intervention_point, result):
            return ApprovalOutcome.ALLOW

        control = AgentControl(runtime, approval_resolver=resolver)
        result = await control.run({"text": "x"}, _echo_execute())
        self.assertEqual(result.value, {"answer": "ok"})

    async def test_invalid_resolver_return_fails_closed(self):
        runtime = QueueRuntime([_escalate()])

        async def resolver(intervention_point, result):
            return "yes"

        control = AgentControl(runtime, approval_resolver=resolver)

        with self.assertRaises(AgentControlBlocked):
            await control.run({"text": "x"}, _noop_execute())

    async def test_resolver_exception_fails_closed_as_blocked(self):
        runtime = QueueRuntime([_escalate()])

        async def resolver(intervention_point, result):
            raise ValueError("resolver exploded")

        control = AgentControl(runtime, approval_resolver=resolver)

        with self.assertRaises(AgentControlBlocked):
            await control.run({"text": "x"}, _noop_execute())

    async def test_sync_resolver_is_supported(self):
        runtime = QueueRuntime([_escalate(), _allow()])

        def resolver(intervention_point, result):
            return ApprovalResolution.allow(result.action_identity)

        control = AgentControl(runtime, approval_resolver=resolver)
        result = await control.run({"text": "x"}, _echo_execute())
        self.assertEqual(result.value, {"answer": "ok"})


class McpApprovalResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_accept_action_allows(self):
        runtime = QueueRuntime([_escalate(), _allow()])

        async def elicit(message):
            return {"action": "accept"}

        control = AgentControl(runtime, approval_resolver=mcp_approval_resolver(elicit))
        result = await control.run({"text": "x"}, _echo_execute())
        self.assertEqual(result.value, {"answer": "ok"})

    async def test_decline_action_blocks(self):
        runtime = QueueRuntime([_escalate()])

        async def elicit(message):
            return {"action": "decline"}

        control = AgentControl(runtime, approval_resolver=mcp_approval_resolver(elicit))

        with self.assertRaises(AgentControlBlocked):
            await control.run({"text": "x"}, _noop_execute())

    async def test_unknown_action_fails_closed(self):
        runtime = QueueRuntime([_escalate()])

        async def elicit(message):
            return {"action": "cancel"}

        control = AgentControl(runtime, approval_resolver=mcp_approval_resolver(elicit))

        with self.assertRaises(AgentControlBlocked):
            await control.run({"text": "x"}, _noop_execute())


def _noop_execute():
    async def execute(value):
        return value

    return execute


def _echo_execute():
    async def execute(value):
        return {"answer": "ok"}

    return execute


if __name__ == "__main__":
    unittest.main()
