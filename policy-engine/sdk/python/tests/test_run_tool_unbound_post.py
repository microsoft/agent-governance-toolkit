# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``run_tool`` refuses a tool whose ``post_tool_call`` is not bound before it runs (#4424).

An unbound intervention point denies with
``runtime_error:intervention_point_unknown`` (#3528). Before the fix the SDK
only learned that from the engine's answer to the post-check, by which time
the tool had already run. These tests pin the order: the same block, the same
reason, and a tool callable that is never invoked.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    Decision,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    SnapshotBuilder,
    Verdict,
)

try:
    from agent_control_specification import _native  # noqa: F401
except ImportError:
    _NATIVE_AVAILABLE = False
else:
    _NATIVE_AVAILABLE = True


_HEADER = """agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: run-tool-binding
policies:
  tools:
    type: custom
    adapter: test
"""

_PRE_POINT = """  pre_tool_call:
    policy_target: $.tool_call.args
    policy:
      id: tools
"""

_POST_POINT = """  post_tool_call:
    policy_target: $.tool_result
    policy:
      id: tools
"""

MANIFEST_PRE_ONLY = _HEADER + "intervention_points:\n" + _PRE_POINT
MANIFEST_BOTH = _HEADER + "intervention_points:\n" + _PRE_POINT + _POST_POINT
# ``input`` is bound so the manifest is valid while neither tool point is.
MANIFEST_NEITHER = (
    _HEADER
    + """intervention_points:
  input:
    policy_target: $.input
    policy:
      id: tools
"""
)
# The parent binds ``post_tool_call``; the child binds ``pre_tool_call``.
MANIFEST_CHAIN_PARENT = _HEADER + "intervention_points:\n" + _POST_POINT
MANIFEST_CHAIN_CHILD = """agent_control_specification_version: 0.4.0-alpha.1
intervention_points:
""" + _PRE_POINT

UNKNOWN = "runtime_error:intervention_point_unknown"


class RecordingPolicy:
    """Allows every call unless told to deny a given policy target value."""

    def __init__(self, deny_when=None):
        self.deny_when = deny_when
        self.invocations = []

    def evaluate(self, invocation):
        self.invocations.append(invocation)
        value = invocation["input"]["policy_target"]["value"]
        if self.deny_when is not None and self.deny_when(value):
            return {"decision": "deny", "reason": "policy_said_no"}
        return {"decision": "allow"}


class SpyTool:
    def __init__(self):
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        return {"sent": args["amount"]}


@unittest.skipUnless(_NATIVE_AVAILABLE, "native extension not built")
class RunToolUnboundPostToolCallTests(unittest.IsolatedAsyncioTestCase):
    async def test_pre_only_manifest_blocks_before_the_tool_runs(self):
        policy = RecordingPolicy()
        control = AgentControl.from_native(MANIFEST_PRE_ONLY, policy_dispatcher=policy)
        tool = SpyTool()

        with self.assertRaises(AgentControlBlocked) as ctx:
            await control.run_tool("send_payment", {"amount": 100}, tool)

        self.assertEqual(tool.calls, [], "the tool ran although the call was reported blocked")
        self.assertEqual(ctx.exception.intervention_point, InterventionPoint.POST_TOOL_CALL)
        self.assertEqual(ctx.exception.result.verdict.decision, Decision.DENY)
        self.assertEqual(ctx.exception.result.verdict.reason, UNKNOWN)
        self.assertIsNone(ctx.exception.result.policy_input)
        self.assertEqual(str(ctx.exception), f"Agent Control Specification blocked post_tool_call ({UNKNOWN}).")
        # The pre-check still ran and permitted the call, as before.
        self.assertEqual(len(policy.invocations), 1)

    async def test_pre_only_block_matches_the_engine_verdict_for_an_unbound_point(self):
        # The early block must be indistinguishable from what the engine
        # returned after the tool ran, so existing callers see no difference.
        policy = RecordingPolicy()
        control = AgentControl.from_native(MANIFEST_PRE_ONLY, policy_dispatcher=policy)
        engine = await control.evaluate_intervention_point(
            InterventionPoint.POST_TOOL_CALL,
            {"tool_call": {"name": "send_payment", "args": {}}, "tool_result": {}},
        )

        with self.assertRaises(AgentControlBlocked) as ctx:
            await control.run_tool("send_payment", {"amount": 100}, SpyTool())

        self.assertEqual(ctx.exception.result, engine)

    async def test_pre_only_manifest_releases_the_tool_call_slot(self):
        control = AgentControl.from_native(MANIFEST_PRE_ONLY, policy_dispatcher=RecordingPolicy())
        builder = SnapshotBuilder(agent_id="agent", session_id="s")

        with self.assertRaises(AgentControlBlocked):
            await control.run_tool("send_payment", {"amount": 1}, SpyTool(), snapshot=builder)

        # The call did not go ahead, so it does not count against the budget.
        self.assertEqual(builder.tool_call_count, 0)

    async def test_pre_only_manifest_through_protect_tool(self):
        control = AgentControl.from_native(MANIFEST_PRE_ONLY, policy_dispatcher=RecordingPolicy())
        tool = SpyTool()
        guarded = control.protect_tool("send_payment", tool)

        with self.assertRaises(AgentControlBlocked) as ctx:
            await guarded({"amount": 5}, tool_call_id="call-1")

        self.assertEqual(tool.calls, [])
        self.assertEqual(ctx.exception.result.verdict.reason, UNKNOWN)

    async def test_pre_only_manifest_in_evaluate_only_mode_still_runs_the_tool(self):
        # Nothing is enforced in evaluate_only mode, so the tool runs and the
        # engine's post-check result is returned for inspection, as before.
        control = AgentControl.from_native(MANIFEST_PRE_ONLY, policy_dispatcher=RecordingPolicy())
        tool = SpyTool()

        result = await control.run_tool(
            "send_payment", {"amount": 2}, tool, mode=EnforcementMode.EVALUATE_ONLY
        )

        self.assertEqual(tool.calls, [{"amount": 2}])
        self.assertEqual(result.value, {"sent": 2})
        self.assertEqual(result.post_tool_call_result.verdict.reason, UNKNOWN)

    async def test_pre_deny_still_takes_precedence(self):
        # A pre-check deny is reported as such, not as the missing post point.
        policy = RecordingPolicy(deny_when=lambda value: value.get("amount", 0) > 50)
        control = AgentControl.from_native(MANIFEST_PRE_ONLY, policy_dispatcher=policy)
        tool = SpyTool()

        with self.assertRaises(AgentControlBlocked) as ctx:
            await control.run_tool("send_payment", {"amount": 100}, tool)

        self.assertEqual(tool.calls, [])
        self.assertEqual(ctx.exception.intervention_point, InterventionPoint.PRE_TOOL_CALL)
        self.assertEqual(ctx.exception.result.verdict.reason, "policy_said_no")

    async def test_both_bound_allow_runs_the_tool(self):
        policy = RecordingPolicy()
        control = AgentControl.from_native(MANIFEST_BOTH, policy_dispatcher=policy)
        tool = SpyTool()

        result = await control.run_tool("send_payment", {"amount": 7}, tool)

        self.assertEqual(tool.calls, [{"amount": 7}])
        self.assertEqual(result.value, {"sent": 7})
        self.assertEqual(result.pre_tool_call_result.verdict.decision, Decision.ALLOW)
        self.assertEqual(result.post_tool_call_result.verdict.decision, Decision.ALLOW)
        self.assertEqual(len(policy.invocations), 2)

    async def test_both_bound_deny_at_post_withholds_the_result(self):
        # The post-check sees the tool result; denying there withholds it but
        # cannot undo the side effect, which is why the pre-check exists.
        policy = RecordingPolicy(deny_when=lambda value: isinstance(value, dict) and "sent" in value)
        control = AgentControl.from_native(MANIFEST_BOTH, policy_dispatcher=policy)
        tool = SpyTool()

        with self.assertRaises(AgentControlBlocked) as ctx:
            await control.run_tool("send_payment", {"amount": 9}, tool)

        self.assertEqual(tool.calls, [{"amount": 9}])
        self.assertEqual(ctx.exception.intervention_point, InterventionPoint.POST_TOOL_CALL)
        self.assertEqual(ctx.exception.result.verdict.reason, "policy_said_no")

    async def test_neither_bound_blocks_at_pre_before_the_tool_runs(self):
        policy = RecordingPolicy()
        control = AgentControl.from_native(MANIFEST_NEITHER, policy_dispatcher=policy)
        tool = SpyTool()

        with self.assertRaises(AgentControlBlocked) as ctx:
            await control.run_tool("send_payment", {"amount": 3}, tool)

        self.assertEqual(tool.calls, [])
        self.assertEqual(ctx.exception.intervention_point, InterventionPoint.PRE_TOOL_CALL)
        self.assertEqual(ctx.exception.result.verdict.reason, UNKNOWN)
        self.assertEqual(policy.invocations, [])

    async def test_post_bound_in_chain_parent_counts_as_bound(self):
        policy = RecordingPolicy()
        control = AgentControl.from_manifest_chain(
            [MANIFEST_CHAIN_PARENT, MANIFEST_CHAIN_CHILD], policy_dispatcher=policy
        )
        tool = SpyTool()

        result = await control.run_tool("send_payment", {"amount": 4}, tool)

        self.assertEqual(tool.calls, [{"amount": 4}])
        self.assertEqual(result.value, {"sent": 4})
        self.assertEqual(len(policy.invocations), 2)

    async def test_post_bound_in_extends_parent_counts_as_bound(self):
        policy = RecordingPolicy()
        with tempfile.TemporaryDirectory() as directory:
            parent = os.path.join(directory, "parent.yaml")
            child = os.path.join(directory, "child.yaml")
            with open(parent, "w", encoding="utf-8") as handle:
                handle.write(MANIFEST_CHAIN_PARENT)
            with open(child, "w", encoding="utf-8") as handle:
                handle.write(MANIFEST_CHAIN_CHILD.replace("intervention_points:", "extends:\n  - parent.yaml\nintervention_points:"))
            control = AgentControl.from_path(child, policy_dispatcher=policy)
            tool = SpyTool()

            result = await control.run_tool("send_payment", {"amount": 6}, tool)

        self.assertEqual(tool.calls, [{"amount": 6}])
        self.assertEqual(result.value, {"sent": 6})


class CustomClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_without_policy_labels_leaves_the_question_to_the_engine(self):
        # A pure-Python client that does not report its bound points keeps the
        # old order: the engine's post-check answer decides, after the tool ran.
        class QueueRuntime:
            def __init__(self, results):
                self.results = list(results)

            async def evaluate_intervention_point(self, request):
                return self.results.pop(0)

        runtime = QueueRuntime(
            [
                InterventionPointResult(Verdict(Decision.ALLOW)),
                InterventionPointResult(Verdict(Decision.DENY, reason=UNKNOWN)),
            ]
        )
        control = AgentControl(runtime)
        tool = SpyTool()

        with self.assertRaises(AgentControlBlocked) as ctx:
            await control.run_tool("send_payment", {"amount": 1}, tool)

        self.assertEqual(tool.calls, [{"amount": 1}])
        self.assertEqual(ctx.exception.result.verdict.reason, UNKNOWN)

    async def test_client_reporting_bound_points_blocks_before_the_tool_runs(self):
        class LabeledRuntime:
            def __init__(self):
                self.requests = []

            def policy_labels(self):
                return {"pre_tool_call": {"policy_id": "tools", "annotators": []}}

            async def evaluate_intervention_point(self, request):
                self.requests.append(request)
                return InterventionPointResult(Verdict(Decision.ALLOW))

        runtime = LabeledRuntime()
        control = AgentControl(runtime)
        tool = SpyTool()

        with self.assertRaises(AgentControlBlocked) as ctx:
            await control.run_tool("send_payment", {"amount": 1}, tool)

        self.assertEqual(tool.calls, [])
        self.assertEqual(ctx.exception.intervention_point, InterventionPoint.POST_TOOL_CALL)
        self.assertEqual(ctx.exception.result.verdict.reason, UNKNOWN)
        self.assertEqual([request.intervention_point for request in runtime.requests], [InterventionPoint.PRE_TOOL_CALL])


if __name__ == "__main__":
    unittest.main()
