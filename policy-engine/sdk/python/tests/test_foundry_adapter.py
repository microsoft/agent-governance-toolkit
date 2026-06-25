from __future__ import annotations

import importlib.util
import json
import unittest
from collections import deque
from collections.abc import Mapping
from dataclasses import replace
from unittest.mock import patch

from agent_control_specification import (
    AdapterUnsupportedError,
    AgentControl,
    AgentControlSuspended,
    ApprovalOutcome,
    ApprovalResolution,
    Decision,
    InterventionPoint,
    InterventionPointResult,
    Verdict,
    action_identity,
    guard_azure_ai_agents,
    guard_foundry_agent,
)

def _has_azure_ai_agents() -> bool:
    # find_spec on a dotted name raises ModuleNotFoundError when the top-level
    # azure package is absent (as in CI), so absence is reported as False rather
    # than raising during collection.
    try:
        return importlib.util.find_spec("azure.ai.agents") is not None
    except ModuleNotFoundError:
        return False


_HAS_AZURE_AI_AGENTS = _has_azure_ai_agents()


def _result(decision=Decision.ALLOW, transformed=None, applied=False):
    if transformed is not None or applied:
        decision = Decision.TRANSFORM
    return InterventionPointResult(
        Verdict(decision),
        transformed_policy_target=transformed,
        transformed_policy_target_applied=applied,
    )


class QueueRuntime:
    def __init__(self, results):
        self.results = deque(results)
        self.requests = []

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        return self.results.popleft()


class IdentityQueueRuntime(QueueRuntime):
    """QueueRuntime that synthesizes policy_input and a bound identity.

    The approval path (escalate -> resolver) binds the approved identity to the
    evaluated policy input, so a suspend resolution only takes effect when the
    result carries an identity. Mirrors tests/test_escalation.py.
    """

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        result = self.results.popleft()
        policy_input = {
            "intervention_point": request.intervention_point.value,
            "snapshot": dict(request.snapshot),
        }
        identity = action_identity(policy_input)
        return replace(
            result, policy_input=policy_input, input_identity=identity, enforced_identity=identity
        )


# --- Minimal fake Azure AI Foundry AgentsClient (never touches Azure) ---------
class _FakeFunction:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _FakeToolCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.type = "function"
        self.function = _FakeFunction(name, arguments)


class _FakeApprovalAction:
    """A non submit_tool_outputs required action (e.g. an MCP tool approval)."""

    def __init__(self):
        self.type = "submit_tool_approval"
        self.submit_tool_approval = object()


class _FakeRequiredAction:
    def __init__(self, tool_calls):
        self.type = "submit_tool_outputs"
        self.submit_tool_outputs = _FakeSubmitToolOutputs(tool_calls)


class _FakeSubmitToolOutputs:
    def __init__(self, tool_calls):
        self.tool_calls = tool_calls


class _FakeRun:
    def __init__(self, run_id, status, thread_id, agent_id=None, required_action=None):
        self.id = run_id
        self.status = status
        self.thread_id = thread_id
        self.agent_id = agent_id
        self.required_action = required_action


class _FakeThread:
    def __init__(self, thread_id):
        self.id = thread_id


class FakeThreads:
    def __init__(self):
        self.create_calls = 0

    def create(self, **kwargs):
        self.create_calls += 1
        return _FakeThread("thread-1")


class FakeMessages:
    def __init__(self):
        self.created = []

    def create(self, *, thread_id, role, content, **kwargs):
        self.created.append({"thread_id": thread_id, "role": role, "content": content})
        return {"id": "msg-1"}


class FakeRuns:
    def __init__(self, required_action, *, agent_id="agent-1"):
        self._run = _FakeRun(
            "run-1", "requires_action", "thread-1", agent_id=agent_id, required_action=required_action
        )
        self.submitted = []
        self.create_calls = 0
        self.get_calls = 0
        self.submit_calls = 0
        self.create_and_process_called = 0

    def create(self, thread_id, *, agent_id=None, **kwargs):
        self.create_calls += 1
        self._run.thread_id = thread_id
        if agent_id is not None:
            self._run.agent_id = agent_id
        return self._run

    def get(self, thread_id, run_id, **kwargs):
        self.get_calls += 1
        return self._run

    def submit_tool_outputs(self, thread_id, run_id, *, tool_outputs, **kwargs):
        self.submit_calls += 1
        self.submitted.append(list(tool_outputs))
        self._run.status = "completed"
        self._run.required_action = None
        return self._run

    def create_and_process(self, *args, **kwargs):
        self.create_and_process_called += 1
        return self._run

    def submit_tool_outputs_stream(self, *args, **kwargs):
        return self._run


class FakeAgentsClient:
    def __init__(self, runs):
        self.threads = FakeThreads()
        self.messages = FakeMessages()
        self.runs = runs
        self.enable_auto_calls_called = 0
        self.process_run_called = 0

    def enable_auto_function_calls(self, *args, **kwargs):
        self.enable_auto_calls_called += 1

    def create_thread_and_process_run(self, *args, **kwargs):
        self.process_run_called += 1
        return self.runs._run


class ToolRecorder:
    def __init__(self):
        self.calls = []

    def search_records(self, **kwargs):
        self.calls.append(("search_records", dict(kwargs)))
        return f"rows for {kwargs.get('query')}"

    def run_sql(self, **kwargs):
        self.calls.append(("run_sql", dict(kwargs)))
        return f"executed {kwargs.get('query')}"

    def boom(self, **kwargs):
        self.calls.append(("boom", dict(kwargs)))
        raise ValueError("tool blew up")


def _field(output, name):
    value = getattr(output, name, None)
    if value is None and isinstance(output, Mapping):
        return output.get(name)
    return value


def _action(*tool_calls):
    return _FakeRequiredAction(list(tool_calls))


class FoundryAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_alias_points_at_same_callable(self):
        self.assertIs(guard_azure_ai_agents, guard_foundry_agent)

    async def test_safe_allowed_and_destructive_denied_in_one_run(self):
        runtime = QueueRuntime([_result(), _result(), _result(Decision.DENY)])
        recorder = ToolRecorder()
        runs = FakeRuns(
            _action(
                _FakeToolCall("call-safe", "search_records", '{"query": "SELECT 1"}'),
                _FakeToolCall("call-drop", "run_sql", '{"query": "DROP TABLE t"}'),
            )
        )
        client = FakeAgentsClient(runs)
        guarded = guard_foundry_agent(
            AgentControl(runtime),
            client,
            tools={"search_records": recorder.search_records, "run_sql": recorder.run_sql},
        )

        run = await guarded.create_thread_and_run(
            "agent-1", content="audit the table", poll_interval=0
        )

        self.assertEqual(run.status, "completed")
        # Only the safe callable ran; the destructive one was denied pre-execution.
        self.assertEqual(recorder.calls, [("search_records", {"query": "SELECT 1"})])
        self.assertEqual(runs.submit_calls, 1)
        outputs = runs.submitted[0]
        self.assertEqual(_field(outputs[0], "tool_call_id"), "call-safe")
        self.assertEqual(_field(outputs[0], "output"), "rows for SELECT 1")
        self.assertEqual(_field(outputs[1], "tool_call_id"), "call-drop")
        rejection = json.loads(_field(outputs[1], "output"))
        self.assertEqual(rejection["agent_control"], "blocked")
        self.assertEqual(rejection["intervention_point"], InterventionPoint.PRE_TOOL_CALL.value)
        # The run context is surfaced to the policy snapshot.
        self.assertEqual(runtime.requests[0].snapshot["thread_id"], "thread-1")
        self.assertEqual(runtime.requests[0].snapshot["run_id"], "run-1")
        self.assertEqual(runtime.requests[0].snapshot["agent_id"], "agent-1")

    async def test_post_transform_redacts_submitted_output(self):
        runtime = QueueRuntime([_result(), _result(transformed={"redacted": True})])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "search_records", '{"query": "SELECT secret"}')))
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        self.assertEqual(recorder.calls, [("search_records", {"query": "SELECT secret"})])
        output = runs.submitted[0][0]
        self.assertEqual(_field(output, "output"), json.dumps({"redacted": True}, separators=(",", ":")))

    async def test_pre_transform_passes_redacted_args_to_callable(self):
        runtime = QueueRuntime([_result(transformed={"query": "SELECT 1"}), _result()])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "search_records", '{"query": "SELECT raw"}')))
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        self.assertEqual(recorder.calls, [("search_records", {"query": "SELECT 1"})])
        self.assertEqual(_field(runs.submitted[0][0], "output"), "rows for SELECT 1")

    async def test_escalate_surfaced_to_approval_path_not_auto_allowed(self):
        runtime = QueueRuntime([_result(Decision.ESCALATE)])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "run_sql", '{"query": "DELETE FROM t"}')))
        consulted = []

        async def resolver(intervention_point, result):
            consulted.append(intervention_point)
            return ApprovalOutcome.DENY

        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"run_sql": recorder.run_sql}
        )

        run = await guarded.create_thread_and_run(
            "agent-1", content="go", poll_interval=0, approval_resolver=resolver
        )

        self.assertEqual(consulted, [InterventionPoint.PRE_TOOL_CALL])
        self.assertEqual(recorder.calls, [])  # never auto-allowed
        rejection = json.loads(_field(runs.submitted[0][0], "output"))
        self.assertEqual(rejection["agent_control"], "blocked")
        self.assertEqual(run.status, "completed")

    async def test_governed_driver_never_uses_auto_function_calls(self):
        runtime = QueueRuntime([_result(), _result()])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "search_records", '{"query": "q"}')))
        client = FakeAgentsClient(runs)
        guarded = guard_foundry_agent(
            AgentControl(runtime), client, tools={"search_records": recorder.search_records}
        )

        await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        self.assertEqual(client.enable_auto_calls_called, 0)
        self.assertEqual(runs.create_and_process_called, 0)
        self.assertEqual(client.process_run_called, 0)
        # Every auto-execute / streaming bypass is blocked through the handle.
        with self.assertRaises(AdapterUnsupportedError):
            guarded.enable_auto_function_calls()
        with self.assertRaises(AdapterUnsupportedError):
            guarded.create_thread_and_process_run(thread_id="thread-1", agent_id="agent-1")
        with self.assertRaises(AdapterUnsupportedError):
            guarded.runs.create_and_process(thread_id="thread-1", agent_id="agent-1")
        with self.assertRaises(AdapterUnsupportedError):
            guarded.runs.submit_tool_outputs_stream(thread_id="thread-1", run_id="run-1")

    async def test_run_until_complete_drives_existing_run(self):
        runtime = QueueRuntime([_result(), _result()])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "search_records", '{"query": "q"}')))
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        run = await guarded.run_until_complete("thread-1", "run-1", poll_interval=0)

        self.assertEqual(run.status, "completed")
        self.assertEqual(recorder.calls, [("search_records", {"query": "q"})])
        self.assertGreaterEqual(runs.get_calls, 1)

    async def test_unknown_tool_is_rejected_without_execution(self):
        runtime = QueueRuntime([])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "delete_everything", "{}")))
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        self.assertEqual(recorder.calls, [])
        self.assertEqual(runtime.requests, [])  # policy never consulted for an unknown tool
        rejection = json.loads(_field(runs.submitted[0][0], "output"))
        self.assertEqual(rejection["agent_control"], "blocked")

    async def test_invalid_json_arguments_are_rejected_without_execution(self):
        runtime = QueueRuntime([])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "search_records", "{not json")))
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        # Malformed arguments fail closed before the callable runs and before the
        # policy is consulted, rather than crashing the run loop.
        self.assertEqual(recorder.calls, [])
        self.assertEqual(runtime.requests, [])
        rejection = json.loads(_field(runs.submitted[0][0], "output"))
        self.assertEqual(rejection["agent_control"], "blocked")
        self.assertIn("not valid JSON", rejection["reason"])

    async def test_non_object_json_arguments_are_rejected_without_execution(self):
        # Valid JSON that is not an object (array/scalar) must fail closed, not be
        # spread into the callable positionally (which would crash the run loop).
        for raw in ('[1, 2, 3]', '42', '"DROP TABLE t"', 'true'):
            with self.subTest(raw=raw):
                runtime = QueueRuntime([])
                recorder = ToolRecorder()
                runs = FakeRuns(_action(_FakeToolCall("call-1", "search_records", raw)))
                guarded = guard_foundry_agent(
                    AgentControl(runtime),
                    FakeAgentsClient(runs),
                    tools={"search_records": recorder.search_records},
                )

                run = await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

                self.assertEqual(recorder.calls, [])
                self.assertEqual(runtime.requests, [])
                rejection = json.loads(_field(runs.submitted[0][0], "output"))
                self.assertEqual(rejection["agent_control"], "blocked")
                self.assertIn("JSON object", rejection["reason"])
                self.assertEqual(run.status, "completed")

    async def test_non_submit_tool_outputs_action_fails_closed_without_spinning(self):
        # An approval/MCP required action this adapter does not govern must raise
        # rather than POST an empty tool_outputs list and busy-loop.
        runtime = QueueRuntime([])
        recorder = ToolRecorder()
        runs = FakeRuns(_FakeApprovalAction())
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        with self.assertRaises(AdapterUnsupportedError):
            await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        self.assertEqual(runs.submit_calls, 0)  # never POSTed empty outputs
        self.assertEqual(recorder.calls, [])

    async def test_max_rounds_caps_a_run_that_never_terminates(self):
        # A server that keeps a run in requires_action after every submit must be
        # bounded, not looped forever.
        runtime = QueueRuntime([_result() for _ in range(40)])
        recorder = ToolRecorder()

        class StuckRuns(FakeRuns):
            def submit_tool_outputs(self, thread_id, run_id, *, tool_outputs, **kwargs):
                self.submit_calls += 1
                self.submitted.append(list(tool_outputs))
                return self._run  # status stays requires_action

        runs = StuckRuns(_action(_FakeToolCall("call-1", "search_records", '{"query": "q"}')))
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        with self.assertRaises(AdapterUnsupportedError):
            await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0, max_rounds=5)
        self.assertLessEqual(runs.submit_calls, 5)

    async def test_suspend_outcome_propagates_and_does_not_execute(self):
        # A suspend approval outcome surfaces AgentControlSuspended to the host
        # (deferred approval), never auto-allowing the tool.
        runtime = IdentityQueueRuntime([_result(Decision.ESCALATE)])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "run_sql", '{"query": "DELETE FROM t"}')))

        async def resolver(intervention_point, result):
            return ApprovalResolution.suspend(handle="ticket-1", action_identity=result.action_identity)

        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"run_sql": recorder.run_sql}
        )

        with self.assertRaises(AgentControlSuspended):
            await guarded.create_thread_and_run(
                "agent-1", content="go", poll_interval=0, approval_resolver=resolver
            )
        self.assertEqual(recorder.calls, [])
        self.assertEqual(runs.submit_calls, 0)

    async def test_tool_execution_error_is_isolated_as_error_output(self):
        # A callable that raises must not abort the run; it yields an error output
        # carrying only the exception kind, not its message.
        runtime = QueueRuntime([_result(), _result(), _result()])
        recorder = ToolRecorder()
        runs = FakeRuns(
            _action(
                _FakeToolCall("call-boom", "boom", "{}"),
                _FakeToolCall("call-ok", "search_records", '{"query": "q"}'),
            )
        )
        guarded = guard_foundry_agent(
            AgentControl(runtime),
            FakeAgentsClient(runs),
            tools={"boom": recorder.boom, "search_records": recorder.search_records},
        )

        run = await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        self.assertEqual(run.status, "completed")
        outputs = runs.submitted[0]
        err = json.loads(_field(outputs[0], "output"))
        self.assertEqual(err["agent_control"], "error")
        self.assertEqual(err["error"], "ValueError")
        self.assertNotIn("blew up", _field(outputs[0], "output"))
        # The sibling call still ran and its output was submitted.
        self.assertEqual(_field(outputs[1], "output"), "rows for q")

    async def test_authoritative_run_context_wins_over_host_snapshot(self):
        runtime = QueueRuntime([_result(), _result()])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "search_records", '{"query": "q"}')))
        guarded = guard_foundry_agent(
            AgentControl(runtime),
            FakeAgentsClient(runs),
            tools={"search_records": recorder.search_records},
            snapshot={"thread_id": "SPOOFED", "tenant": "acme"},
        )

        await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        snap = runtime.requests[0].snapshot
        self.assertEqual(snap["thread_id"], "thread-1")  # server value wins
        self.assertEqual(snap["tenant"], "acme")  # unrelated host keys pass through

    async def test_reserved_snapshot_kwarg_is_rejected_not_forwarded(self):
        runtime = QueueRuntime([_result(), _result()])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "search_records", '{"query": "q"}')))
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        with self.assertRaises(TypeError):
            await guarded.create_thread_and_run(
                "agent-1", content="go", poll_interval=0, agent_control_snapshot={"x": 1}
            )

    def test_invalid_mode_fails_eagerly_at_construction(self):
        runs = FakeRuns(_action())
        with self.assertRaises(ValueError):
            guard_foundry_agent(
                AgentControl(QueueRuntime([])),
                FakeAgentsClient(runs),
                tools={"x": lambda: None},
                mode="not-a-mode",
            )

    async def test_dict_tool_output_when_sdk_models_absent(self):
        runtime = QueueRuntime([_result(), _result()])
        recorder = ToolRecorder()
        runs = FakeRuns(_action(_FakeToolCall("call-1", "search_records", '{"query": "q"}')))
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        with patch(
            "agent_control_specification._adapters.foundry._tool_output_factory", return_value=None
        ):
            await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        output = runs.submitted[0][0]
        self.assertIsInstance(output, dict)
        self.assertEqual(output, {"tool_call_id": "call-1", "output": "rows for q"})

    def test_unsupported_client_surface_raises(self):
        class NotFoundry:
            pass

        with self.assertRaises(AdapterUnsupportedError):
            guard_foundry_agent(AgentControl(QueueRuntime([])), NotFoundry(), tools={"x": lambda: None})

    def test_tools_must_be_callable_mapping(self):
        runs = FakeRuns(_action())
        client = FakeAgentsClient(runs)
        control = AgentControl(QueueRuntime([]))
        with self.assertRaises(AdapterUnsupportedError):
            guard_foundry_agent(control, client, tools={})
        with self.assertRaises(AdapterUnsupportedError):
            guard_foundry_agent(control, client, tools={"x": "not-callable"})


@unittest.skipUnless(_HAS_AZURE_AI_AGENTS, "azure-ai-agents not installed")
class FoundryAdapterLiveTypedTests(unittest.IsolatedAsyncioTestCase):
    async def test_driver_reads_real_required_action_models(self):
        from azure.ai.agents.models import (
            RequiredFunctionToolCall,
            RequiredFunctionToolCallDetails,
            SubmitToolOutputsAction,
            SubmitToolOutputsDetails,
            ToolOutput,
        )

        runtime = QueueRuntime([_result(), _result()])
        recorder = ToolRecorder()
        tool_call = RequiredFunctionToolCall(
            id="call-1",
            function=RequiredFunctionToolCallDetails(
                name="search_records", arguments='{"query": "SELECT 1"}'
            ),
        )
        action = SubmitToolOutputsAction(
            submit_tool_outputs=SubmitToolOutputsDetails(tool_calls=[tool_call])
        )
        runs = FakeRuns(action)
        guarded = guard_foundry_agent(
            AgentControl(runtime), FakeAgentsClient(runs), tools={"search_records": recorder.search_records}
        )

        await guarded.create_thread_and_run("agent-1", content="go", poll_interval=0)

        self.assertEqual(recorder.calls, [("search_records", {"query": "SELECT 1"})])
        output = runs.submitted[0][0]
        self.assertIsInstance(output, ToolOutput)
        self.assertEqual(output.tool_call_id, "call-1")
        self.assertEqual(output.output, "rows for SELECT 1")


if __name__ == "__main__":
    unittest.main()
