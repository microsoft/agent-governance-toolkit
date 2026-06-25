from __future__ import annotations

import importlib.util
import json
import unittest
from collections import deque
from collections.abc import Mapping
from unittest.mock import patch

from agent_control_specification import (
    AdapterUnsupportedError,
    AgentControl,
    ApprovalOutcome,
    Decision,
    InterventionPoint,
    InterventionPointResult,
    Verdict,
    guard_azure_ai_agents,
    guard_foundry_agent,
)

_HAS_AZURE_AI_AGENTS = importlib.util.find_spec("azure.ai.agents") is not None


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


class FakeAgentsClient:
    def __init__(self, runs):
        self.threads = FakeThreads()
        self.messages = FakeMessages()
        self.runs = runs
        self.enable_auto_calls_called = 0

    def enable_auto_function_calls(self, *args, **kwargs):
        self.enable_auto_calls_called += 1


class ToolRecorder:
    def __init__(self):
        self.calls = []

    def search_records(self, **kwargs):
        self.calls.append(("search_records", dict(kwargs)))
        return f"rows for {kwargs.get('query')}"

    def run_sql(self, **kwargs):
        self.calls.append(("run_sql", dict(kwargs)))
        return f"executed {kwargs.get('query')}"


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
        # The bypass methods are blocked through the governed handle.
        with self.assertRaises(AdapterUnsupportedError):
            guarded.enable_auto_function_calls()
        with self.assertRaises(AdapterUnsupportedError):
            guarded.runs.create_and_process(thread_id="thread-1", agent_id="agent-1")

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
