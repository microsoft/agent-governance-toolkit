# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Framework Adapters.

Covers: LangGraphAdapter, CrewAIAdapter, AutoGenAdapter, OpenAIAgentsAdapter.
"""

import time

import pytest

from agent_sre.adapters import (
    AutoGenAdapter,
    CrewAIAdapter,
    DifyAdapter,
    LangGraphAdapter,
    OpenAIAgentsAdapter,
    SemanticKernelAdapter,
    TaskRecord,
)


class TestTaskRecord:
    def test_basic(self):
        r = TaskRecord(task_id="t1", framework="test")
        assert r.task_id == "t1"
        assert r.duration_ms == 0.0

    def test_finish(self):
        r = TaskRecord(task_id="t1", framework="test")
        time.sleep(0.01)
        r.finish(success=True)
        assert r.success is True
        assert r.duration_ms > 0


class TestLangGraphAdapter:
    def test_basic_lifecycle(self):
        a = LangGraphAdapter()
        a.on_graph_start(graph_name="rag")
        a.on_node_start("retrieve")
        a.on_node_end("retrieve")
        a.on_node_start("generate")
        a.on_llm_call(input_tokens=100, output_tokens=50, cost_usd=0.003)
        a.on_node_end("generate")
        task = a.on_graph_end(success=True)

        assert task.success
        assert task.steps == 2
        assert task.cost_usd == 0.003
        assert task.input_tokens == 100

    def test_tool_calls(self):
        a = LangGraphAdapter()
        a.on_graph_start()
        a.on_tool_call("search")
        a.on_tool_call("calc", error="timeout")
        a.on_graph_end()

        assert a.tasks[0].tool_calls == 2
        assert a.tasks[0].tool_errors == 1

    def test_sli_snapshot(self):
        a = LangGraphAdapter()
        a.on_graph_start()
        a.on_graph_end(success=True)
        a.on_graph_start()
        a.on_graph_end(success=False, error="timeout")

        snap = a.get_sli_snapshot()
        assert snap["task_success_rate"] == 0.5
        assert snap["framework"] == "langgraph"
        assert snap["total_tasks"] == 2

    def test_multiple_runs(self):
        a = LangGraphAdapter()
        for _i in range(5):
            a.on_graph_start()
            a.on_llm_call(cost_usd=0.01)
            a.on_graph_end(success=True)

        assert len(a.tasks) == 5
        assert a.total_cost_usd == pytest.approx(0.05)
        assert a.task_success_rate == 1.0


class TestCrewAIAdapter:
    def test_basic_lifecycle(self):
        a = CrewAIAdapter()
        a.on_crew_start(crew_name="research", num_agents=2)
        a.on_agent_task("researcher", "Find papers")
        a.on_agent_complete("researcher", success=True, cost_usd=0.05)
        a.on_agent_task("writer", "Write summary")
        a.on_agent_complete("writer", success=True, cost_usd=0.03)
        task = a.on_crew_end(success=True)

        assert task.success
        assert task.steps == 2
        assert task.cost_usd == pytest.approx(0.08)

    def test_tool_use(self):
        a = CrewAIAdapter()
        a.on_crew_start()
        a.on_tool_use("search")
        a.on_tool_use("calc", error="fail")
        a.on_crew_end()

        assert a.tasks[0].tool_calls == 2
        assert a.tasks[0].tool_errors == 1

    def test_sli_snapshot(self):
        a = CrewAIAdapter()
        a.on_crew_start()
        a.on_crew_end(success=True)

        snap = a.get_sli_snapshot()
        assert snap["framework"] == "crewai"


class TestAutoGenAdapter:
    def test_basic_lifecycle(self):
        a = AutoGenAdapter()
        a.on_conversation_start(initiator="user_proxy")
        a.on_message("assistant", "Hello")
        a.on_message("user_proxy", "Help me")
        a.on_function_call("search")
        a.on_llm_call(input_tokens=200, output_tokens=100, cost_usd=0.005)
        task = a.on_conversation_end(success=True)

        assert task.success
        assert task.steps == 2
        assert task.tool_calls == 1
        assert task.cost_usd == 0.005

    def test_function_error(self):
        a = AutoGenAdapter()
        a.on_conversation_start()
        a.on_function_call("search", error="timeout")
        a.on_conversation_end()

        assert a.tool_accuracy == 0.0

    def test_sli_snapshot(self):
        a = AutoGenAdapter()
        a.on_conversation_start()
        a.on_conversation_end(success=True)

        snap = a.get_sli_snapshot()
        assert snap["framework"] == "autogen"


class TestOpenAIAgentsAdapter:
    def test_basic_lifecycle(self):
        a = OpenAIAgentsAdapter()
        a.on_run_start(agent_name="assistant")
        a.on_tool_call("web_search")
        a.on_handoff("assistant", "writer")
        a.on_guardrail_check("content_filter", passed=True)
        a.on_llm_call(input_tokens=300, output_tokens=150, cost_usd=0.01)
        task = a.on_run_end(success=True)

        assert task.success
        assert task.tool_calls == 1
        assert task.steps == 1  # handoff counts as step

    def test_guardrail_tracking(self):
        a = OpenAIAgentsAdapter()
        a.on_run_start()
        a.on_guardrail_check("safety", passed=True)
        a.on_guardrail_check("content", passed=False)
        a.on_guardrail_check("pii", passed=True)
        a.on_run_end()

        snap = a.get_sli_snapshot()
        assert snap["guardrail_pass_rate"] == pytest.approx(2 / 3)

    def test_handoff_tracking(self):
        a = OpenAIAgentsAdapter()
        a.on_run_start()
        a.on_handoff("agent_a", "agent_b")
        a.on_handoff("agent_b", "agent_c")
        a.on_run_end()

        snap = a.get_sli_snapshot()
        assert snap["total_handoffs"] == 2

    def test_sli_snapshot(self):
        a = OpenAIAgentsAdapter()
        a.on_run_start()
        a.on_run_end(success=True)

        snap = a.get_sli_snapshot()
        assert snap["framework"] == "openai_agents"


class TestBaseAdapter:
    def test_clear(self):
        a = LangGraphAdapter()
        a.on_graph_start()
        a.on_graph_end()
        a.clear()
        assert len(a.tasks) == 0

    def test_empty_metrics(self):
        a = LangGraphAdapter()
        assert a.task_success_rate == 0.0
        assert a.total_cost_usd == 0.0
        assert a.avg_duration_ms == 0.0
        assert a.tool_accuracy == 1.0

    def test_no_current_task_error(self):
        a = LangGraphAdapter()
        with pytest.raises(RuntimeError):
            a.on_graph_end()


class TestAdapterSLIIntegration:
    def test_adapter_feeds_slo(self):
        """Demonstrate adapter SLI snapshot feeding into SLO engine."""
        from agent_sre.slo.indicators import CostPerTask, TaskSuccessRate
        from agent_sre.slo.objectives import SLO

        adapter = LangGraphAdapter()

        # Simulate runs
        for i in range(10):
            adapter.on_graph_start()
            adapter.on_llm_call(cost_usd=0.05)
            adapter.on_graph_end(success=(i < 9))  # 90% success

        # Feed into SLI
        adapter.get_sli_snapshot()
        success_sli = TaskSuccessRate(target=0.95)
        cost_sli = CostPerTask(target_usd=0.10)

        for task in adapter.tasks:
            success_sli.record_task(success=task.success)
            cost_sli.record_cost(cost_usd=task.cost_usd)

        SLO(
            name="langgraph-agent",
            indicators=[success_sli, cost_sli],
        )

        assert success_sli._total == 10
        assert cost_sli._task_count == 10


class TestSemanticKernelAdapter:
    def test_basic_lifecycle(self):
        a = SemanticKernelAdapter()
        a.on_kernel_start(kernel_name="my_kernel")
        a.on_plugin_call("search_plugin", "search")
        a.on_function_result("search_plugin", "search", success=True, cost_usd=0.02)
        a.on_plan_step("step_1")
        a.on_llm_call(input_tokens=100, output_tokens=50, cost_usd=0.005)
        task = a.on_kernel_end(success=True)

        assert task.success
        assert task.tool_calls == 1
        assert task.steps == 1
        assert task.cost_usd == pytest.approx(0.025)

    def test_plugin_error(self):
        a = SemanticKernelAdapter()
        a.on_kernel_start()
        a.on_plugin_call("math", "divide", error="division by zero")
        a.on_kernel_end()

        assert a.tasks[0].tool_errors == 1

    def test_sli_snapshot(self):
        a = SemanticKernelAdapter()
        a.on_kernel_start()
        a.on_plugin_call("search", "find")
        a.on_plugin_call("math", "calc")
        a.on_kernel_end(success=True)

        snap = a.get_sli_snapshot()
        assert snap["framework"] == "semantic_kernel"
        assert snap["total_plugin_calls"] == 2


class TestDifyAdapter:
    def test_basic_lifecycle(self):
        a = DifyAdapter()
        a.on_workflow_start(workflow_name="support")
        a.on_node_start("llm_1", node_type="llm")
        a.on_llm_call(input_tokens=200, output_tokens=100, cost_usd=0.005)
        a.on_node_end("llm_1")
        a.on_node_start("tool_1", node_type="tool")
        a.on_tool_call("web_search")
        a.on_node_end("tool_1")
        task = a.on_workflow_end(success=True)

        assert task.success
        assert task.steps == 2
        assert task.tool_calls == 1
        assert task.cost_usd == pytest.approx(0.005)

    def test_http_request(self):
        a = DifyAdapter()
        a.on_workflow_start()
        a.on_http_request("https://api.example.com", status_code=200)
        a.on_http_request("https://api.example.com", status_code=500, error="server error")
        a.on_workflow_end()

        assert a.tasks[0].tool_calls == 2
        assert a.tasks[0].tool_errors == 1

    def test_node_error(self):
        a = DifyAdapter()
        a.on_workflow_start()
        a.on_node_start("n1", node_type="code")
        a.on_node_end("n1", error="syntax error")
        a.on_workflow_end(success=False)

        assert not a.tasks[0].success
        assert a.tasks[0].tool_errors == 1

    def test_sli_snapshot(self):
        a = DifyAdapter()
        a.on_workflow_start()
        a.on_node_start("n1", node_type="llm")
        a.on_node_end("n1")
        a.on_node_start("n2", node_type="tool")
        a.on_node_end("n2")
        a.on_node_start("n3", node_type="llm")
        a.on_node_end("n3")
        a.on_workflow_end(success=True)

        snap = a.get_sli_snapshot()
        assert snap["framework"] == "dify"
        assert snap["node_type_counts"]["llm"] == 2
        assert snap["node_type_counts"]["tool"] == 1
