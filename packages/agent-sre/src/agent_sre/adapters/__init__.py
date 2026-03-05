# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Framework Adapters for Agent-SRE.

Lightweight wrappers that instrument popular agent frameworks
with SLO monitoring, cost tracking, and evaluation.

Adapters:
- LangGraphAdapter: Instrument LangGraph graph executions
- CrewAIAdapter: Instrument CrewAI crew runs
- AutoGenAdapter: Instrument AutoGen agent conversations
- OpenAIAgentsAdapter: Instrument OpenAI Agents SDK runs
- SemanticKernelAdapter: Instrument Microsoft Semantic Kernel
- DifyAdapter: Instrument Dify workflow engine

All adapters are duck-typed — no framework imports required.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TaskRecord:
    """Record of a single agent task execution."""

    task_id: str
    framework: str
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    success: bool = False
    error: str = ""
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    tool_errors: int = 0
    steps: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        if self.ended_at > 0:
            return (self.ended_at - self.started_at) * 1000
        return 0.0

    def finish(self, success: bool = True, error: str = "") -> None:
        self.ended_at = time.time()
        self.success = success
        self.error = error


class BaseAdapter:
    """Base class for framework adapters."""

    def __init__(self, framework: str) -> None:
        self.framework = framework
        self._tasks: list[TaskRecord] = []
        self._current: TaskRecord | None = None
        self._task_counter = 0

    def _start_task(self, metadata: dict[str, Any] | None = None) -> TaskRecord:
        self._task_counter += 1
        task = TaskRecord(
            task_id=f"{self.framework}-{self._task_counter}",
            framework=self.framework,
            metadata=metadata or {},
        )
        self._current = task
        return task

    def _finish_task(self, success: bool = True, error: str = "") -> TaskRecord:
        if self._current:
            self._current.finish(success=success, error=error)
            self._tasks.append(self._current)
            task = self._current
            self._current = None
            return task
        raise RuntimeError("No task in progress")

    @property
    def tasks(self) -> list[TaskRecord]:
        return list(self._tasks)

    @property
    def task_success_rate(self) -> float:
        if not self._tasks:
            return 0.0
        return sum(1 for t in self._tasks if t.success) / len(self._tasks)

    @property
    def total_cost_usd(self) -> float:
        return sum(t.cost_usd for t in self._tasks)

    @property
    def avg_duration_ms(self) -> float:
        durations = [t.duration_ms for t in self._tasks if t.duration_ms > 0]
        return sum(durations) / len(durations) if durations else 0.0

    @property
    def tool_accuracy(self) -> float:
        total = sum(t.tool_calls for t in self._tasks)
        errors = sum(t.tool_errors for t in self._tasks)
        if total == 0:
            return 1.0
        return 1.0 - (errors / total)

    def get_sli_snapshot(self) -> dict[str, Any]:
        """Get current SLI values for integration with SLO engine."""
        return {
            "task_success_rate": self.task_success_rate,
            "total_cost_usd": self.total_cost_usd,
            "avg_duration_ms": self.avg_duration_ms,
            "tool_accuracy": self.tool_accuracy,
            "total_tasks": len(self._tasks),
            "framework": self.framework,
        }

    def clear(self) -> None:
        self._tasks.clear()
        self._current = None
        self._task_counter = 0


class LangGraphAdapter(BaseAdapter):
    """
    Adapter for LangGraph graph executions.

    Usage with LangGraph:
        adapter = LangGraphAdapter()

        # Before graph execution
        adapter.on_graph_start(graph_name="my_rag_graph")

        # During execution (hook into node callbacks)
        adapter.on_node_start("retrieve")
        adapter.on_node_end("retrieve")
        adapter.on_node_start("generate")
        adapter.on_llm_call(input_tokens=100, output_tokens=50, cost_usd=0.003)
        adapter.on_node_end("generate")

        # After execution
        adapter.on_graph_end(success=True)
    """

    def __init__(self) -> None:
        super().__init__("langgraph")
        self._node_count = 0

    def on_graph_start(self, graph_name: str = "", **kwargs: Any) -> TaskRecord:
        self._node_count = 0
        return self._start_task({"graph_name": graph_name, **kwargs})

    def on_node_start(self, node_name: str) -> None:
        if self._current:
            self._current.steps += 1

    def on_node_end(self, node_name: str, error: str = "") -> None:
        if self._current and error:
            self._current.tool_errors += 1

    def on_llm_call(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        if self._current:
            self._current.input_tokens += input_tokens
            self._current.output_tokens += output_tokens
            self._current.cost_usd += cost_usd

    def on_tool_call(self, tool_name: str, error: str = "") -> None:
        if self._current:
            self._current.tool_calls += 1
            if error:
                self._current.tool_errors += 1

    def on_graph_end(self, success: bool = True, error: str = "") -> TaskRecord:
        return self._finish_task(success=success, error=error)


class CrewAIAdapter(BaseAdapter):
    """
    Adapter for CrewAI crew runs.

    Usage with CrewAI:
        adapter = CrewAIAdapter()

        # Before crew kickoff
        adapter.on_crew_start(crew_name="research_crew", num_agents=3)

        # During execution
        adapter.on_agent_task("researcher", "Find latest papers")
        adapter.on_agent_complete("researcher", success=True)
        adapter.on_agent_task("writer", "Write summary")
        adapter.on_agent_complete("writer", success=True)

        # After crew completes
        adapter.on_crew_end(success=True)
    """

    def __init__(self) -> None:
        super().__init__("crewai")
        self._agent_tasks: list[dict[str, Any]] = []

    def on_crew_start(self, crew_name: str = "", num_agents: int = 0) -> TaskRecord:
        self._agent_tasks.clear()
        return self._start_task({"crew_name": crew_name, "num_agents": num_agents})

    def on_agent_task(self, agent_role: str, task_description: str = "") -> None:
        if self._current:
            self._current.steps += 1
            self._agent_tasks.append({
                "agent_role": agent_role,
                "task": task_description,
                "started_at": time.time(),
            })

    def on_agent_complete(
        self,
        agent_role: str,
        success: bool = True,
        cost_usd: float = 0.0,
    ) -> None:
        if self._current:
            self._current.cost_usd += cost_usd
            if not success:
                self._current.tool_errors += 1
            self._current.tool_calls += 1

    def on_tool_use(self, tool_name: str, error: str = "") -> None:
        if self._current:
            self._current.tool_calls += 1
            if error:
                self._current.tool_errors += 1

    def on_crew_end(self, success: bool = True, error: str = "") -> TaskRecord:
        return self._finish_task(success=success, error=error)


class AutoGenAdapter(BaseAdapter):
    """
    Adapter for AutoGen conversations.

    Usage with AutoGen:
        adapter = AutoGenAdapter()

        # Before conversation
        adapter.on_conversation_start(initiator="user_proxy")

        # During conversation
        adapter.on_message("assistant", "Let me help you...")
        adapter.on_message("user_proxy", "Thanks!")
        adapter.on_function_call("search", error="")

        # After conversation
        adapter.on_conversation_end(success=True)
    """

    def __init__(self) -> None:
        super().__init__("autogen")
        self._message_count = 0

    def on_conversation_start(self, initiator: str = "") -> TaskRecord:
        self._message_count = 0
        return self._start_task({"initiator": initiator})

    def on_message(self, sender: str, content: str = "") -> None:
        if self._current:
            self._message_count += 1
            self._current.steps += 1

    def on_function_call(self, function_name: str, error: str = "") -> None:
        if self._current:
            self._current.tool_calls += 1
            if error:
                self._current.tool_errors += 1

    def on_llm_call(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        if self._current:
            self._current.input_tokens += input_tokens
            self._current.output_tokens += output_tokens
            self._current.cost_usd += cost_usd

    def on_conversation_end(self, success: bool = True, error: str = "") -> TaskRecord:
        return self._finish_task(success=success, error=error)


class OpenAIAgentsAdapter(BaseAdapter):
    """
    Adapter for OpenAI Agents SDK.

    Usage with OpenAI Agents:
        adapter = OpenAIAgentsAdapter()

        # Before agent run
        adapter.on_run_start(agent_name="research_agent")

        # During run
        adapter.on_tool_call("web_search")
        adapter.on_handoff("research_agent", "writing_agent")
        adapter.on_guardrail_check("content_filter", passed=True)

        # After run
        adapter.on_run_end(success=True)
    """

    def __init__(self) -> None:
        super().__init__("openai_agents")
        self._handoffs: list[dict[str, str]] = []
        self._guardrail_checks: int = 0
        self._guardrail_failures: int = 0

    def on_run_start(self, agent_name: str = "") -> TaskRecord:
        self._handoffs.clear()
        return self._start_task({"agent_name": agent_name})

    def on_tool_call(self, tool_name: str, error: str = "") -> None:
        if self._current:
            self._current.tool_calls += 1
            if error:
                self._current.tool_errors += 1

    def on_handoff(self, from_agent: str, to_agent: str) -> None:
        if self._current:
            self._current.steps += 1
            self._handoffs.append({"from": from_agent, "to": to_agent})

    def on_guardrail_check(self, guardrail_name: str, passed: bool = True) -> None:
        self._guardrail_checks += 1
        if not passed:
            self._guardrail_failures += 1

    def on_llm_call(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        if self._current:
            self._current.input_tokens += input_tokens
            self._current.output_tokens += output_tokens
            self._current.cost_usd += cost_usd

    def on_run_end(self, success: bool = True, error: str = "") -> TaskRecord:
        return self._finish_task(success=success, error=error)

    def get_sli_snapshot(self) -> dict[str, Any]:
        snapshot = super().get_sli_snapshot()
        snapshot["guardrail_pass_rate"] = (
            1.0 - (self._guardrail_failures / self._guardrail_checks)
            if self._guardrail_checks > 0
            else 1.0
        )
        snapshot["total_handoffs"] = len(self._handoffs)
        return snapshot


class SemanticKernelAdapter(BaseAdapter):
    """
    Adapter for Microsoft Semantic Kernel.

    Usage:
        adapter = SemanticKernelAdapter()
        adapter.on_kernel_start(kernel_name="my_kernel")
        adapter.on_plugin_call("search_plugin", "search", error="")
        adapter.on_function_result("search_plugin", "search", success=True, cost_usd=0.01)
        adapter.on_plan_step("step_1")
        adapter.on_llm_call(input_tokens=100, output_tokens=50, cost_usd=0.005)
        adapter.on_kernel_end(success=True)
    """

    def __init__(self) -> None:
        super().__init__("semantic_kernel")
        self._plugin_calls: list[dict[str, Any]] = []

    def on_kernel_start(self, kernel_name: str = "", **kwargs: Any) -> TaskRecord:
        self._plugin_calls.clear()
        return self._start_task({"kernel_name": kernel_name, **kwargs})

    def on_plugin_call(self, plugin_name: str, function_name: str = "", error: str = "") -> None:
        if self._current:
            self._current.tool_calls += 1
            if error:
                self._current.tool_errors += 1
            self._plugin_calls.append({
                "plugin": plugin_name,
                "function": function_name,
                "error": error,
            })

    def on_function_result(self, plugin_name: str, function_name: str = "",
                           success: bool = True, cost_usd: float = 0.0) -> None:
        if self._current:
            self._current.cost_usd += cost_usd
            if not success:
                self._current.tool_errors += 1

    def on_plan_step(self, step_name: str) -> None:
        if self._current:
            self._current.steps += 1

    def on_llm_call(self, input_tokens: int = 0, output_tokens: int = 0,
                    cost_usd: float = 0.0) -> None:
        if self._current:
            self._current.input_tokens += input_tokens
            self._current.output_tokens += output_tokens
            self._current.cost_usd += cost_usd

    def on_kernel_end(self, success: bool = True, error: str = "") -> TaskRecord:
        return self._finish_task(success=success, error=error)

    def get_sli_snapshot(self) -> dict[str, Any]:
        snapshot = super().get_sli_snapshot()
        snapshot["total_plugin_calls"] = len(self._plugin_calls)
        return snapshot


class DifyAdapter(BaseAdapter):
    """
    Adapter for Dify workflow engine.

    Usage:
        adapter = DifyAdapter()
        adapter.on_workflow_start(workflow_name="customer_support")
        adapter.on_node_start("llm_1", node_type="llm")
        adapter.on_llm_call(input_tokens=200, output_tokens=100, cost_usd=0.005)
        adapter.on_node_end("llm_1")
        adapter.on_node_start("tool_1", node_type="tool")
        adapter.on_tool_call("web_search")
        adapter.on_node_end("tool_1")
        adapter.on_workflow_end(success=True)
    """

    def __init__(self) -> None:
        super().__init__("dify")
        self._node_types: dict[str, str] = {}

    def on_workflow_start(self, workflow_name: str = "", **kwargs: Any) -> TaskRecord:
        self._node_types.clear()
        return self._start_task({"workflow_name": workflow_name, **kwargs})

    def on_node_start(self, node_id: str, node_type: str = "") -> None:
        if self._current:
            self._current.steps += 1
            self._node_types[node_id] = node_type

    def on_node_end(self, node_id: str, error: str = "") -> None:
        if self._current and error:
            self._current.tool_errors += 1

    def on_tool_call(self, tool_name: str, error: str = "") -> None:
        if self._current:
            self._current.tool_calls += 1
            if error:
                self._current.tool_errors += 1

    def on_llm_call(self, input_tokens: int = 0, output_tokens: int = 0,
                    cost_usd: float = 0.0) -> None:
        if self._current:
            self._current.input_tokens += input_tokens
            self._current.output_tokens += output_tokens
            self._current.cost_usd += cost_usd

    def on_http_request(self, url: str, status_code: int = 200, error: str = "") -> None:
        if self._current:
            self._current.tool_calls += 1
            if error or status_code >= 400:
                self._current.tool_errors += 1

    def on_workflow_end(self, success: bool = True, error: str = "") -> TaskRecord:
        return self._finish_task(success=success, error=error)

    def get_sli_snapshot(self) -> dict[str, Any]:
        snapshot = super().get_sli_snapshot()
        snapshot["node_type_counts"] = {}
        for nt in self._node_types.values():
            snapshot["node_type_counts"][nt] = snapshot["node_type_counts"].get(nt, 0) + 1
        return snapshot
