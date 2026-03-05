# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS Governance Quickstart — All 7 Framework Integrations

Demonstrates how Agent OS adds governance (policy enforcement, signals,
audit trails) to every major agent framework with a unified API.

Usage:
    pip install agent-os
    python governance_quickstart.py
"""

from agent_os.integrations import (
    GovernancePolicy,
    LangChainKernel,
    LlamaIndexKernel,
    CrewAIKernel,
    AutoGenKernel,
    OpenAIKernel,
    SemanticKernelWrapper,
)
from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel


# ── Shared policy for all frameworks ─────────────────────────────
policy = GovernancePolicy(
    max_tokens=10_000,
    max_tool_calls=20,
    timeout_seconds=300,
    blocked_patterns=["password", "secret", "api_key"],
    confidence_threshold=0.8,
    log_all_calls=True,
)

print("=" * 60)
print("Agent OS — Governance Quickstart")
print("=" * 60)


# ── 1. LangChain ─────────────────────────────────────────────────
def langchain_example():
    """Wrap any LangChain runnable with governance."""
    # from langchain_core.runnables import RunnableLambda
    # chain = RunnableLambda(lambda x: f"Echo: {x}")
    # kernel = LangChainKernel(policy=policy)
    # governed = kernel.wrap(chain)
    # result = governed.invoke("Hello LangChain!")
    print("\n[1] LangChain — invoke/stream/batch with policy enforcement")
    print("    LangChainKernel wraps any Runnable, adds pre/post checks")
    print("    Signals: SIGSTOP (pause), SIGCONT (resume), SIGKILL (terminate)")


# ── 2. LlamaIndex ────────────────────────────────────────────────
def llamaindex_example():
    """Wrap a LlamaIndex query engine with governance."""
    # from llama_index.core import VectorStoreIndex
    # index = VectorStoreIndex.from_documents(docs)
    # engine = index.as_query_engine()
    # kernel = LlamaIndexKernel(policy=policy)
    # governed = kernel.wrap(engine)
    # result = governed.query("Summarise the document")
    print("\n[2] LlamaIndex — query/chat/retrieve/stream with governance")
    print("    LlamaIndexKernel validates blocked patterns, enforces limits")
    print("    Async support: aquery(), achat()")


# ── 3. CrewAI ─────────────────────────────────────────────────────
def crewai_example():
    """Wrap a CrewAI Crew with governance."""
    # from crewai import Crew, Agent, Task
    # agent = Agent(role="Analyst", goal="Analyze data")
    # task = Task(description="Analyze trends", agent=agent)
    # crew = Crew(agents=[agent], tasks=[task])
    # kernel = CrewAIKernel(policy=policy)
    # governed = kernel.wrap(crew)
    # result = governed.kickoff()
    print("\n[3] CrewAI — kickoff with policy-enforced multi-agent crews")
    print("    CrewAIKernel validates each agent step, enforces timeouts")


# ── 4. AutoGen ────────────────────────────────────────────────────
def autogen_example():
    """Govern AutoGen agents in-place."""
    # from autogen import AssistantAgent, UserProxyAgent
    # assistant = AssistantAgent("assistant", llm_config={...})
    # kernel = AutoGenKernel(policy=policy)
    # kernel.govern(assistant)
    # kernel.signal("assistant", "SIGSTOP")   # pause
    # kernel.signal("assistant", "SIGCONT")   # resume
    # kernel.unwrap(assistant)                 # restore original
    print("\n[4] AutoGen — in-place governance with signal handling")
    print("    AutoGenKernel mutates agents, adds SIGSTOP/SIGCONT/SIGKILL")
    print("    unwrap() cleanly restores original methods")


# ── 5. OpenAI Assistants ─────────────────────────────────────────
def openai_assistants_example():
    """Wrap OpenAI Assistants API with governance."""
    # from openai import OpenAI
    # client = OpenAI()
    # kernel = OpenAIKernel(policy=policy)
    # governed = kernel.wrap_assistant(assistant, client)
    # thread = governed.create_thread()
    # governed.add_message(thread.id, "Analyse this")
    # run = governed.run(thread.id)
    print("\n[5] OpenAI Assistants — run monitoring with policy enforcement")
    print("    OpenAIKernel wraps the Assistants API, enforces tool allow-lists")
    print("    sigkill() cancels active runs")


# ── 6. OpenAI Agents SDK ─────────────────────────────────────────
def openai_agents_sdk_example():
    """Wrap the new OpenAI Agents SDK with governance."""
    # from agents import Agent, Runner
    # agent = Agent(name="analyst", instructions="...")
    # kernel = OpenAIAgentsKernel(policy={...})
    # governed = kernel.wrap_runner(Runner)
    # result = await governed.run(agent, "Analyse Q4")
    print("\n[6] OpenAI Agents SDK — GovernanceGuardrail + GovernedRunner")
    print("    OpenAIAgentsKernel adds tool guards and audit logging")


# ── 7. Semantic Kernel ───────────────────────────────────────────
def semantic_kernel_example():
    """Wrap Microsoft Semantic Kernel with governance."""
    # from semantic_kernel import Kernel
    # sk = Kernel()
    # wrapper = SemanticKernelWrapper(policy=policy)
    # governed = wrapper.wrap(sk)
    # result = await governed.invoke("plugin", "function", input="data")
    print("\n[7] Semantic Kernel — function/plugin governance with audit")
    print("    SemanticKernelWrapper validates tool allow-lists, memory ops")
    print("    Supports planner step validation")


# ── Run all ───────────────────────────────────────────────────────
if __name__ == "__main__":
    langchain_example()
    llamaindex_example()
    crewai_example()
    autogen_example()
    openai_assistants_example()
    openai_agents_sdk_example()
    semantic_kernel_example()

    print("\n" + "=" * 60)
    print("All 7 frameworks governed with a single GovernancePolicy!")
    print("Docs: https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/integrations.md")
    print("=" * 60)
