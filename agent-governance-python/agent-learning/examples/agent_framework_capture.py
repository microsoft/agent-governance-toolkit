# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Capture Microsoft Agent Framework responses as governed learning episodes."""

from __future__ import annotations

import asyncio
import secrets

from agent_framework import Agent
from agent_framework.openai import OpenAIChatClient
from agent_learning import Action, CaptureConfig, InMemoryStore, SoftmaxPolicy, TaskPolicy
from agent_os.lite import govern

from agent_learning_gov import GovernedEpisodeCapture, InMemoryAuditSink

PROMPT_STRATEGIES = {
    "concise": "Answer in no more than three sentences.",
    "evidence_first": "State the supporting evidence before the recommendation.",
}


async def run_governed_turn(
    agent: Agent,
    task_policy: TaskPolicy,
    capture: GovernedEpisodeCapture,
    prompt: str,
) -> object:
    """Run one Agent Framework turn under an Agent Learning policy decision."""
    decision = task_policy.adjudicate(task_policy.decide(), "accept")
    context = capture.start(
        prompt,
        decision_result=decision,
        intent_summary="answer a support question",
        action_type="prompt_strategy",
        expected_outcome="return a useful and policy-compliant answer",
    )
    strategy = PROMPT_STRATEGIES.get(context.action_id)
    if strategy is None:
        raise RuntimeError(f"No executable prompt strategy for {context.action_id!r}")
    try:
        response = await agent.run(f"{strategy}\n\nUser request: {prompt}")
        return capture.end(
            context,
            response.text or "",
            execution_status="completed",
            result_summary="Agent Framework returned an answer",
        )
    except Exception:
        capture.end(
            context,
            "",
            execution_status="failed",
            result_summary="Agent Framework execution failed",
        )
        raise


async def main() -> None:
    store = InMemoryStore()
    audit = InMemoryAuditSink()
    provenance_key = secrets.token_bytes(32)
    kernel = govern(deny=["untrusted_prompt_strategy"])
    policy = SoftmaxPolicy.from_actions(
        [Action(id="concise"), Action(id="evidence_first")],
        agent_id="framework-agent",
        task_id="answer-support-question",
    )
    store.store_policy(policy.snapshot())
    capture = GovernedEpisodeCapture(
        kernel,
        config=CaptureConfig(
            enabled=True,
            agent_id="framework-agent",
            task_id="answer-support-question",
        ),
        store=store,
        audit_sink=audit,
        provenance_key=provenance_key,
    )
    agent = Agent(
        client=OpenAIChatClient(),
        name="GovernedSupportAgent",
        instructions="Answer support questions accurately and concisely.",
    )

    episode = await run_governed_turn(
        agent,
        TaskPolicy(policy.snapshot()),
        capture,
        "How do I rotate an application credential?",
    )
    print(f"captured episode {episode.id} with action {episode.action_id}")


if __name__ == "__main__":
    asyncio.run(main())
