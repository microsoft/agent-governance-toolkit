# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Foundry execution, Azure AI Evaluation scoring, and governed learning."""

from __future__ import annotations

import asyncio
import os
import secrets

from agent_framework import Agent
from agent_framework.foundry import FoundryChatClient
from agent_learning import (
    Action,
    CaptureConfig,
    InMemoryStore,
    LearningRunner,
    SoftmaxPolicy,
    TaskPolicy,
)
from agent_learning.config import ScoreConfig, ScoreRuntimeConfig
from agent_os.lite import govern
from azure.identity import AzureCliCredential

from agent_learning_gov import (
    GovernedEpisodeCapture,
    GovernedLearningRunner,
    InMemoryAuditSink,
)

PROMPT_STRATEGIES = {
    "concise": "Answer in no more than three sentences.",
    "grounded": "Lead with verifiable evidence and identify any uncertainty.",
}


def _required_environment() -> dict[str, str]:
    names = (
        "FOUNDRY_PROJECT_ENDPOINT",
        "FOUNDRY_MODEL",
        "AGENT_LEARNING_SCORE_ENDPOINT",
        "AGENT_LEARNING_SCORE_DEPLOYMENT",
    )
    values = {name: os.environ.get(name, "") for name in names}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")
    return values


async def main() -> None:
    settings = _required_environment()
    store = InMemoryStore()
    audit = InMemoryAuditSink()
    provenance_key = secrets.token_bytes(32)
    kernel = govern(deny=["unsafe_response_strategy"])
    policy = SoftmaxPolicy.from_actions(
        [Action(id="concise"), Action(id="grounded")],
        agent_id="foundry-agent",
        task_id="answer-question",
    )
    store.store_policy(policy.snapshot())
    capture = GovernedEpisodeCapture(
        kernel,
        config=CaptureConfig(
            enabled=True,
            agent_id="foundry-agent",
            task_id="answer-question",
        ),
        store=store,
        audit_sink=audit,
        provenance_key=provenance_key,
    )
    credential = AzureCliCredential()
    try:
        agent = Agent(
            client=FoundryChatClient(
                project_endpoint=settings["FOUNDRY_PROJECT_ENDPOINT"],
                model=settings["FOUNDRY_MODEL"],
                credential=credential,
            ),
            name="GovernedFoundryAgent",
            instructions="Answer accurately, cite available evidence, and avoid speculation.",
        )
        prompts = [
            "Summarize the incident response process.",
            "Explain how access reviews reduce standing privilege.",
            "Describe a safe credential rotation plan.",
            "Summarize the data retention policy.",
            "Explain why production rollout should use a canary.",
        ]
        for prompt in prompts:
            task_policy = TaskPolicy(policy.snapshot())
            decision = task_policy.adjudicate(task_policy.decide(), "accept")
            context = capture.start(
                prompt,
                decision_result=decision,
                intent_summary="answer an enterprise governance question",
                action_type="response_strategy",
                expected_outcome="return an accurate, relevant, complete answer",
            )
            strategy = PROMPT_STRATEGIES.get(context.action_id)
            if strategy is None:
                raise RuntimeError(f"No executable prompt strategy for {context.action_id!r}")
            try:
                response = await agent.run(f"{strategy}\n\nUser request: {prompt}")
            except Exception as exc:
                capture.end(
                    context,
                    "",
                    execution_status="failed",
                    result_summary=f"Foundry request failed ({type(exc).__name__})",
                )
                raise
            capture.end(
                context,
                response.text or "",
                execution_status="completed",
                result_summary="Foundry returned an answer",
            )

        score_config = ScoreConfig(
            azure_endpoint=settings["AGENT_LEARNING_SCORE_ENDPOINT"],
            azure_deployment=settings["AGENT_LEARNING_SCORE_DEPLOYMENT"],
            credential_mode="azure-cli",
        )
        learning = LearningRunner(
            store=store,
            policy=policy,
            score_config=score_config,
            score_runtime_config=ScoreRuntimeConfig(tier="llm"),
        )
        run = GovernedLearningRunner(
            kernel,
            learning,
            audit_sink=audit,
            provenance_key=provenance_key,
        ).run_offline_batch("foundry-agent", task_id="answer-question")
        print(run.metrics)
    finally:
        credential.close()


if __name__ == "__main__":
    asyncio.run(main())
