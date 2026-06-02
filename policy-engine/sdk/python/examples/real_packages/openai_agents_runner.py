from __future__ import annotations

import asyncio

from agents import Agent, Runner
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncAzureOpenAI

from agent_control_specification import InterventionPoint, guard_openai_agents_runner

from _common import assert_blocked, control, require_azure


async def main() -> None:
    azure = require_azure()
    client = AsyncAzureOpenAI(
        azure_endpoint=azure["AZURE_OPENAI_ENDPOINT"],
        api_key=azure["AZURE_OPENAI_API_KEY"],
        api_version=azure["AZURE_OPENAI_API_VERSION"],
        azure_deployment=azure["AZURE_OPENAI_DEPLOYMENT"],
    )
    agent = Agent(
        name="acs-real-openai-agent",
        model=OpenAIChatCompletionsModel(
            model=azure["AZURE_OPENAI_DEPLOYMENT"],
            openai_client=client,
        ),
    )
    guarded = guard_openai_agents_runner(Runner, control=control())

    try:
        await guarded.run(agent, "BLOCKME", max_turns=1)
    except BaseException as exc:
        assert_blocked(exc, InterventionPoint.INPUT)
    else:
        raise AssertionError("OpenAI Agents BLOCKME input was not blocked")


if __name__ == "__main__":
    asyncio.run(main())
