from __future__ import annotations

import asyncio

from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import AzureOpenAIChatCompletionClient

from agent_control_specification import InterventionPoint, guard_autogen_agent

from _common import assert_blocked, control, require_azure


async def main() -> None:
    azure = require_azure()
    model_client = AzureOpenAIChatCompletionClient(
        azure_endpoint=azure["AZURE_OPENAI_ENDPOINT"],
        api_key=azure["AZURE_OPENAI_API_KEY"],
        api_version=azure["AZURE_OPENAI_API_VERSION"],
        azure_deployment=azure["AZURE_OPENAI_DEPLOYMENT"],
        model=azure["AZURE_OPENAI_DEPLOYMENT"],
        model_info={
            "vision": False,
            "function_calling": True,
            "json_output": True,
            "family": "unknown",
            "structured_output": True,
        },
    )
    agent = AssistantAgent("acs_real_autogen", model_client=model_client)
    guarded = guard_autogen_agent(agent, control=control())

    try:
        await guarded.run(task="BLOCKME")
    except BaseException as exc:
        assert_blocked(exc, InterventionPoint.INPUT)
    else:
        raise AssertionError("AutoGen BLOCKME task was not blocked")


if __name__ == "__main__":
    asyncio.run(main())
