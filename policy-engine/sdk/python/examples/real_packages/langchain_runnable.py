from __future__ import annotations

import asyncio

from langchain_openai import AzureChatOpenAI

from agent_control_specification import InterventionPoint, guard_langchain_runnable

from _common import assert_blocked, control, require_azure


async def main() -> None:
    azure = require_azure()
    runnable = AzureChatOpenAI(
        azure_endpoint=azure["AZURE_OPENAI_ENDPOINT"],
        api_key=azure["AZURE_OPENAI_API_KEY"],
        api_version=azure["AZURE_OPENAI_API_VERSION"],
        azure_deployment=azure["AZURE_OPENAI_DEPLOYMENT"],
        max_tokens=8,
    )
    guarded = guard_langchain_runnable(runnable, control=control())

    try:
        await guarded.ainvoke("BLOCKME")
    except BaseException as exc:
        assert_blocked(exc, InterventionPoint.INPUT)
    else:
        raise AssertionError("LangChain BLOCKME input was not blocked")


if __name__ == "__main__":
    asyncio.run(main())
