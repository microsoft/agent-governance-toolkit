from __future__ import annotations

import asyncio

from openai import AsyncAzureOpenAI

from agent_control_specification import InterventionPoint, guard_openai_client

from _common import assert_blocked, control, require_azure


async def main() -> None:
    azure = require_azure()
    client = AsyncAzureOpenAI(
        azure_endpoint=azure["AZURE_OPENAI_ENDPOINT"],
        api_key=azure["AZURE_OPENAI_API_KEY"],
        api_version=azure["AZURE_OPENAI_API_VERSION"],
        azure_deployment=azure["AZURE_OPENAI_DEPLOYMENT"],
    )
    guarded = guard_openai_client(client, control=control())

    response = await guarded.chat.completions.create(
        model=azure["AZURE_OPENAI_DEPLOYMENT"],
        messages=[{"role": "user", "content": "Reply with exactly ACS_OK"}],
        max_completion_tokens=16,
    )
    if not response.choices:
        raise AssertionError("guarded Azure OpenAI call returned no choices")

    try:
        await guarded.chat.completions.create(
            model=azure["AZURE_OPENAI_DEPLOYMENT"],
            messages=[{"role": "user", "content": "BLOCKME"}],
            max_completion_tokens=16,
        )
    except BaseException as exc:
        assert_blocked(exc, InterventionPoint.PRE_MODEL_CALL)
    else:
        raise AssertionError("OpenAI BLOCKME request was not blocked")


if __name__ == "__main__":
    asyncio.run(main())
