from __future__ import annotations

import asyncio

from anthropic import AsyncAnthropic

from agent_control_specification import InterventionPoint, guard_anthropic_client

from _common import assert_blocked, control


async def main() -> None:
    client = AsyncAnthropic(api_key="not-used-pre-model-block")
    guarded = guard_anthropic_client(client, control=control())

    try:
        await guarded.messages.create(
            model="claude-3-5-sonnet-latest",
            max_tokens=8,
            messages=[{"role": "user", "content": "BLOCKME"}],
        )
    except BaseException as exc:
        assert_blocked(exc, InterventionPoint.PRE_MODEL_CALL)
    else:
        raise AssertionError("Anthropic BLOCKME request was not blocked")


if __name__ == "__main__":
    asyncio.run(main())
