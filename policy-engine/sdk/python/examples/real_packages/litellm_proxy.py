from __future__ import annotations

import asyncio

import litellm.proxy.proxy_server as proxy_server

from agent_control_specification import InterventionPoint, guard_litellm_proxy

from _common import assert_blocked, call_asgi, control


async def main() -> None:
    guarded = guard_litellm_proxy(proxy_server.app, control=control())

    try:
        await call_asgi(
            guarded,
            "/chat/completions",
            {"model": "gpt-4o", "messages": [{"role": "user", "content": "BLOCKME"}]},
        )
    except BaseException as exc:
        assert_blocked(exc, InterventionPoint.PRE_MODEL_CALL)
    else:
        raise AssertionError("LiteLLM proxy BLOCKME request was not blocked")


if __name__ == "__main__":
    asyncio.run(main())
