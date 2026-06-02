from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP

from agent_control_specification import InterventionPoint, guard_mcp_server

from _common import assert_blocked, control


async def main() -> None:
    server = FastMCP("acs-real-mcp")

    @server.tool()
    def echo(value: str) -> str:
        return value

    guarded = guard_mcp_server(server, control=control())

    try:
        await guarded.call_tool("echo", {"value": "BLOCKME"})
    except BaseException as exc:
        assert_blocked(exc, InterventionPoint.PRE_TOOL_CALL)
    else:
        raise AssertionError("MCP BLOCKME tool args were not blocked")


if __name__ == "__main__":
    asyncio.run(main())
