from __future__ import annotations

import asyncio

from semantic_kernel import Kernel
from semantic_kernel.functions import KernelArguments, kernel_function

from agent_control_specification import InterventionPoint, guard_semantic_kernel_function

from _common import assert_blocked, control


class Tools:
    @kernel_function(name="echo")
    def echo(self, value: str) -> str:
        return value


async def main() -> None:
    kernel = Kernel()
    plugin = kernel.add_plugin(Tools(), plugin_name="acs_real")
    guarded = guard_semantic_kernel_function(plugin.functions["echo"], control=control())

    try:
        await guarded.invoke(kernel, KernelArguments(value="BLOCKME"))
    except BaseException as exc:
        assert_blocked(exc, InterventionPoint.PRE_TOOL_CALL)
    else:
        raise AssertionError("Semantic Kernel BLOCKME tool args were not blocked")


if __name__ == "__main__":
    asyncio.run(main())
