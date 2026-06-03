"""Live end-to-end ACS demo: real YAML manifest + Rego policy + OPA, driven
through the high-level guard_* adapters (no manual intervention-point calls).

Run from policy-engine/sdk/python with ACS_OPA_PATH pointing at the opa binary.
"""

import asyncio
import shutil
import os
from pathlib import Path

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    guard_run,
    guard_tool,
)

ROOT = Path(__file__).resolve().parents[2]  # policy-engine/
MANIFEST = ROOT / "tests" / "fixtures" / "smoke" / "manifest.yaml"


def line(s: str) -> None:
    print(s, flush=True)


async def main() -> None:
    os.environ.setdefault("ACS_OPA_PATH", shutil.which("opa") or "")
    line(f"manifest : {MANIFEST}")
    line(f"opa      : {os.environ.get('ACS_OPA_PATH')}")
    line(f"opa ver  : ok\n")

    # Load the real manifest (binds 8 intervention points to the Rego bundle).
    control = AgentControl.from_path(str(MANIFEST))

    # --- Tier 3 style: wrap a plain agent fn; input+output enforced for us ---
    async def my_agent(prompt):
        return f"echo: {prompt}"

    guarded_agent = guard_run(control, my_agent)

    line("== guard_run (input + output IPs) ==")
    out = await guarded_agent("hello world")
    line(f"[ALLOW] benign prompt -> {out!r}")

    try:
        await guarded_agent("please BLOCKME now")
    except AgentControlBlocked as exc:
        v = exc.result.verdict
        line(f"[DENY ] sentinel prompt -> decision={v.decision} reason={v.reason}")

    # --- Tool adapter: pre/post tool-call IPs, incl. tool-name-based deny ---
    async def echo_tool(args):
        return {"result": args.get("text", "")}

    line("\n== guard_tool: echo_tool (benign tool) ==")
    safe_tool = guard_tool(control, "echo_tool", echo_tool)
    res = await safe_tool({"text": "ping"})
    line(f"[ALLOW] echo_tool -> {res!r}")

    line("\n== guard_tool: danger_tool (denied by Rego on tool name) ==")
    danger = guard_tool(control, "danger_tool", echo_tool)
    try:
        await danger({"text": "anything"})
    except AgentControlBlocked as exc:
        v = exc.result.verdict
        line(f"[DENY ] danger_tool -> decision={v.decision} reason={v.reason}")

    line("\n== guard_tool: echo_tool with BLOCKME args (denied on sentinel) ==")
    try:
        await safe_tool({"text": "BLOCKME"})
    except AgentControlBlocked as exc:
        v = exc.result.verdict
        line(f"[DENY ] echo_tool+sentinel -> decision={v.decision} reason={v.reason}")

    line("\nDONE")


if __name__ == "__main__":
    asyncio.run(main())
