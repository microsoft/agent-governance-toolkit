"""Multi-adapter ACS demo (Python SDK) against the comprehensive demo manifest."""

import asyncio
import os
import shutil
from pathlib import Path

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    guard_run,
    guard_model_call,
    guard_tool,
)

MANIFEST = Path(__file__).resolve().parent / "manifest.yaml"


def show(tag, value):
    print(f"  {tag:<7} {value}", flush=True)


async def call(label, fn, *args):
    try:
        out = await fn(*args)
        show("ALLOW", f"{label} -> {out!r}")
    except AgentControlBlocked as exc:
        v = exc.result.verdict
        show("DENY", f"{label} -> {v.decision} ({v.reason})")


async def main():
    os.environ.setdefault("ACS_OPA_PATH", shutil.which("opa") or "")
    control = AgentControl.from_path(str(MANIFEST))
    print("PYTHON SDK", flush=True)

    # --- guard_run: input + output intervention points ---
    print("\n[guard_run] generic agent (input/output)")
    agent = guard_run(control, lambda p: f"answer: {p}")
    await call("benign", agent, "hello there")
    await call("deny  ", agent, "do BLOCKME please")
    # transform: SECRET in input is redacted before reaching the agent body
    agent_echo = guard_run(control, lambda p: f"used input: {p}")
    out = await agent_echo("here is my SECRET value")
    show("XFORM", f"secret input -> {out!r}")

    # --- guard_model_call: pre/post model-call points ---
    print("\n[guard_model_call] model wrapper (pre/post model)")
    model = guard_model_call(control, lambda req: {"text": "SECRET model output"})
    out = await model({"prompt": "summarize"})
    show("XFORM", f"secret model response -> {out!r}")

    # --- guard_tool: pre/post tool-call points ---
    print("\n[guard_tool] tool wrappers (pre/post tool)")
    echo = guard_tool(control, "echo_tool", lambda a: {"result": a.get("text", "")})
    await call("echo_tool", echo, {"text": "ping"})
    danger = guard_tool(control, "danger_tool", lambda a: {"result": "x"})
    await call("danger_tool(name-deny)", danger, {"text": "anything"})
    payments = guard_tool(control, "payments_tool", lambda a: {"result": "SECRET receipt"})
    out = await payments({"amount": 10})
    show("XFORM", f"payments_tool secret result -> {out!r}")


if __name__ == "__main__":
    asyncio.run(main())
