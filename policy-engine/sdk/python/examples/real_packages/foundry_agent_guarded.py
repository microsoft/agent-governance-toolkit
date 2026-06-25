"""Govern a live Azure AI Foundry hosted agent run with ACS via guard_foundry_agent.

This is the framework-side companion to ``foundry_agents.py``. That file shows the
policy wiring (an LLM judge that classifies each tool argument) and the two manual
integration styles. This file shows the adapter that removes the manual run-loop
boilerplate. ``guard_foundry_agent`` returns a thin proxy over the real
``AgentsClient`` whose governed driver drives the
``requires_action -> submit_tool_outputs`` loop, routes every required function
tool call through ACS ``pre_tool_call`` and ``post_tool_call``, and submits a
policy rejection output instead of executing on a deny.

It reuses ``build_control`` and ``TOOLS`` from ``foundry_agents`` so the very same
fail-closed judge policy now governs a real hosted agent run rather than an
in-process call. The agent is created without auto function calling, so the model
decides which tool to call and ACS gates each call before the host executes it.

Run it with real credentials set (see ``_common.require_azure`` plus the Foundry
project variables below)::

    export AZURE_OPENAI_ENDPOINT=...          # judge backend, see foundry_agents.py
    export AZURE_OPENAI_API_KEY=...
    export AZURE_OPENAI_DEPLOYMENT=...
    export AZURE_OPENAI_API_VERSION=...
    export AZURE_AI_FOUNDRY_PROJECT_ENDPOINT=...   # https://<res>.services.ai.azure.com/api/projects/<project>
    export AZURE_AI_FOUNDRY_AGENT_MODEL=...         # hosted agent model deployment name
    pip install "agent-control-specification" azure-ai-agents azure-identity
    python foundry_agent_guarded.py

Security invariant. A destructive tool call is never executed. The judge policy
fails closed, so a destructive label, an unexpected label, a missing label, or a
fail-closed transient all deny, and the adapter submits a rejection output for the
denied call so the agent learns it was blocked.
"""

from __future__ import annotations

import asyncio
import os

from _common import require_azure


def require_foundry() -> dict[str, str]:
    """Return the Foundry project settings or raise when any is missing.

    Mirrors ``_common.require_azure`` so the example skips cleanly when the live
    Foundry connection is not configured.
    """

    names = ("AZURE_AI_FOUNDRY_PROJECT_ENDPOINT", "AZURE_AI_FOUNDRY_AGENT_MODEL")
    values = {name: os.environ.get(name, "") for name in names}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise RuntimeError(f"Missing Azure AI Foundry environment variables: {', '.join(missing)}")
    return values


async def main() -> None:
    # azure-ai-agents is an optional dependency. Import it lazily so the example
    # reports a clear skip instead of crashing on import when it is absent.
    try:
        from azure.ai.agents import AgentsClient
        from azure.ai.agents.models import FunctionTool
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:
        print(f"skip: install azure-ai-agents and azure-identity to run this example ({exc})")
        return

    try:
        require_azure()  # the judge backend used by build_control
        foundry = require_foundry()
    except RuntimeError as exc:
        print(f"skip: {exc}")
        return

    from agent_control_specification import AgentControlBlocked, guard_foundry_agent

    # Reuse the exact fail-closed judge policy and callables from the reference.
    from foundry_agents import TOOLS, build_control

    control = build_control()
    function_tools = FunctionTool(set(TOOLS.values()))

    client = AgentsClient(
        endpoint=foundry["AZURE_AI_FOUNDRY_PROJECT_ENDPOINT"],
        credential=DefaultAzureCredential(),
    )

    with client:
        # Create the hosted agent with the tool definitions but WITHOUT enabling
        # auto function calls, so ACS gates each call at the run-loop seam.
        agent = client.create_agent(
            model=foundry["AZURE_AI_FOUNDRY_AGENT_MODEL"],
            name="acs-governed-foundry-agent",
            instructions=(
                "You are a database assistant. Use search_records to read and "
                "run_sql for statements the user explicitly asks for."
            ),
            tools=function_tools.definitions,
        )

        # The governed proxy. enable_auto_function_calls and runs.create_and_process
        # are blocked through this handle, so the auto-call bypass is unreachable.
        guarded = guard_foundry_agent(control, client, tools=TOOLS)

        try:
            run = await guarded.create_thread_and_run(
                agent.id,
                content="Show me the customer named Ada, then delete the audit log.",
                poll_interval=1.0,
            )
            print(f"run finished with status {run.status}")
        except AgentControlBlocked as blocked:
            # Raised only when a post point blocks the result of a call that already
            # ran. A denied pre call is submitted as a rejection, not raised.
            print(f"blocked at {blocked.intervention_point.value}: {blocked.result.verdict.reason}")
        finally:
            client.delete_agent(agent.id)

    print("OK: the Foundry run loop was governed by ACS without the auto-call bypass.")


if __name__ == "__main__":
    asyncio.run(main())
