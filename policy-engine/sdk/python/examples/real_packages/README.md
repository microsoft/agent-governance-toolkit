# Real-package integration examples

Runnable references that wire ACS governance into genuine third-party agent
frameworks. They are deliberately **not** mocked: each imports the real package
and most make real Azure OpenAI calls, so they double as live smoke tests.

## Prerequisites

Set real Azure OpenAI credentials (read by `_common.require_azure`, either from
the environment or a `.env` at the `policy-engine/` root):

```bash
export AZURE_OPENAI_ENDPOINT=...        # https://<resource>.openai.azure.com
export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_DEPLOYMENT=...       # e.g. gpt-4o / gpt-5.x
export AZURE_OPENAI_API_VERSION=...      # e.g. 2025-04-01-preview
```

Install the ACS SDK plus the framework you want to exercise. The optional
`realpkg-tests` extra pulls in every framework used here:

```bash
pip install "agent-control-specification" azure-ai-agents
# or, for all examples:  pip install -e ".[realpkg-tests]"
```

Run an example directly from this directory (so `_common` resolves):

```bash
cd policy-engine/sdk/python/examples/real_packages
python foundry_agents.py
```

## Azure AI Foundry Agents (`foundry_agents.py`)

Shows how a production user gates a Foundry agent's tool calls with ACS. It
builds real `FunctionTool` definitions from the `azure-ai-agents` SDK and governs
the tool-execution seam with a policy backed by a **live Azure OpenAI LLM judge**
(no canned verdicts). The host policy fails closed: it allows only an explicit
"safe" verdict, so a destructive, unexpected, or missing label denies. Two
integration styles for the same seam:

- **Short path**: `control.protect_tool(name, execute=fn)` returns a drop-in
  async wrapper that evaluates `PRE_TOOL_CALL` and `POST_TOOL_CALL`, applies any
  transform, and raises `AgentControlBlocked` on a deny.
- **Long path**: call `control.evaluate_intervention_point(...)` yourself and
  branch on `verdict.decision` (allow / deny / escalate / transform). This is the
  shape you drop into a framework's own auto-function-call hook.

The example judges tool input on `PRE_TOOL_CALL`; it does not bind a judge on
`POST_TOOL_CALL`, so output is evaluated but not gated (that is where output
governance would attach). The judge sees untrusted argument text and is subject
to prompt injection, so treat it as defense in depth behind deterministic policy.

To wire it into a live Foundry agent run, register the same callables with
`FunctionTool`/`ToolSet` and route the SDK's function-invocation hook through
`protect_tool`, so every tool the agent decides to call is gated first.

The manifest is built in-process so the Azure endpoint comes from the environment
and the API key is referenced by name (`api_key_env`), never written to disk. In
production load a committed manifest with `AgentControl.from_path(...)` or a
pinned remote one with `AgentControl.from_url(...)`.
