# Governing an Azure AI Foundry agent with ACS

Add fail-closed tool governance to a Python agent running in Azure AI Foundry.
Every tool the model calls is checked by a policy before your code runs it, and a
call the policy rejects is never executed. You copy two policy files and add one
line to your agent.

The worked, runnable version of this is `foundry_agents.py` (policy demo) and
`foundry_agent_guarded.py` (live hosted-agent run) in this directory.

## Prerequisites

```bash
pip install agent-control-specification azure-ai-agents azure-identity
# opa must be on PATH (or ACS_OPA_PATH); the example policy runs a Rego rule
```

The example policy classifies each tool argument with a live model, so it needs
Azure OpenAI credentials and a Foundry project.

```bash
export AZURE_OPENAI_ENDPOINT=...              # https://<resource>.openai.azure.com
export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_DEPLOYMENT=...            # e.g. gpt-4o
export AZURE_OPENAI_API_VERSION=...           # e.g. 2025-04-01-preview
export AZURE_AI_FOUNDRY_PROJECT_ENDPOINT=...  # https://<res>.services.ai.azure.com/api/projects/<project>
export AZURE_AI_FOUNDRY_AGENT_MODEL=...       # hosted agent model deployment name
```

## Step 1. Take the two policy files

Copy these next to your agent. They are the governance contract, kept as data so
you can change what is enforced without a code change.

```
foundry_governance.acs.yaml      # the manifest: which seams are checked, and with what
policy/foundry_tool_guard.rego   # the decision: allow a tool call only when the judge labels it safe
```

You do not need to write these from scratch to get started. The shipped files
deny any tool argument the model judge does not label `safe`, and fail closed if
the judge is unavailable. To change what is enforced, edit the Rego rule and run
`opa test policy`.

Neither file has to live on disk. Load a remote manifest with
`AgentControl.from_url("https://policies.example/foundry_governance.acs.yaml", sha256="<hex>")`,
and reference a remote Rego bundle from the manifest with a pinned `bundle_url`
instead of the local `bundle`.

```yaml
policies:
  tool_guard:
    type: rego
    bundle_url:
      url: https://policies.example/foundry_tool_guard.tar.gz
      sha256: <64-hex digest>
    query: data.agent_control_specification.foundry_tool_guard.verdict
```

A remote manifest or bundle must be pinned with a `sha256` so a swapped policy
cannot silently run.

## Step 2. Wire it into your agent

Load the manifest, then wrap your `AgentsClient` with `guard_foundry_agent`. That
one call routes every tool the model requests through the policy at the run-loop
seam and submits a rejection instead of executing a denied call.

```python
from azure.ai.agents import AgentsClient
from azure.ai.agents.models import FunctionTool
from azure.identity import DefaultAzureCredential
from agent_control_specification import AgentControl, guard_foundry_agent

# Your real tool callables, keyed by the name the model calls.
TOOLS = {"search_records": search_records, "run_sql": run_sql}

control = AgentControl.from_path("foundry_governance.acs.yaml")

client = AgentsClient(endpoint=FOUNDRY_PROJECT_ENDPOINT, credential=DefaultAzureCredential())
with client:
    agent = client.create_agent(
        model=FOUNDRY_AGENT_MODEL,
        name="acs-governed-foundry-agent",
        instructions="You are a database assistant.",
        tools=FunctionTool(set(TOOLS.values())).definitions,
    )

    # The one line that adds governance.
    guarded = guard_foundry_agent(control, client, tools=TOOLS)
    run = await guarded.create_thread_and_run(
        agent.id,
        content="Show me the customer named Ada, then delete the audit log.",
        poll_interval=1.0,
    )
    print(run.status)
```

Create the agent without auto function calling, as above. If Foundry runs the
tool for you, ACS never sees the seam. The guarded handle blocks the auto-call
paths so that bypass is unreachable.

`foundry_governance.acs.yaml` references its Azure endpoint, deployment, and
api_version from the environment, which is why `build_control` in the example
injects them rather than calling `from_path` directly. A deployment with a fixed
endpoint can commit those fields and use the `from_path` one-liner above.

## Run it

```bash
cd policy-engine/sdk/python/examples/real_packages
python foundry_agents.py          # policy demo, no Foundry project needed
python foundry_agent_guarded.py   # a live hosted Foundry agent run
```

When the model asks to delete the audit log, the policy denies and your `run_sql`
callable never runs. A safe read proceeds. That is the guarantee.

## More control

- Invoke tools yourself instead of through the adapter. Use
  `control.protect_tool(name, execute=fn)` for a drop-in guarded callable, or
  `control.evaluate_intervention_point(...)` plus `control.enforce(...)` in your
  own hook. Both are shown in `foundry_agents.py`.
- The language-neutral guide with the Rust, Node, and .NET SDKs is
  [`QUICKSTART.md`](../../../../QUICKSTART.md). The full host surface, including
  approvals for `escalate`, is in
  [`docs/sdk-surfaces.md`](../../../../docs/sdk-surfaces.md).
