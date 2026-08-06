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
"safe" verdict, so a destructive, unexpected, or missing label denies.

### The three files that make up the integration

This is the minimal shape of a real ACS integration. The governance contract is
committed as data, not assembled in Python.

| File | Role |
|------|------|
| `foundry_governance.acs.yaml` | The ACS manifest. Declares the intervention points, the live Azure OpenAI `intent_judge` annotator, and the policy binding. |
| `policy/foundry_tool_guard.rego` | The deterministic decision. Reads `annotations.intent_judge.label` and fails closed, allowing only a `safe` label. `policy/foundry_tool_guard_test.rego` proves it with `opa test policy`. |
| `foundry_agents.py` | The host. Loads the manifest, drives the Foundry run loop, and enforces each verdict at the tool-call seam. |

The Rego policy runs through OPA, so `opa` must be on `PATH` (or `ACS_OPA_PATH`)
in addition to the Azure credentials above.

### Write your own integration

See [`FOUNDRY_INTEGRATION.md`](FOUNDRY_INTEGRATION.md) for a standalone,
beginner-friendly walkthrough of adding ACS governance to a Python agent running
in Azure AI Foundry. It explains the manifest, the Rego policy, and the host
wiring from scratch, and it is written to hand to a developer new to ACS.

### Two host integration styles for the same seam

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

The Azure resource endpoint, deployment, and api_version are per-deployment
configuration, so `build_control` injects them into the committed manifest from
the environment at load. The API key is referenced by name (`api_key_env`) and
never written to disk. A deployment whose endpoint is fixed can commit those
fields directly and load with `AgentControl.from_path(...)`, or pin a remote
manifest with `AgentControl.from_url(...)`.

## Host-side telemetry export (`telemetry.py`)

Shows the pure-Python telemetry layer. A single governed `control.run()` emits
one redaction-safe `TelemetryEvent` per intervention point to a `MultiSink` that
fans out to a JSON Lines audit sink, an in-memory sink, and, when
`opentelemetry` is installed, an `OtelMetricsTelemetrySink` that exports the same
`acs_intervention_*` metrics as the Rust `agent_control_specification_otel` crate.
Unlike the other examples it needs no Azure credentials and no third-party
framework, only the native binding, so it runs as a self-contained smoke test.

```bash
cd policy-engine/sdk/python/examples/real_packages
python telemetry.py
```

The printed JSON Lines carry decision, reason code, policy id, duration, and
action identity only. The governed input and output payloads never appear, which
is the redaction invariant the sink layer guarantees.
