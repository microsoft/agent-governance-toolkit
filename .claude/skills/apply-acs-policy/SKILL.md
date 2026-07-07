---
name: apply-acs-policy
description: >
  Shield an AI agent with Agent Control Specification (ACS) runtime governance.
  Use when the user wants to guard, protect, or apply a control policy to an
  agent at specific intervention points (e.g. "shield my payments agent",
  "deny password reads and escalate wire transfers", "redact account numbers
  from the output"). Generates an ACS manifest and Rego policy with `acs init`,
  validates it, and reports the per-intervention-point verdicts (allow, warn,
  deny, escalate, transform).
---

# Apply an ACS governance policy

You help the user shield an agent with Agent Control Specification (ACS), the
stateless, deterministic, fail-closed policy runtime in `policy-engine/`. You
orchestrate the existing `acs` generator CLI and the ACS SDK. You never
reimplement decision logic, which belongs in the Rust `core/`.

Read `policy-engine/AGENTS.md` for ACS vocabulary and runtime invariants before
suggesting changes.

## When to use

The user wants runtime enforcement over an agent, not an evaluation of it. ACS
mediates the agent loop `Input -> Model -> Tool Call -> Tool Result -> Output`
at eight intervention points and returns a normalized verdict at each. Use this
skill to author a control policy and show what it does.

This skill has two entry modes:

- **Shield mode** — no policy exists yet: gather the threat statement and
  intervention points, generate the manifest and policy (Steps 1-3), then
  report the verdicts (Step 4).
- **Policy Q&A mode** — a generated policy already exists under the output
  directory and the user asks about it ("which points deny?", "why did the wire
  transfer escalate?"). Skip to Step 4 and answer from `manifest.yaml`,
  `policy/<slug>.rego`, and `report.md`.

## The eight intervention points

`agent_startup`, `input`, `pre_model_call`, `post_model_call`, `pre_tool_call`,
`post_tool_call`, `output`, `agent_shutdown`. Guard only the points the user's
threat statement needs. `pre_tool_call` and `post_tool_call` are the tool
points and read the tool name.

## Verdicts

`allow`, `warn`, `deny`, `escalate`, and `transform`. A runtime error fails
closed to `deny` with no transform. `deny` blocks the action, `escalate` routes
to a host approval resolver, `transform` rewrites the mediated value in place
(for example redacting an account id).

## Preconditions (check, don't assume)

1. **ACS generator installed**: `acs --help` succeeds. If not, guide install:
   ```
   python -m pip install ./policy-engine/generator
   ```
2. **Native ACS SDK installed**: `acs init` runs core semantic validation
   through the native runtime, so `agent_control_specification` must import.
   Install it (builds the Rust core via maturin, so a Rust toolchain and a
   platform C linker are required):
   ```
   python -m pip install ./policy-engine/sdk/python
   ```
   If the build fails with a missing linker or Rust toolchain, tell the user
   which toolchain is missing rather than working around it. `acs init` cannot
   complete without this SDK.
3. **OPA for strict validation**: `--strict` validates Rego through OPA and
   requires an `opa` binary on `PATH`. Without OPA, generate without `--strict`
   and tell the user Rego was not evaluated.
3. **Never read or print** `.env`, credentials, or provider keys. The LLM-backed
   `acs --prompt` path reads `ACS_GENERATOR_API_*` variable NAMES only; the
   guided `acs init` path below needs no credentials.

## Steps

### 1. Gather the threat statement and points

Turn the user's request into concrete guided-init inputs:

- `--name` the agent or policy name.
- `--points` the comma-separated intervention points to guard.
- `--tool <name>:<clearance1>,<clearance2>` for each mediated tool. Repeatable.
- `--deny-keyword <word>` for keywords that should deny a policy target.
- `--escalate-tool <name>` for tools that require a human approval route.
- `--redact-output-pattern '<regex>'` to transform matches out of the output.

If the request is vague, ask ONE clarifying question first. Vague threat
statements produce weak policies.

### 2. Generate the manifest and policy

Prefer the deterministic guided path (no credentials required):

```
acs init --non-interactive \
  --name "<agent name>" \
  --points <comma-separated points> \
  --tool <name>:<clearances> \
  --deny-keyword <word> \
  --escalate-tool <name> \
  --redact-output-pattern '<regex>' \
  --sample-test \
  --out build/<slug>
```

This writes `manifest.yaml`, `policy/<slug>.rego`, `report.md`, one
`snapshots/<intervention_point>.json` per point, and a `test_policy.py` smoke
test. The output directory must be empty unless you pass `--force`. Use
`--dry-run` to preview artifacts without writing files.

For a prose-to-policy draft when the user prefers freeform, use
`acs --prompt "<threat statement>" --out build/<slug>` (needs `ACS_GENERATOR_API_*`).

### 3. Show and confirm

Show the generated intervention points from `manifest.yaml` and the verdict
rules summarized in `report.md`. Confirm with the user before treating the
policy as final.

### 4. Validate and report the verdicts

- **Validate**: re-run Step 2 with `--strict` when `opa` is available. Report
  schema and Rego validation results. If OPA is missing, say so plainly.
- **Report** a per-intervention-point verdict table sourced from `report.md`
  and the generated snapshots. Do not invent verdicts. Present it as:

  | Intervention point | Verdict | Reason |
  |---|---|---|
  | pre_tool_call/wire_transfer | escalate | large transfer requires review |
  | output | transform | account id redacted |

- For **Policy Q&A mode**, answer the specific question from `manifest.yaml`,
  `policy/<slug>.rego`, and `report.md` instead of emitting the full table.

### 5. Wire ACS into the host (optional next step)

When the user wants live enforcement in their own agent, point them at the
Python SDK adapters rather than hand-written host code:

```python
from agent_control_specification import AgentControl

control = AgentControl.from_path("build/<slug>/manifest.yaml")
guarded_tool = control.protect_tool(wire_transfer)   # pre/post_tool_call
result = await control.run(agent_fn, user_input)     # input/output
```

Framework adapters exist for LangChain, OpenAI, MCP, LiteLLM proxy, and others.
See `policy-engine/sdk/python/README.md`. For a runnable end-to-end reference,
point the user at `policy-engine/examples/bank_agent`.

## Output format

**Policy summary**:
- Agent/policy name and output directory
- Guarded intervention points
- Mediated tools and their clearances

**Verdict table** (one row per guarded point, from `report.md` and snapshots).

**Validation**: schema OK/FAIL, Rego via OPA OK/FAIL/skipped.

**Suggested next step**: one concrete action (e.g. "add a `post_tool_call`
redaction for SSNs", "wire `control.protect_tool` into the payments tool",
"run the bank_agent example to see enforcement live").

## Guardrails

- **Orchestrate, don't reimplement** — call `acs` and the SDK; never hand-code
  verdict logic. Decision behavior lives in `core/`.
- **Don't invent verdicts** — report only what the generated artifacts show.
- **Fail closed** — ACS denies on runtime error. Never suggest a bypass path.
- **Use ACS vocabulary** — intervention point, snapshot, policy input, verdict,
  effect, manifest with `extends`.
- **Don't read, print, or commit** `.env`, credential values, or build outputs.
- **If the threat statement is vague**, ask one clarifying question FIRST.
