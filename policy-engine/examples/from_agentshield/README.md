# AgentShield → ACS example ports

These examples are faithful ports of the policies in the AgentShield repository,
expressed as AgentControlSpecification (ACS) artifacts: a `manifest.yaml` declaring
intervention points + a Rego policy bundle, plus a deterministic `app/run_demo.py`
that drives the **real ACS core + OPA** over crafted snapshots and asserts the
verdict at every gate. They prove the AgentShield policy surface is expressible
("writable") as ACS.

## Validate everything

```bash
# from the repo root, with the ACS python SDK + opa available
PYTHONPATH=generator python examples/from_agentshield/validate_all.py
```

`validate_all.py` is the "writable as ACS" gate. For each port it:
1. JSON-schema-validates the manifest against `spec/schema/manifest.schema.json`.
2. Loads it through the real core (`AgentControl.from_path`) — resolves and parses
   the Rego bundle, proving the core accepts the artifacts.
3. Runs `opa eval` for every intervention point query against a synthetic input
   and asserts a single well-formed verdict object.
4. Runs each port's `app/run_demo.py` and requires `demo verification: PASS`.

> The static OPA step only exercises each policy's **default** branch. The
> per-port demo is what exercises the deny/escalate/warn/effect branches, so every
> demo must demonstrate every non-allow outcome its policy can produce.

## Mapping conventions (AgentShield → ACS)

| AgentShield | ACS |
| --- | --- |
| `resources.tools` | manifest `tools:` map (a tool not declared is **denied** — ACS fails closed) |
| `resources.endpoints` (URL+method allowlist) | a synthetic `http.request` tool at `pre_tool_call`; Rego does allowlist + **default-deny** on unmatched url/method |
| `input_validation.guard_policies` | `input` intervention point (`action: warn` → `warn`, else `deny`) |
| `state_validation.guard_policies` (tools) | `pre_tool_call` |
| `state_validation.guard_policies` (endpoints) | `pre_tool_call` over the `http.request` tool |
| `tool_execution_validation` (LLM judge) | a declared `annotator` (type `llm`/`classifier`) consumed at `pre_tool_call` |
| `variables.on_demand_by: {kind: human}` | `escalate` verdict (host approval resolver decides) |
| `variables.populated_by: {kind: endpoint}` | host-supplied annotation or snapshot field |
| `predicates` (regex) | Rego helper rules (RE2 — **no lookahead/backrefs**) |

### Semantics that must be preserved

- **PASS-condition inversion.** AgentShield `evaluate_when` expressions are *pass*
  conditions: if the expression is false, the guard **blocks**. In Rego, write a
  **total boolean helper** (`object.get(..., null)` for every snapshot/annotation
  read so it never goes undefined) and emit the deny with `not pass_helper`. Never
  rely on an undefined Rego expression to mean "false" — it silently skips the deny.
- **Severity-ordered else-chain.** Multiple guards on one point collapse into one
  `<point>_verdict` `else`-chain ordered **deny → escalate → warn → allow**, keeping
  `default <point>_verdict := {"decision": "allow"}`. This preserves AgentShield's
  "hard block beats approvable write" precedence and avoids OPA complete-rule conflicts.
- **RE2 reformulation, conservatively.** PCRE negative lookahead has no RE2 analogue.
  Reformulate by **extracting each target and classifying it individually**, and when
  you cannot prove every target is safe, **treat it as unsafe** (fail toward deny).
  Never let a single "safe" marker anywhere in a string suppress a match globally.
- **`active_if` is not a pass condition.** A guard with a `reason` but no
  `evaluate_when` is an unconditional block when active — emit deny/warn when the
  resource matches; do **not** invert `active_if`.
- **Stateful variables.** ACS is stateless. A variable populated by a prior tool
  call / endpoint must be represented as a host snapshot field (or a `post_tool_call`
  `result_labels` round-trip), and the port's demo must supply it explicitly.
  Approval `lifetime` other than `per_call` requires a documented host snapshot
  contract; ACS does not persist approval state.

## Not portable as artifacts

The `_shared/mcp_trust_boundary/` fixtures (HTTPS-required, localhost opt-in,
timeout/retry caps, trust-anchor/response-schema/signature checks) assert
AgentShield's *loader/transport* guarantees for resolver connections. ACS delegates
annotator/policy transport to the host, so the core does not enforce these at load.
They are documented in `negative_fixtures/README.md` as host-harness responsibilities
rather than copied into manifests (which would imply guarantees ACS does not make).
