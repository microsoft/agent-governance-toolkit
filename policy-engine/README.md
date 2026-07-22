# Agent Control Specification (ACS)

Agent Control Specification, ACS, is the policy layer of the Agent Governance Toolkit. It is a stateless, deterministic, fail closed policy decision runtime for agent security. A host acts as the policy enforcement point and calls ACS at defined intervention points with a complete JSON snapshot. ACS acts as the policy decision point, evaluates the bound policy and optional annotations through a pure logic Rust core, and returns a normalized verdict that the host enforces.

Define once. Enforce everywhere.

ACS lives in this `policy-engine/` directory as AGT owned source. It is folded into AGT as the AGT 5.0 policy layer, and the directory is named for that role inside AGT.

## Why a unified policy layer

Agents no longer only generate text. They retrieve data, call tools, and execute actions across systems, so the governing question becomes who decides what an agent is allowed to do across its whole lifecycle. Today that governance is fragmented. Policies are embedded in prompts, framework hooks, and application code, enforcement is inconsistent across systems, and security teams lack centralized visibility. ACS gives AGT one portable contract for that decision so policy stops being scattered across the stack.

## What ACS is

ACS is a portable, lifecycle aware policy contract for AI agents. A single manifest declares what to validate across input, model, tools, and output, when each policy is evaluated, how decisions are structured and composed, and what evidence is captured for audit. AGT hosts resolve the manifest, build the snapshot at each intervention point, and apply the returned verdict.

## Core idea

A single policy artifact covers the full agent loop.

```text
Input -> Model -> Tool Call -> Tool Result -> Output
```

## Example manifest

```yaml
agent_control_specification_version: "0.3.1-beta"
metadata:
  name: email-agent
policies:
  email_policy:
    type: rego
    bundle: ./policy
    query: data.email_agent.verdict
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args"
    policy_target_kind: tool_args
    tool_name_from: "$.tool_call.name"
    policy:
      id: email_policy
tools:
  send_email:
    type: Tool
    id: send_email
    clearance: internal
```

## How ACS integrates with AGT

AGT is the host and policy enforcement point around the ACS decision core. The integration spans three layers.

| Layer | Role in the integration |
| --- | --- |
| AGT host adapters | Framework adapters in `agent-os` intercept the agent loop, build the snapshot for each intervention point, call the policy layer, and enforce the returned verdict. |
| `agt-policies` bridge | The Python `agt.policies` package mediates between AGT host calls and the ACS runtime and normalizes verdicts for host consumption. |
| ACS native runtime | The `agent_control_specification` Python SDK over the Rust core performs the deterministic decision and is built from `sdk/python` with maturin. |

AGT folder discovery, scope, and merge pre-resolve manifests before the engine evaluates them, so the runtime always receives one fully resolved manifest. Manifest resolution rules live in [`spec/agt/AGT-RESOLUTION-1.0.md`](spec/agt/AGT-RESOLUTION-1.0.md).

## Core properties

| Property | Runtime contract |
| --- | --- |
| Stateless | The runtime retains no mutable state that influences later verdicts. The host supplies the complete snapshot for every call. |
| Deterministic | The same manifest, snapshot, mode, and dispatcher outputs produce the same verdict and transformed policy target. |
| Fail closed | Runtime failures return `deny`, use a reserved runtime error reason, and apply no transform. |

Security boundaries and host obligations are described in [`docs/security-model.md`](docs/security-model.md). The stateless runtime contract is described in [`docs/stateless-runtime.md`](docs/stateless-runtime.md).

## Intervention points

| Intervention point | Use |
| --- | --- |
| `agent_startup` | Evaluate agent or session startup metadata before the run begins. |
| `input` | Evaluate external request ingress before the agent loop begins. |
| `pre_model_call` | Evaluate model request messages, context, and tool definitions before the model call. |
| `post_model_call` | Evaluate the model response before the host acts on it. |
| `pre_tool_call` | Evaluate one concrete tool invocation before execution. |
| `post_tool_call` | Evaluate one concrete tool result before it returns to the agent or caller. |
| `output` | Evaluate the assembled final user visible response. |
| `agent_shutdown` | Evaluate agent or session shutdown metadata and summaries. |

`pre_tool_call` and `post_tool_call` are the only tool intervention points and the only points that accept `tool_name_from`.

## Divergences from upstream ACS

These behaviors are part of the normative [`spec/SPECIFICATION.md`](spec/SPECIFICATION.md), which is the single authoritative contract for this engine. The table below is a quick summary.

| Divergence | AGT contract |
| --- | --- |
| Verdict mutation | Effects are removed and replaced by a `transform` verdict type. |
| Evidence | Verdicts and telemetry carry optional evidence fields. |
| Cedar | `policies.type` includes `cedar` as a built in policy type. |
| Approval | The manifest has a top level `approval` section for escalation backend configuration. |
| Manifest resolution | AGT folder discovery, scope, and merge pre-resolve manifests before this engine sees them. |

## Manifest schema overview

| Block | Meaning |
| --- | --- |
| `agent_control_specification_version` | Non empty version string. The current spec describes `0.3.1-beta`. |
| `metadata` | Free form manifest metadata. |
| `extends` | Ordered parent manifest paths or HTTPS URLs for ACS compatibility. AGT hosts submit the resolved manifest. |
| `policies` | Named policy definitions. Supported types are `rego`, `cedar`, `test`, and `custom`. |
| `intervention_points` | Closed map keyed by the eight intervention point names. Each entry binds one policy. |
| `tools` | Catalog of projected tool metadata. Entries accept arbitrary fields including `clearance` and `security_labels`. |
| `annotators` | Declarations for named annotators with type `classifier`, `llm`, or `endpoint`. |
| `approval` | Escalation backend configuration owned by AGT. |

| Intervention point field | Meaning |
| --- | --- |
| `policy_target` | Snapshot path for the value under evaluation. |
| `policy_target_kind` | Optional descriptive label copied into the policy input. |
| `annotations` | Per point opt in map for declared annotators and their `from` paths. |
| `policy` | Binding with `id`, optional `query`, and host defined adapter fields. |
| `tool_name_from` | Snapshot path for current tool name on tool intervention points only. |

## Policies

| Policy type | Runtime behavior |
| --- | --- |
| `rego` | Prepared as a `RegoPolicyInvocation` and executable with the OPA dispatcher when the `opa` feature is enabled and OPA is available. |
| `cedar` | Prepared as a built in policy invocation when the `cedar` feature is enabled. |
| `test` | Fixed test double path for runtime tests. |
| `custom` | Host dispatcher path identified by a required `adapter` string. |

## Artifact validation

The Rust core exposes `validate_acs_artifacts` and every language SDK delegates
to that implementation. The result shape is identical across Rust, Python,
Node, and .NET, with `valid` plus structured diagnostics for manifest schema,
typed ACS semantics, and OPA Rego parsing.

```rust
use agent_control_specification::validate_acs_artifacts;

let result = validate_acs_artifacts(manifest_yaml, &rego_modules, None);
```

A policy binding selects one policy by `policy.id`. Rego policies require a query either on the policy definition or the binding.

| Verdict member | Meaning |
| --- | --- |
| `decision` | Required value of `allow`, `deny`, `warn`, `escalate`, or `transform`. |
| `reason` | Optional low cardinality code. Policy output must not use the runtime error prefix. |
| `message` | Optional host facing text. |
| `transform` | Optional body required only for `transform` decisions. |
| `evidence` | Optional opaque evidence object propagated to telemetry. |
| `result_labels` | Optional labels that the host can persist with produced data. |

## Annotators

The core declares annotator types and dispatches through host owned implementations. The runtime resolves each point specific `from` path against the preliminary policy input, calls the dispatcher, and writes the returned value only under `annotations.<name>`.

| Integration | Path |
| --- | --- |
| Reference classifier dispatcher | `core/src/dispatchers/classifier.rs` |
| Reference LLM judge dispatcher | `core/src/dispatchers/llm.rs` |
| LLM provider preset guide | [`docs/llm-annotator-providers.md`](docs/llm-annotator-providers.md) |
| Reference endpoint dispatcher | `core/src/dispatchers/endpoint.rs` |

## Information flow control

ACS implements IFC as a stateless label flow policy model. The host tracks provenance and supplies source labels in `input.snapshot.ifc.source_labels`. The manifest declares sink metadata in the tool catalog.

| IFC path | Role |
| --- | --- |
| `input.snapshot.ifc.source_labels` | Policy input location for host supplied source labels. |
| `input.tool.clearance` | Projected tool sink clearance from the manifest. |
| `input.tool.security_labels` | Projected tool sink labels from the manifest. |
| `examples/ifc_agent` | Runnable Rust and Rego IFC demo. |
| [`docs/ifc-label-flow.md`](docs/ifc-label-flow.md) | Design note for label flow and host responsibilities. |

## Observability

The Rust core emits structured telemetry through `TelemetrySink`. Event kinds include `decision`, `annotator_dispatch`, `policy_evaluation`, `evaluation_timing`, `intervention_point.transformed`, `annotator_failed`, and `policy_failed`.

| Perf telemetry mode | Wire value | Behavior |
| --- | --- | --- |
| `Off` | `0` | No external or stage timing perf events. |
| `External` | `1` | Annotator dispatch and policy evaluation cost events. |
| `Full` | `2` | External events plus per evaluation timing. |

Telemetry defaults are content redacted. Events include stable fields such as `reason_code`, error class, action identity, policy id, annotator names, decisions, modes, durations, evidence artefacts, and evidence pointer key names. Events omit raw policy targets, tool arguments, model output, annotation payloads, transform values, evidence pointer URLs, secrets, and personal data.

### Built-in sinks and OpenTelemetry export

Every SDK ships pluggable telemetry sinks so a host can route the redaction-safe event without hand-rolling an audit layer. Each emits one `decision` event per evaluation and converges on the same OpenTelemetry contract, the per-decision counters `acs_intervention_{allow,deny,warn,escalate,transform}_total` and the histogram `acs_intervention_duration_ms` under the meter `agent_control_specification`. A sink that raises is caught and swallowed, so telemetry is never load-bearing.

| SDK | How a sink is installed | OpenTelemetry sink |
| --- | --- | --- |
| Rust | `AgentControl::with_telemetry(Arc<dyn TelemetrySink>)`; built-in `InMemoryTelemetrySink`, `StdoutJsonTelemetrySink`, `MultiSink` | `OtelTelemetrySink` from the `agent_control_specification_otel` crate, added as a dependency |
| Python | `telemetry_sink=` on `AgentControl` and every factory; `InMemoryTelemetrySink`, `JsonStdoutTelemetrySink`, `MultiSink` | `OtelMetricsTelemetrySink`, import-optional on `opentelemetry` |
| Node | `telemetrySink` on `AgentControl` and every factory; `InMemoryTelemetrySink`, `JsonStdoutTelemetrySink`, `MultiSink` | `OtelMetricsTelemetrySink`, import-optional on `@opentelemetry/api` |
| .NET | `telemetrySink` on `AgentControl` and every factory; `InMemoryTelemetrySink`, `JsonStdoutTelemetrySink`, `MultiSink` | `OtelMetricsTelemetrySink` over the BCL `System.Diagnostics.Metrics` meter that OpenTelemetry .NET collects |

In Rust the core owns emission, so installing a sink is enough and the manifest-sourced policy id and annotator names are always present. The Python, Node, and .NET host-side layers build the event from the returned `InterventionPointResult` and read the policy id and annotator names from the fully merged manifest through a native `policy_labels` accessor at construction, so those labels are present for every constructor, including remote and manifest-chain sources.

## SDK matrix

| SDK | Native binding | Artifact install | Artifact smoke |
| --- | --- | --- | --- |
| Rust | Direct Rust crate over the core engine | Add local `.crate` artifacts to a temporary crate with `[patch.crates-io]` paths. | Evaluate one manifest from the temporary host crate. |
| Python | PyO3 extension built by maturin | Install the wheel from `artifacts/` into a temporary virtual environment. | Call `NativeRuntimeClient.from_path` and evaluate one allow and one deny case. |
| Node | napi-rs addon built by `@napi-rs/cli` | Install the `.tgz` package from `artifacts/` into a temporary project. | Call `AgentControl.fromPath` and evaluate one allow and one deny case. |
| .NET | P/Invoke over the core shared library | Restore from the local nupkg source in `artifacts/`. | Call `AgentControl.FromPath` and evaluate one allow and one deny case. |

## Build

The ACS Cargo workspace is embedded inside the top level AGT Cargo workspace. To build just this engine, run the scoped workspace commands from `policy-engine/`.

```sh
cd policy-engine
cargo build --workspace
cargo test --workspace
```

The same crates are also reachable from the repository root through package specific Cargo commands.

```sh
cargo build -p agt_core_engine
cargo test -p agt_core_engine
```

## Layout

| Path | Role |
| --- | --- |
| `core/` | Rust runtime renamed from `agent_control_specification_core` to `agt_core_engine` in M2. |
| `sdk/` | Language SDK bindings for Rust, Python through PyO3, Node through napi, .NET through P/Invoke, and Go added in M4. |
| `policy/lib/` | Stock Rego library and stock Cedar library added in M4. |
| `integrations/` | Reference annotators, OTEL bridge, and Rig adapter. |
| `spec/` | Normative ACS derived spec docs and JSON schemas. |
| `generator/` | `acs-generate` CLI. |
| `examples/` | Reference host implementations. |
| `tests/` | Conformance, parity, and formal model assets. |

## Examples

| Example | Demonstrates |
| --- | --- |
| `examples/README.md` | Example taxonomy, goal based selection, and smoke validation guidance. |
| `examples/bank_agent` | Committed core fixtures, canonical policy inputs, lifecycle points, tool points, transforms, and a stdlib Python demo. |
| `examples/lifecycle_rego` | Full lifecycle mediation with zero config Rego, allow, warn, deny, escalate, approval, and transform based redaction. |
| `examples/custom_dispatchers` | Offline classifier, endpoint, LLM annotator dispatchers, and a custom policy dispatcher. |
| `examples/manifest_extends` | File based manifest composition with inherited policies and workload specific intervention points. |
| `examples/conformance_snapshots` | Fixture driven policy review with named snapshots and expected verdict metadata. |
| `examples/coding_agent` | Rust host app, manifest composition, OPA policy, approvals, redaction, and streaming aggregation by the host. |
| `examples/ifc_agent` | Stateless IFC label flow with Rust, OPA, and the shared IFC Rego library. |

## Reserved reasons

| Convention | Meaning |
| --- | --- |
| `runtime_error:<code>` | Reserved reason namespace for runtime failures. |

Policies must not emit reasons with that prefix. See specification section 15 for the complete reserved table.

## Attribution

| Item | Value |
| --- | --- |
| Original ACS license | Preserved at `policy-engine/LICENSE.acs`. |

## License

ACS is licensed under the MIT License. See `LICENSE` in repository checkouts and `LICENSE.acs` for the vendored source attribution.
