# Agent Control Specification

Agent Control Specification is a stateless, deterministic policy decision runtime for agent security. A host application acts as the Policy Enforcement Point and calls ACS at defined intervention points with a complete JSON snapshot. ACS acts as the Policy Decision Point and evaluates the bound policy, optional annotations, and policy target scoped effects through a pure logic Rust core with a C ABI and SDK bindings for Rust, Python, Node, and .NET.

| Item | Value |
| --- | --- |
| Status | Alpha and draft |
| Specification version | `0.3.0-alpha` |
| Normative spec | [`spec/SPECIFICATION.md`](spec/SPECIFICATION.md) |
| Threat model | [`docs/security-model.md`](docs/security-model.md) |

## Core properties

| Property | Runtime contract |
| --- | --- |
| Stateless | The runtime retains no mutable state that influences later verdicts. The host supplies the complete snapshot for every call. |
| Deterministic | The same manifest, snapshot, mode, and dispatcher outputs produce the same verdict and transformed policy target. |
| Fail closed | Runtime failures return `deny`, use a reserved runtime error reason, and apply no effect. |

The model is specified in [`spec/SPECIFICATION.md`](spec/SPECIFICATION.md). Security boundaries and host obligations are described in [`docs/security-model.md`](docs/security-model.md).

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

## Quickstart with Rust and Rego

This example is reduced from [`examples/ifc_agent`](examples/ifc_agent). It uses the bundled OPA dispatcher and evaluates one `pre_tool_call` snapshot.

`manifest.yaml`

```yaml
agent_control_specification_version: "0.3.0-alpha"
metadata:
  name: "ifc-agent"
policies:
  ifc_policy:
    type: rego
    bundle: ./policy
    data_paths:
      - ../../policy/lib
    query: data.agent_control_specification.ifc_agent.verdict
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args"
    policy_target_kind: tool_args
    tool_name_from: "$.tool_call.name"
    policy:
      id: ifc_policy
      query: data.agent_control_specification.ifc_agent.pre_tool_call_verdict
tools:
  public_egress:
    type: Tool
    id: public_egress
    clearance: public
    security_labels: [external]
```

`policy/ifc_agent.rego`

```rego
package agent_control_specification.ifc_agent

import data.agent_control_specification.lib.ifc
import rego.v1

default verdict := {"decision": "allow"}

default pre_tool_call_verdict := {"decision": "allow"}

verdict := pre_tool_call_verdict if {
	input.intervention_point == "pre_tool_call"
}

source_labels := object.get(object.get(input.snapshot, "ifc", {}), "source_labels", [])

sink_clearance := object.get(input.tool, "clearance", "")

pre_tool_call_verdict := ifc.verdict(sink_clearance, source_labels) if {
	input.intervention_point == "pre_tool_call"
}
```

Rust host call from [`examples/ifc_agent/demo.rs`](examples/ifc_agent/demo.rs)

```rust
use agent_control_specification::{
    AgentControl, Decision, EnforcementMode, InterventionPoint,
};
use serde_json::json;
use std::{env, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let example_dir = sdk_dir.join("../../examples/ifc_agent").canonicalize()?;
    env::set_current_dir(&example_dir)?;

    // Zero-config construction. The manifest declares a Rego policy bundle and no
    // annotators, so from_path wires the bundled OPA policy dispatcher against the
    // manifest-relative bundle with no host dispatcher code.
    let control = AgentControl::from_path("manifest.yaml")?;

    let denied = control.evaluate_intervention_point(
        InterventionPoint::PreToolCall,
        json!({
            "ifc": {"source_labels": ["confidential"]},
            "tool_call": {
                "name": "public_egress",
                "args": {"body": "customer account balance"}
            }
        }),
        EnforcementMode::Enforce,
    );

    assert_eq!(denied.verdict.decision, Decision::Deny);
    assert_eq!(
        denied.verdict.reason.as_deref(),
        Some("ifc_clearance_violation")
    );

    println!("demo verification: PASS");
    Ok(())
}
```

`from_path` resolves the manifest, wires the bundled OPA policy dispatcher against the manifest-relative Rego bundle, and supplies a default annotator dispatcher, so a host that uses Rego policies needs no dispatcher wiring. A host that needs custom annotation logic or custom policy evaluation supplies its own dispatchers through `AgentControl::from_path_with_dispatchers`. See [Zero-config construction](#zero-config-construction).

Verified command

```sh
cargo run -p agent_control_specification --example ifc_agent --quiet
```

## Zero-config construction

Every SDK exposes a single `from_path` constructor that loads a manifest and wires the bundled dispatchers, so a host that uses Rego policies and either declares no annotators or configures real annotator endpoints integrates in roughly three lines. The bundled OPA policy dispatcher resolves the manifest-relative Rego bundle and shells to a local `opa` binary. The bundled annotator dispatcher routes each annotator by its `type` to the bundled classifier, LLM, or endpoint implementation.

```rust
let control = AgentControl::from_path("manifest.yaml")?;
```

```python
control = AgentControl.from_path("manifest.yaml")
```

```typescript
const control = AgentControl.fromPath("manifest.yaml");
```

```csharp
var control = AgentControl.FromPath("manifest.yaml");
```

Use `from_path` when the manifest uses Rego policies and the annotators either are absent or point at configured endpoints with credentials. Supply custom dispatchers through the `*_with_dispatchers` constructors (Rust) or the optional dispatcher arguments (Python, Node, .NET) when annotators are local, deterministic, mocked, or offline, or when policy outputs need host-specific post-processing. An explicitly supplied dispatcher always overrides the bundled default, and the two dispatchers default independently, so a host can take the bundled OPA policy dispatcher while supplying its own annotator dispatcher.

One constraint follows from the bundled defaults. The bundled classifier, LLM, and endpoint annotators issue network calls, so a zero-config annotator requires a reachable endpoint or provider plus any credentials it needs. Redaction needs no custom dispatcher. A Rego policy emits a `redact` effect with a `pattern` regex or a `values` literal list, and the core resolves it into character-offset spans deterministically before applying it, so pattern-driven and value-driven redaction work under zero-config. The [`support_agent`](examples/support_agent) example shows a Rego policy that redacts PII through pattern `redact` effects with no host span computation.

## Manifest schema overview

| Block | Meaning |
| --- | --- |
| `agent_control_specification_version` | Non empty version string. The current spec describes `0.3.0-alpha`. |
| `metadata` | Free form manifest metadata. |
| `extends` | Ordered parent manifest paths merged before the child manifest. |
| `policies` | Named policy definitions. Supported types are `rego`, `test`, and `custom`. |
| `intervention_points` | Closed map keyed by the eight intervention point names. Each entry binds one policy. |
| `tools` | Catalog of projected tool metadata. Entries accept arbitrary fields including `clearance` and `security_labels`. |
| `annotators` | Declarations for named annotators with type `classifier`, `llm`, or `endpoint`. |

| Intervention point field | Meaning |
| --- | --- |
| `policy_target` | Snapshot path for the value under evaluation. |
| `policy_target_kind` | Optional descriptive label copied into the policy input. |
| `annotations` | Per point opt in map for declared annotators and their `from` paths. |
| `policy` | Binding with `id`, optional `query`, and host defined adapter fields. |
| `tool_name_from` | Snapshot path for current tool name on tool intervention points only. |

Manifest details are in specification sections 9 and 11 and in [`core/src/manifest.rs`](core/src/manifest.rs).

## Policies

| Policy type | Runtime behavior |
| --- | --- |
| `rego` | Prepared as a `RegoPolicyInvocation` and executable with `OpaPolicyDispatcher` when OPA is available. |
| `test` | Fixed test double path for runtime tests. |
| `custom` | Host dispatcher path identified by a required `adapter` string. |

A policy binding selects one policy by `policy.id`. Rego policies require a query either on the policy definition or the binding. The bundled OPA runner calls `opa eval --format json --stdin-input`, passes `bundle` as `--bundle`, and passes `data` or `data_paths` as `--data`.

| Verdict member | Meaning |
| --- | --- |
| `decision` | Required value of `allow`, `deny`, `warn`, or `escalate`. |
| `reason` | Optional low cardinality code. Policy output must not use the runtime error prefix. |
| `message` | Optional host facing text. |
| `effects` | Optional array of policy target scoped effects. |

## Annotators

ACS core declares annotator types and dispatches through host owned implementations. `classifier`, `llm`, and `endpoint` are the supported manifest types. The runtime resolves each point specific `from` path against the preliminary policy input, calls the dispatcher, and writes the returned value only under `annotations.<name>`.

| Integration | Path |
| --- | --- |
| Reference classifier dispatcher | [`integrations/annotators/src/classifier.rs`](integrations/annotators/src/classifier.rs) |
| Reference LLM judge dispatcher | [`integrations/annotators/src/llm.rs`](integrations/annotators/src/llm.rs) |
| Reference endpoint dispatcher | [`integrations/annotators/src/endpoint.rs`](integrations/annotators/src/endpoint.rs) |
| Bundled AACS provider | Feature `aacs`, provider `aacs`, type `AacsProvider` |
| AACS usage example | [`integrations/annotators/examples/live_aacs_classifier.rs`](integrations/annotators/examples/live_aacs_classifier.rs) |

## Extends composition

File based loaders resolve `extends` entries relative to the including manifest, merge parents before children, clear resolved `extends`, and validate the result. Relative paths are confined to the allowed root established by the top level manifest. URL shaped entries with HTTP or HTTPS schemes are rejected. Cycles, missing files, version conflicts, and conflicting duplicate definitions fail closed.

| SDK | Loader entry points |
| --- | --- |
| Rust | `Manifest::from_path`, `Manifest::from_yaml_chain`, `Manifest::merge_chain` |
| Python | `NativeRuntimeClient.from_path`, `NativeRuntimeClient.from_manifest_chain`, native `from_path`, native `from_manifest_chain` |
| Node | `AgentControl.fromPath`, `AgentControl.fromManifestChain`, native `fromPath`, native `fromManifestChain` |
| .NET | `AgentControl.FromPath`, `AgentControl.FromManifestChain`, `NativeAgentControlRuntime.FromPath`, `NativeAgentControlRuntime.FromManifestChain` |

## Information Flow Control

ACS implements IFC as a stateless label flow policy model. The host tracks provenance and supplies source labels in `input.snapshot.ifc.source_labels`. The manifest declares sink metadata in the tool catalog. The reusable Rego library [`policy/lib/ifc.rego`](policy/lib/ifc.rego) defines the default lattice `public < internal < confidential < secret` and denies no write down flows unless sink clearance dominates all source labels.

| IFC path | Role |
| --- | --- |
| `input.snapshot.ifc.source_labels` | Policy input location for host supplied source labels. |
| `input.tool.clearance` | Projected tool sink clearance from the manifest. |
| `input.tool.security_labels` | Projected tool sink labels from the manifest. |
| [`examples/ifc_agent`](examples/ifc_agent) | Runnable Rust and Rego IFC demo. |
| [`docs/ifc-label-flow.md`](docs/ifc-label-flow.md) | Design note for label flow and host responsibilities. |

## Observability

ACS core emits structured telemetry through `TelemetrySink`. Event kinds include `decision`, `annotator_dispatch`, `policy_evaluation`, `evaluation_timing`, `effect_applied`, `annotator_failed`, and `policy_failed`. The OpenTelemetry bridge in [`integrations/otel`](integrations/otel) provides `OtelTelemetrySink` and emits counters such as `acs_intervention_allow_total` plus the `acs_intervention_duration_ms` histogram.

| PerfTelemetry mode | Wire value | Behavior |
| --- | --- | --- |
| `Off` | `0` | No external or stage timing perf events. |
| `External` | `1` | Annotator dispatch and policy evaluation cost events. |
| `Full` | `2` | External events plus per evaluation timing. |

Telemetry defaults are content redacted. Events include stable fields such as `reason_code`, policy id, annotator names, decisions, modes, and durations. Events omit raw policy targets, tool arguments, model output, annotation payloads, secrets, and personal data.

## SDK matrix

| SDK | Native binding | Build or install | Test command |
| --- | --- | --- | --- |
| Rust | Direct Rust crate over `agent_control_specification_core` | `cargo build -p agent_control_specification` | `cargo test -p agent_control_specification --quiet` |
| Python | PyO3 extension built by maturin | `cd sdk/python && python3 -m maturin build --quiet` | `PYTHONPATH=sdk/python python3 -m unittest discover sdk/python/tests` |
| Node | napi-rs addon built by `@napi-rs/cli` | `cd sdk/node && npm install && npm run build` | `cd sdk/node && npm test` |
| .NET | P/Invoke over `libagent_control_specification_core` | `cd sdk/dotnet && dotnet build AgentControlSpecification.sln` | `cd sdk/dotnet && dotnet run --project tests/AgentControlSpecification.Tests/AgentControlSpecification.Tests.csproj` |

## Generator

The generator under [`generator/`](generator/) is a Python CLI named `acs-generate`. It asks an OpenAI compatible language model for a constrained JSON policy plan, builds a manifest and Rego policy from that plan, validates the artifacts, and writes `manifest.yaml`, `policy/<slug>.rego`, and `report.md` to the selected output directory.

```sh
PYTHONPATH=generator python3 -m acs_generator --help
```

```sh
acs-generate \
  --prompt "Deny risky transfers and redact account identifiers" \
  --tool wire_transfer:confidential \
  --out generated/bank-agent
```

The command requires `--prompt` or `--prompt-file`, an output directory, and model configuration through flags or `ACS_GENERATOR_API_BASE`, `ACS_GENERATOR_API_KEY`, `ACS_GENERATOR_MODEL`, and `ACS_GENERATOR_API_VERSION`.

## Examples

| Example | Demonstrates |
| --- | --- |
| [`examples/bank_agent`](examples/bank_agent) | Bank agent fixtures, canonical policy inputs, lifecycle points, tool points, effects, and a stdlib Python demo. |
| [`examples/coding_agent`](examples/coding_agent) | Rust host app, manifest `extends`, OPA policy, approvals, redaction, and streaming aggregation by the host. |
| [`examples/ifc_agent`](examples/ifc_agent) | Stateless IFC label flow with Rust, OPA, and the shared IFC Rego library. |
| [`examples/records_agent`](examples/records_agent) | .NET host app for a medical records assistant with model, tool, output, and approval flows. |
| [`examples/research_agent`](examples/research_agent) | Node host app for web research tools with OPA, annotations, approvals, and redaction. |
| [`examples/support_agent`](examples/support_agent) | Python host app for customer support guardrails with classifier annotations and tool enforcement. |

## Reserved reasons

| Convention | Meaning |
| --- | --- |
| `runtime_error:<code>` | Reserved reason namespace for runtime failures. |

Policies must not emit reasons with that prefix. See specification section 15 for the complete reserved table.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

ACS is licensed under the MIT License. See [`LICENSE`](LICENSE).
