# `policy-engine/` - AGT policy engine vendored from ACS

This directory is the home of the AGT policy engine. It started as a vendored copy of [`responsibleai/AgentControlSpecification`](https://github.com/responsibleai/AgentControlSpecification) at commit `318dbca` and has since been synced to upstream commit `eeaa83b`. It is being folded into AGT as the AGT 5.0 policy layer.

After the merge, this directory is AGT owned source. The ACS upstream repo will be archived once AGT 5.0 ships. There is no upstream tracking branch.

## Why `policy-engine/` and not `acs/`

The user decision in `architecture-exploration.md` Q9 and Q13 is explicit. ACS becomes the policy layer of AGT and stops existing as a standalone thing. The directory is named for its role inside AGT.

## What the engine provides

The engine provides a stateless and deterministic policy decision runtime for agent security. A host evaluates complete snapshots at intervention points, receives a normalized verdict, and enforces allow, warn, deny, escalate, or transform outcomes.

A single policy artifact covers the full agent loop.

```text
Input -> Model -> Tool Call -> Tool Result -> Output
```

## Core properties

| Property | Runtime contract |
| --- | --- |
| Stateless | The runtime retains no mutable state that influences later verdicts. The host supplies the complete snapshot for every call. |
| Deterministic | The same manifest, snapshot, mode, and dispatcher outputs produce the same verdict and transformed policy target. |
| Fail closed | Runtime failures return `deny`, use a reserved runtime error reason, and apply no transform. |

Security boundaries and host obligations are described in [`docs/security-model.md`](docs/security-model.md). Layer ownership is described in [`docs/architecture.md`](docs/architecture.md).

## Divergences from upstream ACS

Recorded in `spec/acs/SPECIFICATION-AGT.md` when authored in M1.

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
| Original ACS source | MIT licensed by Microsoft contributors at `responsibleai/AgentControlSpecification`. |
| Original ACS license | Preserved at `policy-engine/LICENSE.acs`. |
| Original ACS README | Preserved at `policy-engine/README.vendored-acs.md` for reference. |

## License

ACS is licensed under the MIT License. See `LICENSE` in repository checkouts and `LICENSE.acs` for the vendored source attribution.
