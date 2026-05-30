# `policy-engine/` — AGT policy engine (vendored from ACS)

This directory is the home of the AGT policy engine. It started as a vendored copy of
[`responsibleai/AgentControlSpecification`](https://github.com/responsibleai/AgentControlSpecification)
at commit `318dbca` and is being folded into AGT as the AGT 5.0 policy layer.

After the merge, this directory is **AGT-owned source** — the ACS upstream repo will be
archived once AGT 5.0 ships. There is no upstream-tracking branch.

## Why "policy-engine/" and not "acs/"
The user decision in `architecture-exploration.md` (Q9, Q13) is explicit: ACS becomes the
policy layer of AGT and stops existing as a standalone thing. The directory is named for
its role inside AGT.

## Attribution
- Original ACS source: MIT licensed by Microsoft contributors at `responsibleai/AgentControlSpecification`.
- Original ACS LICENSE preserved at `policy-engine/LICENSE.acs`.
- Original ACS README preserved at `policy-engine/README.vendored-acs.md` for reference.

## Divergences from upstream ACS
Recorded in `spec/acs/SPECIFICATION-AGT.md` (to be authored in M1). Headline divergences:
- **Effects removed from the verdict**, replaced by a `transform` verdict type (Q2).
- **`evidence` field added** to the verdict and to telemetry events (Q4).
- **Cedar promoted to a built-in policy type** (`policies.type` enum now includes `cedar`) (Q10).
- **`approval` top-level manifest section** added for escalation backend configuration (Q13).
- **AGT folder-discovery + scope + merge** layer pre-resolves manifests before they reach this engine (Q6). This engine never sees `extends: [...]` from an AGT host; it always sees a flat, fully-merged manifest.

## Build
The ACS Cargo workspace is now embedded inside the top-level AGT Cargo workspace at
`/home/mhabuomar/code/agt/agent-policy-spec/Cargo.toml`. To build just this engine:

```sh
cd policy-engine
cargo build --workspace
cargo test --workspace
```

The same crates are also reachable from the repo root:

```sh
cd /home/mhabuomar/code/agt/agent-policy-spec
cargo build -p agt_core_engine
cargo test -p agt_core_engine
```

## Layout
| Path | Role |
| --- | --- |
| `core/` | Rust runtime (renamed `agent_control_specification_core` → `agt_core_engine` in M2) |
| `sdk/` | Language SDK bindings (Rust, Python via PyO3, Node via napi, .NET via P/Invoke). Go SDK added in M4. |
| `policy/lib/` | Stock Rego library (and stock Cedar library to be added in M4) |
| `integrations/` | Reference annotators, OTEL bridge, rig adapter |
| `spec/` | Normative ACS-derived spec docs |
| `generator/` | `acs-generate` CLI |
| `examples/` | Reference host implementations |
| `tests/` | Conformance + Quint formal model |
