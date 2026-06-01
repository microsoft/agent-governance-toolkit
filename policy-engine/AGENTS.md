# AGENTS.md

## Repository overview

Agent Control Specification is a stateless, deterministic, intervention point policy runtime for agent security. The Rust core owns pure decision logic and exposes C ABI, PyO3, napi, and P/Invoke surfaces through SDKs.

## Layout

| Path | Purpose |
| --- | --- |
| `core/` | Pure Rust runtime, manifest loading, policy input construction, verdict normalization, effects, FFI, and core tests. |
| `sdk/rust/` | Rust SDK crate and examples. |
| `sdk/python/` | Python SDK over the native core plus adapter helpers and tests. |
| `sdk/node/` | Node.js SDK over the native core plus TypeScript adapter helpers and tests. |
| `sdk/dotnet/` | .NET SDK over the native core plus framework adapter shapes and tests. |
| `integrations/` | Reference annotators, OpenTelemetry, and Rig integration crates. |
| `generator/` | ACS policy artifact generator. |
| `spec/` | Normative specification and JSON schemas. |
| `docs/` | Design notes, security model, deployment notes, runbooks, and SDK surface guidance. |
| `examples/` | Runnable ACS host examples and generated demo agents. |
| `tests/` | Parity fixtures, formal model, performance harness, and conformance assets. |

## Vocabulary

Use ACS terms when writing issues, docs, tests, and code comments.

- Intervention point.
- Snapshot.
- Policy input.
- Verdict with `allow`, `warn`, `deny`, or `escalate`.
- Effect scoped to the policy target.
- Annotator.
- Manifest with `extends`.
- Fail closed runtime error.
- Host approval handling for `escalate`.

Do not introduce predecessor project concepts that ACS removed.

## Build and test

Run the narrow command for the area you changed, then run the broader command before merging when behavior spans SDKs.

| Area | Commands |
| --- | --- |
| Rust workspace | `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` |
| Core example | `cargo run -p agent_control_specification --example basic_host --quiet` |
| Python SDK and generator | `python -m pip install ./sdk/python ./generator pytest` then `pytest sdk/python generator` |
| Node SDK | `cd sdk/node && npm ci && npm test` |
| .NET SDK | `cd sdk/dotnet && dotnet build AgentControlSpecification.sln` then `dotnet run --project tests/AgentControlSpecification.Tests` |
| Formal model | `quint test tests/formal/acs_mediation.qnt` when Quint is available |
| Performance harness | `cargo bench -p agent_control_specification_core` when touching hot paths |

OPA backed tests and examples need `opa` on `PATH`. Use `AGENT_CONTROL_REQUIRE_OPA=1` when validating CI parity locally.

## Runtime invariants

- The runtime is stateless. Hosts provide the complete snapshot for every evaluation.
- Runtime errors fail closed to `deny` with a reserved runtime error reason and no effects.
- Effects apply only when the verdict allows effect application.
- Annotator output is isolated under `annotations.<name>`.
- File based `extends` resolution is confined to the top level manifest root.
- Approval identity must bind to the canonical policy input for the action being approved.

## Change rules

- Keep changes focused and avoid unrelated cleanup.
- Put pure decision behavior in `core/` first, then expose it through SDKs.
- Keep SDK code responsible for host async orchestration and idiomatic adapter shapes.
- Update parity fixtures when a cross SDK contract changes.
- Update specification text only when the normative contract changes.
- Never commit secrets, credentials, or raw sensitive payloads in logs or fixtures.

## Prose style

Documentation prose must be dense and technical. Do not use em dashes. Do not use colons inside prose sentences. Colons are acceptable in headings, tables, code blocks, YAML, and JSON.
