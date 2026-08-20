# AGENTS.md

## Repository overview

The policy decision runtime now ships from the registry as `agent-control-spec`, rebased on the agent-hooks control contract. This tree is what AGT layers on top of it. `core/` is a deprecation shim that keeps the historical `agent_control_specification_core` symbols importable for one release cycle, and `sdk/rust/` is AGT's host SDK.

Read `docs/acs-retarget.md` before changing anything here.

## Layout

| Path | Purpose |
| --- | --- |
| `core/` | Deprecation shim over `agent-control-spec`, plus the surface that crate does not carry. That surface is artifact validation, the bounded manifest YAML parser, the richer telemetry sinks, and the policy input digest. |
| `sdk/rust/` | AGT's host SDK. Owns the host obligations under AGENT-HOOKS-0.1 sections 8 to 10, which are transform application, `evaluate_only`, approval resolution, and identity. |
| `sdk/python/` | Python SDK. Not yet retargeted. The published `agent-control-spec` Python package exposes only `AcsInterceptor`, so the manifest and artifact validation this SDK is built on has no published equivalent. |
| `sdk/node/` | Node SDK. Same blocker as the Python SDK. |
| `sdk/dotnet/` | .NET SDK over the native core plus framework adapter shapes and tests. |
| `integrations/` | Reference annotators, OpenTelemetry, and Rig integration crates. |
| `generator/` | ACS policy artifact generator. |
| `spec/` | Normative specification and JSON schemas. |
| `docs/` | Design notes, security model, deployment notes, runbooks, and SDK surface guidance. |
| `examples/` | Runnable ACS host examples and generated demo agents. |
| `tests/` | Parity fixtures, formal model, performance harness, and conformance assets. |

## Vocabulary

Use ACS terms when writing issues, docs, tests, and code comments.

- Interception point. The agent-hooks name. `InterventionPoint` is the retired AGT spelling.
- Snapshot.
- Policy input.
- Verdict with `allow`, `deny`, or `transform`. The set is closed at three under AGENT-HOOKS-0.1 section 5.1. A former `warn` is an `allow` carrying `warnings[]`, and a former `escalate` is a liftable `deny` carrying an `approval` block.
- Transform scoped to the policy target. This is the only value changing decision. The effects plane is gone.
- Annotator.
- Manifest with `extends`. Paths root at `$target`, not `$policy_target`.
- Fail closed runtime error. The engine emits `runtime_error:*`. The `host_error:*` namespace is reserved for hosts and an interceptor must never emit it.
- Host approval handling for a liftable `deny`.

Do not introduce predecessor project concepts that ACS removed, and do not reintroduce the five verdict model.

## Build and test

Run the narrow command for the area you changed, then run the broader command before merging when behavior spans SDKs.

| Area | Commands |
| --- | --- |
| Rust workspace | `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` |
| Core example | `cargo run -p agent_control_specification --example basic_host --quiet` |
| Generator | `python -m pip install ./generator pytest` then `pytest generator` |
| Node SDK | `cd sdk/node && npm ci && npm test` |
| .NET SDK | `cd sdk/dotnet && dotnet build AgentControlSpecification.sln` then `dotnet run --project tests/AgentControlSpecification.Tests` |
| Formal model | `quint test tests/formal/acs_mediation.qnt` when Quint is available |
| Rego policies | `cd policy/lib && opa test .` |

OPA backed tests and examples need `opa` on `PATH`. Use `AGENT_CONTROL_REQUIRE_OPA=1` when validating CI parity locally.

## Runtime invariants

- The runtime is stateless. Hosts provide the complete snapshot for every evaluation.
- Runtime errors fail closed to `deny` with a reserved `runtime_error:*` reason.
- A `transform` is the only value changing decision and is scoped to the policy target.
- Applying a transform, honouring `evaluate_only`, resolving approvals, and computing identity are host obligations under AGENT-HOOKS-0.1 sections 8 to 10. They live in `sdk/rust/src/host/`, never in the policy plane.
- Annotator output is isolated under `annotations.<name>`.
- File based `extends` resolution is confined to the top level manifest root.
- Approval identity must bind to the canonical policy input for the action being approved.

## Change rules

- Keep changes focused and avoid unrelated cleanup.
- Pure decision behavior belongs upstream in `agent-control-spec`, not here. File a proposal on that repository rather than forking semantics into `core/`.
- Keep SDK code responsible for host async orchestration and idiomatic adapter shapes.
- Update parity fixtures when a cross SDK contract changes.
- Update specification text only when the normative contract changes.
- Never commit secrets, credentials, or raw sensitive payloads in logs or fixtures.

## Prose style

Documentation prose must be dense and technical. Do not use em dashes. Do not use colons inside prose sentences. Colons are acceptable in headings, tables, code blocks, YAML, and JSON.
