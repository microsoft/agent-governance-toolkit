# ACS Quickstart

Agent Control Specification is a stateless, deterministic policy decision runtime for agent security. A host calls ACS at intervention points with a complete JSON snapshot. ACS returns a verdict, optional effects, and the policy input that produced the decision.

## Prerequisites

- Rust 1.85 or newer.
- Python 3.11 or newer for the Python SDK and generator.
- Node.js 18 or newer for the Node SDK.
- .NET 8 SDK for the .NET SDK.
- OPA on `PATH` for Rego backed examples and tests.

## Build the core

```sh
cargo build
```

## Run the core tests

```sh
cargo test --workspace
```

## Run one mediated activity

The smallest host example lives in [`examples/basic_host.rs`](examples/basic_host.rs). It builds a manifest in memory, dispatches one classifier annotator, evaluates one `input` intervention point, receives a `warn` verdict, and applies a replace effect to the policy target.

```sh
cargo run -p agent_control_specification --example basic_host --quiet
```

Expected output includes a `warn` decision and a redacted policy target.

## Try SDKs

Use the SDK README files for language specific setup.

| SDK | Start here | Local test command |
| --- | --- | --- |
| Rust | [`sdk/rust/Cargo.toml`](sdk/rust/Cargo.toml) | `cargo test -p agent_control_specification` |
| Python | [`sdk/python/README.md`](sdk/python/README.md) | `python -m pip install ./sdk/python pytest && pytest sdk/python` |
| Node.js | [`sdk/node/README.md`](sdk/node/README.md) | `cd sdk/node && npm ci && npm test` |
| .NET | [`sdk/dotnet/README.md`](sdk/dotnet/README.md) | `cd sdk/dotnet && dotnet run --project tests/AgentControlSpecification.Tests` |

## Next steps

- Read the normative spec in [`spec/SPECIFICATION.md`](spec/SPECIFICATION.md).
- Review the security model in [`docs/security-model.md`](docs/security-model.md).
- Study generated end to end examples under [`examples/`](examples/).
- Use [`docs/sdk-surfaces.md`](docs/sdk-surfaces.md) when choosing an SDK surface.
