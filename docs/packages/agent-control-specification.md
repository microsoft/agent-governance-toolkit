---
title: Agent Control Specification
last_reviewed: 2026-06-02
owner: docs-team
---

# Agent Control Specification

<div align="center" markdown>

**Stateless, deterministic, fail-closed policy decisions for agent security**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/core-Rust-orange.svg)](https://www.rust-lang.org/)

</div>

!!! important "Public Preview"
    Agent Control Specification is vendored into AGT under `policy-engine/` as the
    AGT 5.0 policy layer. APIs and manifest details may change before GA.

## What ACS is

Agent Control Specification, or ACS, is a stateless, deterministic, fail-closed policy decision runtime for agent security. A host submits a complete snapshot plus a policy manifest at each intervention point, and ACS returns a normalized verdict that the host enforces.

The core is pure Rust and exposes native binding surfaces for C-ABI, PyO3, napi, and P-Invoke. AGT includes SDKs for Python, Node.js, .NET, and Rust.

## Intervention-point model

ACS mediates the agent loop by evaluating policy at eight intervention points across this flow.

```text
Input -> Model -> Tool Call -> Tool Result -> Output
```

| Intervention point | When the host calls ACS |
| --- | --- |
| `agent_startup` | Before an agent session starts. |
| `input` | After user or system input is assembled. |
| `pre_model_call` | Before the model receives a prompt or request. |
| `post_model_call` | After the model returns a response. |
| `pre_tool_call` | Before a tool invocation executes. |
| `post_tool_call` | After a tool result is available. |
| `output` | Before final output is returned or published. |
| `agent_shutdown` | Before the agent session is closed. |

Each call includes the full snapshot for that point, so hosts can run ACS without relying on retained runtime state.

## Core properties

| Property | Runtime contract |
| --- | --- |
| Stateless | The runtime retains no mutable state that influences later verdicts. The host supplies the complete snapshot for every call. |
| Deterministic | The same manifest, snapshot, mode, and dispatcher outputs produce the same verdict and transformed policy target. |
| Fail-closed | Runtime errors return `deny`, use a reserved runtime-error reason, and apply no transform. |

## Verdict types

| Verdict | Meaning |
| --- | --- |
| `allow` | The host may proceed with the policy target. |
| `warn` | The host may proceed while recording or surfacing a warning. |
| `deny` | The host must block the action. |
| `escalate` | The host must route the action to an approval backend or fail closed if none is available. |
| `transform` | The host receives a transformed policy target, such as redacted output, and applies it instead of the original target. |

Verdicts may include optional evidence fields that propagate into telemetry.

## Policy types

| Policy type | Runtime behavior |
| --- | --- |
| `rego` | Uses OPA policy evaluation when the OPA dispatcher is enabled and available. |
| `cedar` | Uses the built-in Cedar policy path when the Cedar feature is enabled. |
| `test` | Provides fixed test-double behavior for runtime and conformance tests. |
| `custom` | Calls a host dispatcher identified by adapter configuration. |

The AGT variant replaces upstream effects with the `transform` verdict, adds optional `evidence` fields on verdicts and telemetry, and adds a top-level `approval` section for escalation backends.

## Manifest shape

| Block | Meaning |
| --- | --- |
| `agent_control_specification_version` | Non-empty version string for the manifest contract. |
| `metadata` | Free-form manifest metadata. |
| `extends` | Ordered parent manifest paths or HTTPS URLs. AGT hosts submit the resolved manifest. |
| `policies` | Named policy definitions for `rego`, `cedar`, `test`, or `custom`. |
| `intervention_points` | Closed map keyed by the eight intervention point names. |
| `tools` | Catalog of projected tool metadata, including sink labels and clearances. |
| `annotators` | Named classifier, LLM, or endpoint annotators. |
| `approval` | Escalation backend configuration owned by AGT. |

## Information flow control and telemetry

ACS supports Information Flow Control as a stateless label-flow model. The host tracks provenance and supplies source labels in the snapshot, while manifest tool metadata describes sink labels and clearances.

The Rust core emits structured telemetry through a `TelemetrySink`. Telemetry is content-redacted by default and records stable fields such as decisions, reason codes, error classes, policy IDs, annotator names, modes, durations, and evidence metadata without raw prompts, tool arguments, model output, transform values, secrets, or personal data.

## Where it lives in AGT

ACS is vendored into [`policy-engine/`](../../policy-engine/) as the AGT 5.0 policy layer and is now AGT-owned source. It is the decision-runtime core that backs policy evaluation. Agent OS remains the kernel and host layer that calls into ACS and enforces the verdicts.

## SDKs and specification

| Surface | Path |
| --- | --- |
| Python SDK | [`policy-engine/sdk/python/`](../../policy-engine/sdk/python/) |
| Node.js SDK | [`policy-engine/sdk/node/`](../../policy-engine/sdk/node/) |
| .NET SDK | [`policy-engine/sdk/dotnet/`](../../policy-engine/sdk/dotnet/) |
| Rust SDK | [`policy-engine/sdk/rust/`](../../policy-engine/sdk/rust/) |
| Normative specification | [`policy-engine/spec/SPECIFICATION.md`](../../policy-engine/spec/SPECIFICATION.md) |

The Python SDK distribution is named `agent-control-specification` in `policy-engine/sdk/python/pyproject.toml` and is built with maturin from the vendored source.
