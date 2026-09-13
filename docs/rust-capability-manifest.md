---
title: "Rust Capability and Ownership Manifest"
last_reviewed: 2026-08-18
owner: agt-maintainers
---

# Rust Capability and Ownership Manifest

This manifest records the current AGT Rust capability surface, the repository
that owns each gap, and the evidence needed to change a status. It is a
source-backed inventory, not a certification, compliance statement, or
production-readiness claim.

The evidence baseline is AGT commit
[`7d0cef5`](https://github.com/microsoft/agent-governance-toolkit/commit/7d0cef5d9820a865c3c19b07bd39ecf7053b58a1),
agent-hooks commit
[`8a06c9d`](https://github.com/responsibleai/agent-hooks/commit/8a06c9defab04f811c92902160f95bcb380aab56),
and ACS commit
[`6d71fe9`](https://github.com/responsibleai/agent-control-spec/commit/6d71fe9a16bcd6bf307147f3d90aa2949ce2646d).
Recheck source, tests, trackers, and upstream specifications before updating a
row.

## Evidence rules

Allowed states: `shipped`, `partial`, `missing`, `blocked`, and `deferred`.

| Status | Required evidence |
|---|---|
| `shipped` | The complete capability in the row's stated scope exists on current main. The row links an applicable normative artifact, or says `N/A` with a reason, and links implementation plus a behavioral test or official conformance vector. A public type, example, or documentation page alone is insufficient. |
| `partial` | A useful implemented subset exists, but a named workflow, enforcement boundary, packaging path, or evidence requirement is incomplete. The row links the existing evidence, the limitation, and a tracker. |
| `missing` | No current Rust implementation satisfies the capability. The row names one owning repository and a tracker. |
| `blocked` | The intended work cannot complete until a named external decision or prerequisite is resolved. The row links the blocker and tracker. |
| `deferred` | The capability is intentionally unscheduled pending a named ownership, demand, or sequencing decision. The row gives one present owner for that decision and a tracker. |

Every row has exactly one current owner. Contract changes to agent context,
verdicts, approval, composition, interception records, or the CTK belong in
[`responsibleai/agent-hooks`](https://github.com/responsibleai/agent-hooks).
Changes to ACS manifests, evaluation, dispatchers, effects, or interceptor
semantics belong in
[`responsibleai/agent-control-spec`](https://github.com/responsibleai/agent-control-spec).
AGT owns its CLI, audit, replay, compliance, dashboards, SRE workflows, and
AGT integrations. An AGT integration may consume canonical contracts; it must
not fork them.

## Source precedence

Use the first applicable source in this order:

1. normative specifications and machine-readable schemas;
2. official conformance vectors and reports;
3. the canonical Rust implementation and its behavioral tests;
4. AGT integration source and behavioral tests; and
5. Python only as a UX or workflow exemplar when the higher-precedence
   sources are silent.

The canonical host contract is
[AGENT-HOOKS-0.1](https://github.com/responsibleai/agent-hooks/blob/8a06c9defab04f811c92902160f95bcb380aab56/spec/AGENT-HOOKS-0.1.md),
with its
[schemas](https://github.com/responsibleai/agent-hooks/tree/8a06c9defab04f811c92902160f95bcb380aab56/spec/schema)
and
[CTK vectors](https://github.com/responsibleai/agent-hooks/tree/8a06c9defab04f811c92902160f95bcb380aab56/conformance/vectors).
The canonical policy-interceptor contract is the
[ACS specification](https://github.com/responsibleai/agent-control-spec/blob/6d71fe9a16bcd6bf307147f3d90aa2949ce2646d/spec/SPECIFICATION.md)
and
[manifest schema](https://github.com/responsibleai/agent-control-spec/blob/6d71fe9a16bcd6bf307147f3d90aa2949ce2646d/spec/schema/manifest.schema.json),
with its
[runtime coverage](https://github.com/responsibleai/agent-control-spec/blob/6d71fe9a16bcd6bf307147f3d90aa2949ce2646d/tests/conformance/coverage.md)
and
[agent-hooks report](https://github.com/responsibleai/agent-control-spec/blob/6d71fe9a16bcd6bf307147f3d90aa2949ce2646d/conformance/agent-hooks/REPORT.md).

## Current and proposed architecture

Current AGT main contains an embedded ACS 0.3.1-beta workspace and AGT-owned
Rust integrations. The `agentmesh` operator CLI currently evaluates the
crate's local rule-based `PolicyEngine`; it does not establish an
AGENT-HOOKS-0.1 host-conformance claim or imply ACS 0.4 behavior.

[PR #3561](https://github.com/microsoft/agent-governance-toolkit/pull/3561)
proposes replacing the embedded engine with the published ACS 0.4 runtime and
agent-hooks host contract. That PR is open, has requested changes, and is
blocked on
[responsibleai/agent-control-spec#24](https://github.com/responsibleai/agent-control-spec/issues/24).
Nothing in the conditional architecture is classified as current AGT main
until the prerequisite and PR are resolved.

## Rust capability inventory

### Core, operator, and SRE capabilities

| Capability | Status | Owner | Canonical contract or exemplar | Current implementation and evidence | Limitation and tracker |
|---|---|---|---|---|---|
| Core `agentmesh` governance primitives | `partial` | `microsoft/agent-governance-toolkit` | `N/A` for AGT-owned identity, trust, audit, MCP, rings, and lifecycle primitives; ACS applies where an AGT 5 policy interceptor is claimed | [`agentmesh` modules](../agent-governance-rust/agentmesh/src/lib.rs) and [behavioral tests](../agent-governance-rust/agentmesh/tests/) | Implemented primitives do not by themselves establish workflow, host-conformance, or operational parity. Trackers: [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680), [#3083](https://github.com/microsoft/agent-governance-toolkit/issues/3083), [#3084](https://github.com/microsoft/agent-governance-toolkit/issues/3084), [#2986](https://github.com/microsoft/agent-governance-toolkit/issues/2986), and [#3521](https://github.com/microsoft/agent-governance-toolkit/issues/3521). |
| Published ACS 0.4 and agent-hooks adoption in AGT | `blocked` | `microsoft/agent-governance-toolkit` | Canonical ACS specification, schema, coverage, and agent-hooks CTK report linked above | Current main remains on the [embedded ACS 0.3.1-beta specification](../policy-engine/spec/SPECIFICATION.md); proposed migration evidence is in [#3561](https://github.com/microsoft/agent-governance-toolkit/pull/3561) | #3561 is not merged and its registry-trust precondition [ACS #24](https://github.com/responsibleai/agent-control-spec/issues/24) is open. |
| Unified Rust `agt` operator CLI | `partial` | `microsoft/agent-governance-toolkit` | `N/A` -- AGT-specific operator UX; the [Python CLI](../agent-governance-python/agent-compliance/src/agent_compliance/cli/agt.py) is workflow prior art only | Feature-gated [command surface](../agent-governance-rust/agentmesh/src/bin/agt/cli.rs), [dispatcher](../agent-governance-rust/agentmesh/src/bin/agt/main.rs), and [CLI tests](../agent-governance-rust/agentmesh/tests/cli.rs) cover `check`, `policy`, `audit`, and `trust` | Missing `doctor`, replay, offline integrity verification, compliance/OWASP verification, and dashboard workflows. Track [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680); initial CLI delivery was [#2445](https://github.com/microsoft/agent-governance-toolkit/issues/2445). |
| Local-rule `agt check` and `agt policy` commands | `shipped` | `microsoft/agent-governance-toolkit` | `N/A` -- these commands document the existing AGT-local `PolicyEngine` scope and make no ACS claim | [`check.rs`](../agent-governance-rust/agentmesh/src/bin/agt/cmd/check.rs), [`policy.rs`](../agent-governance-rust/agentmesh/src/bin/agt/cmd/policy.rs), and [behavioral CLI tests](../agent-governance-rust/agentmesh/tests/cli.rs) | Complete only for the documented local-rule surface. ACS alignment remains conditional on #3561 and is not implied by this row. |
| `agt audit tail` and `agt audit export` | `partial` | `microsoft/agent-governance-toolkit` | `N/A` -- AGT-specific operator transport UX | [`audit.rs`](../agent-governance-rust/agentmesh/src/bin/agt/cmd/audit.rs) and [behavioral CLI tests](../agent-governance-rust/agentmesh/tests/cli.rs) | Reads and re-emits serialized logs but does not verify the hash chain or embedded control records. Track [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680). |
| `agt trust show` and `agt trust set` | `shipped` | `microsoft/agent-governance-toolkit` | `N/A` -- AGT-specific file-backed trust-store UX | [`trust.rs`](../agent-governance-rust/agentmesh/src/bin/agt/cmd/trust.rs) and [behavioral CLI tests](../agent-governance-rust/agentmesh/tests/cli.rs) | Complete for the documented file-backed score workflow; this is not an external identity or authorization protocol claim. |
| Deterministic replay workflow | `missing` | `microsoft/agent-governance-toolkit` | `N/A` -- AGT/SRE workflow; [Python replay](../agent-governance-python/agent-sre/src/agent_sre/replay/) is UX and workflow prior art only | No Rust replay command or bounded replay envelope exists on current main | Define a host-owned envelope over canonical records before implementation. Track [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680). |
| `agt doctor`, policy linting, compliance and OWASP verification | `missing` | `microsoft/agent-governance-toolkit` | Agent-hooks CTK and ACS conformance artifacts are authoritative for their scopes; Python compliance CLI is presentation prior art only | No Rust `doctor`, `verify`, or `lint-policy` command exists on current main | Must distinguish conformance evidence from certification and bind any attestation to verified inputs. Track [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680). |
| Dashboard and broad governance observability | `partial` | `microsoft/agent-governance-toolkit` | [OpenTelemetry specification](https://opentelemetry.io/docs/specs/otel/); agent-hooks is explicitly a control plane, not a telemetry plane | Opt-in [`agentmesh` policy spans](../agent-governance-rust/agentmesh/src/telemetry.rs) have [behavioral tests](../agent-governance-rust/agentmesh/tests/telemetry.rs); the embedded ACS workspace also has an [OTel metrics bridge](../policy-engine/integrations/otel/src/lib.rs) | Current Rust coverage is narrower than fleet dashboards and broad policy/trust/audit/prompt/MCP telemetry. Track [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680); telemetry foundation history is [#2446](https://github.com/microsoft/agent-governance-toolkit/issues/2446). |

### Host contract and existing integrations

| Capability | Status | Owner | Canonical contract or exemplar | Current implementation and evidence | Limitation and tracker |
|---|---|---|---|---|---|
| AGT Rust host adapter and CTK conformance claim | `missing` | `microsoft/agent-governance-toolkit` | AGENT-HOOKS-0.1, schemas, CTK vectors, [harness contract](https://github.com/responsibleai/agent-hooks/blob/8a06c9defab04f811c92902160f95bcb380aab56/conformance/HARNESS.md), and [claim rules](https://github.com/responsibleai/agent-hooks/blob/8a06c9defab04f811c92902160f95bcb380aab56/conformance/CLAIMS.md) | The canonical Rust SDK and CTK exist upstream, but AGT has no production-path harness or accepted per-part report | Package presence is not host conformance, and conformance is not security certification. Track [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680). Contract or CTK changes belong in `responsibleai/agent-hooks`. |
| Rig tool integration | `partial` | `microsoft/agent-governance-toolkit` | Current embedded ACS host obligations; canonical successor is the ACS and agent-hooks stack linked above | Real [`rig-core` adapter](../policy-engine/integrations/rig/src/lib.rs) and [behavioral tests](../policy-engine/integrations/rig/tests/guarded_tool.rs) exercise allow, deny, transform, approval, bypass, and concurrency cases | Existing workspace crate is `publish = false` and targets embedded ACS 0.3.1-beta. Do not duplicate it; track packaging and canonical-stack decisions in [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680) and [#3561](https://github.com/microsoft/agent-governance-toolkit/pull/3561). |
| Official MCP Rust SDK integration | `partial` | `microsoft/agent-governance-toolkit` | [Official `rmcp` SDK](https://github.com/modelcontextprotocol/rust-sdk) plus current embedded ACS host obligations | Real [`rmcp` adapter](../policy-engine/integrations/mcp/src/lib.rs) and [behavioral tests](../policy-engine/integrations/mcp/tests/guarded_tool.rs) exercise pre- and post-tool enforcement | Existing workspace crate is `publish = false` and targets embedded ACS 0.3.1-beta. It is distinct from, and must not duplicate, canonical [`agentmesh-mcp`](../agent-governance-rust/agentmesh-mcp/). Track [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680) and [#3561](https://github.com/microsoft/agent-governance-toolkit/pull/3561). |
| OpenAI Rust tool integration | `partial` | `microsoft/agent-governance-toolkit` | Current embedded ACS host obligations; OpenAI client types are transport integration, not policy semantics | Real [`async-openai` adapter](../policy-engine/integrations/openai/src/lib.rs) and [behavioral tests](../policy-engine/integrations/openai/tests/guarded_tool_call.rs) exercise allow and pre-/post-tool denial | Existing workspace crate is `publish = false` and targets embedded ACS 0.3.1-beta. Do not create a competing adapter; track packaging and canonical-stack decisions in [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680) and [#3561](https://github.com/microsoft/agent-governance-toolkit/pull/3561). |
| OpenTelemetry integration | `partial` | `microsoft/agent-governance-toolkit` | OpenTelemetry specification; ACS defines only redaction-safe telemetry semantics for its runtime | Existing [`agentmesh` span sink](../agent-governance-rust/agentmesh/src/telemetry.rs) has [behavioral tests](../agent-governance-rust/agentmesh/tests/telemetry.rs); the embedded ACS [metrics bridge](../policy-engine/integrations/otel/src/lib.rs) and [example](../policy-engine/integrations/otel/examples/basic.rs) also exist | The ACS bridge has no crate-local behavioral test, and neither path provides the broader dashboard surface. Extend existing signals rather than inventing another telemetry contract. Track [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680). |
| Goose/ACP host integration | `deferred` | `microsoft/agent-governance-toolkit` | AGENT-HOOKS-0.1 host contract and official CTK; ACS may be installed only as one interceptor | No AGT Goose/ACP production-path adapter or CTK report exists | AGT owns the decision on accepting a reference integration. If maintainers decline, implementation should move to the consuming Goose repository without changing canonical semantics. Track [#3680](https://github.com/microsoft/agent-governance-toolkit/issues/3680); do not implement before ownership is agreed. |

## Updating this manifest

Before changing a row:

1. search open and closed issues and pull requests in all three owning
   repositories;
2. inspect the current default branches, applicable specifications, schemas,
   vectors, implementation, and tests;
3. keep exactly one owner and link a limitation plus tracker for every
   incomplete state;
4. require implementation plus behavioral or official conformance evidence
   before using `shipped`; and
5. update the package matrix and Rust README when operator-visible status or
   discoverability changes.
