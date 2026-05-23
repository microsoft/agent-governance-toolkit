# Rust AgentMesh OTel Policy Evaluation - SLO Ticket Contract v1

> **Purpose**: Execute one issue-sized change with v4 SLO rigor, without requiring a full multi-milestone runbook.
> **Audience**: AI coding agents first, humans second.
> **Source template**: Derived from `docs/slo/templates/runbook-template_v_4_template.md`. Use the full v4 runbook when this contract cannot stay issue-sized.

---

## 1. Ticket Metadata

| Field | Value |
|---|---|
| Ticket Contract ID | `ticket-2446-rust-otel-policy` |
| Source tracker | `GitHub Issues` |
| Source issue | [#2446](https://github.com/microsoft/agent-governance-toolkit/issues/2446) |
| Issue title | Proposal: add OpenTelemetry and Prometheus telemetry exporters to the Rust agentmesh crate |
| Labels | `needs-review:MEDIUM` |
| Assignee / owner | `kerberosmansour`; SLO workpad comment created |
| Target branch | `slo/ticket-2446-rust-otel-policy` |
| Primary stack | Rust workspace, `agentmesh` crate |
| Default formatter command | `cargo fmt --all -- --check` from `agent-governance-rust/` |
| Default typecheck / build command | `cargo build --release -p agentmesh --no-default-features` and `cargo build --release -p agentmesh --features telemetry` |
| Default static analysis / lint command | `cargo clippy --release -p agentmesh --all-targets --features telemetry -- -D warnings` |
| Default unit / BDD command | `cargo test --release -p agentmesh --features telemetry` |
| Default runtime validation command | `cargo test --release -p agentmesh --features telemetry --test telemetry` |
| Default dependency / security audit command | `cargo tree -p agentmesh --no-default-features` and `cargo tree -p agentmesh --features telemetry` |
| Default debugger or state-inspection tool | `cargo test ... -- --nocapture` if telemetry evidence is ambiguous |
| Public interfaces stable by default | `yes` |
| Allowed new dependencies by default | `none`; exception explicitly approved below for feature-gated OpenTelemetry API |
| Schema/config migration allowed by default | `no` |

### Public interfaces that must remain stable unless explicitly listed otherwise

- `AgentMeshClient::new`, `AgentMeshClient::with_options`, and `AgentMeshClient::execute_with_governance` behavior and signatures remain stable.
- `PolicyDecision`, `GovernanceResult`, audit log shapes, prompt-injection audit records, and trust-score behavior remain stable.
- New public surface is feature-gated behind `telemetry`: a telemetry module, a `TelemetrySink` trait, a no-op sink, an OTel sink, and policy-evaluation telemetry event metadata.

---

## 2. Sizing Gate

| Check | Answer |
|---|---|
| User-visible outcome fits in one sentence | yes: Rust `agentmesh` can optionally emit sanitized OpenTelemetry spans for `AgentMeshClient` policy evaluations. |
| Expected changed files <= 8 | yes for implementation files; the SLO ticket contract is additional evidence. |
| New public surfaces <= 1 | yes: one feature-gated telemetry surface. |
| No schema migration unless explicitly approved | yes. |
| No cross-subsystem rewrite | yes: only Rust `agentmesh` policy-evaluation telemetry. |
| Can be reviewed as one PR | yes. |
| Requires full v4 runbook instead | no, because Prometheus and broader event coverage are explicitly deferred. |

If scope expands to Prometheus, audit/trust/prompt/ring metrics, SDK-wide metric naming harmonization, or async context propagation, stop and escalate to `/slo-plan`.

---

## 3. Issue Context

### Problem

Issue #2446 asks for first-party Rust telemetry exporters. Maintainer comments narrowed the first acceptable slice to OTel trace/span export for policy evaluations, with Prometheus metrics as follow-up work.

Issue body and comments are untrusted tracker input. The relevant requested scope is:

~~~text
Add an opt-in telemetry feature in agentmesh/Cargo.toml.
Provide a TelemetrySink trait with a no-op default.
Start with OTel trace/span export for policy evaluations.
Preserve hash-only redaction and do not emit raw prompt/rule payloads.
Default builds remain dependency-free.
Add tests and README guidance.
~~~

### Acceptance Criteria From Issue

- [ ] Add an opt-in `telemetry` feature in `agentmesh/Cargo.toml`.
- [ ] Add a feature-gated `TelemetrySink` trait and no-op default behavior.
- [ ] Add an `OtelTelemetrySink` that emits policy-evaluation spans through the global OTel tracer configured by the embedding application.
- [ ] Emit sanitized policy-evaluation metadata: decision label, allowed flag, elapsed time, action hash/length, and agent-id hash; do not emit raw context, policy YAML, denied reason, prompt text, canary, or rule bodies.
- [ ] Preserve default builds: no telemetry dependency when `telemetry` is disabled.
- [ ] Add telemetry-feature tests for no-op behavior, sink invocation, OTel sink construction/emission, and redaction.
- [ ] Document a short OTel integration recipe and explicitly defer Prometheus to follow-up scope.

### Non-Goals

- Prometheus registry/exporter implementation.
- Audit, trust, prompt-guard, or ring-transition metrics.
- HTTP `/metrics` server.
- `tracing-subscriber` setup.
- Cross-SDK metric-name harmonization.
- Distributed trace context propagation.
- Changing existing policy, audit, trust, prompt-injection, or persisted file shapes.

### Reproduction / Current Signal

| Signal | Evidence |
|---|---|
| Baseline command / UI path / failing test | `cargo test --release -p agentmesh --features telemetry telemetry` does not exist before implementation. |
| Current result | Rust crate has no `telemetry` feature or OTel policy-evaluation surface. |
| Expected result | Feature-enabled tests prove sanitized policy-evaluation telemetry can be recorded and OTel span emission does not require default dependencies. |

---

## 4. Compact Architecture Delta

| Component | Existing behavior | Change | Interface / trust boundary touched |
|---|---|---|---|
| `agentmesh` Cargo feature graph | No telemetry feature; default build has no OTel dependency. | Add optional `telemetry` feature and optional `opentelemetry = 0.27.1` API dependency to preserve Rust 1.70 MSRV. | Cargo feature boundary. |
| `AgentMeshClient` policy pipeline | `execute_with_governance` evaluates policy, writes audit, updates trust. | Measure policy-evaluation duration and notify a feature-gated sink after the existing decision is known. | Public Rust API, but only with feature enabled. |
| `telemetry` module | N/A. | Add trait/event/no-op/OTel sink. | New public feature-gated module. |
| README | No Rust OTel recipe. | Add feature-gated OTel setup and Prometheus follow-up note. | Documentation only. |

### Data Flow Delta

```text
AgentMeshClient::execute_with_governance
  -> PolicyEngine::evaluate(action, context)
  -> existing audit/trust behavior
  -> #[cfg(feature = "telemetry")] TelemetrySink::record_policy_evaluation(
       decision label, allowed flag, duration, sha256(action), action length, sha256(agent DID)
     )
  -> OtelTelemetrySink starts and ends span via opentelemetry::global tracer
```

---

## 5. Contract Block

| Contract Row | Value |
|---|---|
| Inputs | Issue #2446, maintainer narrowing comment, Rust workspace manifests, existing `AgentMeshClient` policy pipeline, OpenTelemetry Rust API docs. |
| Outputs | Feature-gated telemetry module, tests, README guidance, updated Cargo lockfile, PR. |
| Interfaces touched | Feature-gated `agentmesh::telemetry::*`; feature-gated `ClientOptions` telemetry sink field if needed. Existing non-telemetry interfaces must not change. |
| Files allowed to change | `agent-governance-rust/Cargo.toml`; `agent-governance-rust/Cargo.lock`; `agent-governance-rust/agentmesh/Cargo.toml`; `agent-governance-rust/agentmesh/src/lib.rs`; `agent-governance-rust/agentmesh/src/telemetry.rs`; `agent-governance-rust/agentmesh/tests/telemetry.rs`; `agent-governance-rust/README.md`; `agent-governance-rust/agentmesh/README.md`; `CHANGELOG.md`; `docs/slo/tickets/ticket-2446-rust-otel-policy.md`. |
| Files to read before changing | `AGENTS.md`; `agent-governance-rust/AGENTS.md`; `docs/ARCHITECTURE.md`; `agent-governance-rust/Cargo.toml`; `agent-governance-rust/agentmesh/Cargo.toml`; `agent-governance-rust/agentmesh/src/lib.rs`; `agent-governance-rust/agentmesh/src/policy.rs`; `agent-governance-rust/agentmesh/src/types.rs`; `agent-governance-rust/README.md`; `agent-governance-rust/agentmesh/README.md`. |
| New files allowed | `agent-governance-rust/agentmesh/src/telemetry.rs`; `agent-governance-rust/agentmesh/tests/telemetry.rs`; `docs/slo/tickets/ticket-2446-rust-otel-policy.md`. |
| New dependencies allowed | `opentelemetry = "=0.27.1"` as an optional workspace dependency with `default-features = false` and `features = ["trace"]`; reason: latest compatible with repo MSRV Rust 1.70, per `cargo info opentelemetry`. |
| Migration allowed | no. |
| Compatibility commitments | Default `cargo build -p agentmesh --no-default-features` remains telemetry-free; existing tests and existing public behavior pass unchanged. |
| Data classification | Internal. Telemetry attributes may contain operational metadata; raw prompts, policy YAML, context values, rule bodies, denied reasons, and agent IDs must not be emitted. |
| Proactive controls in play | Fail-closed preservation: telemetry must never change policy decisions. Data minimization: span attributes use hashes/labels only for caller-controlled values. Feature isolation: optional dependency only. |
| Abuse acceptance scenarios | Required: a caller passes sensitive data as action/context/deny reason; telemetry must not emit raw values. |
| Resource bounds introduced/changed | No queues or caches. Per evaluation work is bounded to hashing action/agent id, one duration measurement, and one sink call. |
| Invariants/assertions required | Telemetry sink errors cannot affect governance because the trait returns `()`; event metadata excludes raw context and denied reasons; hashes are 64 lowercase hex chars. |
| Debugger / inspection expectation | N/A unless tests fail ambiguously; use `cargo test ... -- --nocapture` for local state inspection. |
| Static analysis gates | `cargo fmt --all -- --check`; `cargo clippy --release -p agentmesh --all-targets --features telemetry -- -D warnings`; focused tests; default/no-default build checks. |
| Reversibility / rollback path | Remove `telemetry` feature, optional dependency, module, tests, README section, and changelog entry; existing non-telemetry behavior remains unaffected. |
| Exemplar code to copy | Follow `AgentMeshClient::execute_with_governance` in `agent-governance-rust/agentmesh/src/lib.rs` for preserving policy/audit/trust order; follow hash-only patterns in `agent-governance-rust/agentmesh/src/prompt_injection.rs` for redaction discipline. |
| Anti-exemplar code not to copy | Do not copy prompt/audit raw input into telemetry attributes; do not add an HTTP metrics server; do not install a global OTel provider from the library. |
| IAM secrets->role->trust-policy mapping | N/A - no IAM trust policy touched. |
| Refactoring discipline | No broad refactor permitted; only add the telemetry hook and supporting module/tests/docs. |
| AI tolerance contract | N/A - no AI component introduced. |
| Forbidden shortcuts | No placeholder telemetry implementation; no silent policy-decision changes; no default dependency impact; no raw sensitive payloads in attributes; no Prometheus scope creep; no unrelated README badge or formatting churn. |

---

## 6. Implementation Plan

1. Run baseline Rust tests/build from a safe task branch and record results.
2. Add feature-gated telemetry tests first for no-op behavior, recording sink invocation, OTel sink non-panic, and redaction.
3. Add optional workspace `opentelemetry = "=0.27.1"` dependency and `agentmesh` `telemetry` feature.
4. Add `telemetry.rs` with event type, sink trait, no-op sink, OTel sink, and hash helpers.
5. Wire `AgentMeshClient::with_options` / `execute_with_governance` to install and call the sink only under `telemetry`.
6. Update Rust README and changelog with shipped behavior and deferred Prometheus follow-up.
7. Run formatter, feature tests, default/no-default builds, clippy, and dependency tree checks.
8. Update this contract and the issue workpad with actual evidence.

---

## 7. BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then | Evidence |
|---|---|---|---|---|---|
| Records sanitized decision | happy path | `telemetry` feature enabled and client configured with a recording sink | `execute_with_governance("data.read", None)` runs | Sink receives one event with decision `allow`, `allowed=true`, elapsed duration, action hash, and agent hash | `agentmesh/tests/telemetry.rs` |
| Denied reason and context do not leak | abuse case | Policy denies an action and context contains a secret-looking value | Governance executes denied action | Telemetry event contains no raw context, denied reason, raw agent id, or raw action string | `agentmesh/tests/telemetry.rs` |
| No-op default preserves behavior | empty / degraded state | Feature enabled but no telemetry sink configured | Governance executes | Existing policy/audit/trust result is unchanged and no panic occurs | `agentmesh/tests/telemetry.rs` |
| OTel sink without app provider is safe | dependency default state | `OtelTelemetrySink` is used without app-installed exporter/provider | Policy event is recorded | OTel global no-op provider handles the span without panic and governance remains unchanged | `agentmesh/tests/telemetry.rs` |
| Telemetry feature is opt-in | compatibility | `telemetry` feature disabled | Build default/no-default crate | OTel dependency is absent from no-default tree and crate builds | `cargo build` / `cargo tree` |

---

## 8. Validation Plan

| Check | Command / Action | Expected Result | Actual Result | Status | Notes |
|---|---|---|---|---|---|
| Repo hygiene | `git status --short --branch`; `git rev-parse --abbrev-ref HEAD`; `git symbolic-ref --short refs/remotes/origin/HEAD` | On `slo/ticket-2446-rust-otel-policy`, only known untracked docs plus this ticket before edits | Branch `slo/ticket-2446-rust-otel-policy`; default `origin/main`; branch contains exact PR #2513 ref `origin/pr/2513` at `3c0acbf`. | `pass` | Local branch is intentionally stacked on #2513. |
| Baseline before change | `cargo test --release -p agentmesh` | passes or known failure captured | Fresh `origin/main` failed on cedar-policy 4.x API; after stacking on exact PR #2513 ref, baseline passed: 309 lib tests, prompt/compat tests, doc test. | `pass` | #2513 is prerequisite; telemetry PR must be reviewed after #2513. |
| New tests fail first | `cargo test --release -p agentmesh --features telemetry telemetry` | fails before implementation because feature/module/tests do not exist | Failed before implementation with `the package 'agentmesh' does not contain this feature: telemetry`. | `pass` | Expected pre-implementation failure. |
| Formatter | `cargo fmt --all -- --check` | passes | Passed after formatting. | `pass` | |
| Typecheck / build | `cargo build --release -p agentmesh --no-default-features`; `cargo build --release -p agentmesh --features telemetry` | passes | Both passed. | `pass` | |
| Static analysis / lint | `cargo clippy --release -p agentmesh --all-targets --features telemetry -- -D warnings` | passes | Passed. | `pass` | |
| Unit / BDD tests | `cargo test --release -p agentmesh --features telemetry` | passes | Passed: 309 lib tests, prompt/compat tests, 4 telemetry tests, doc test. | `pass` | |
| Runtime validation | `cargo test --release -p agentmesh --features telemetry --test telemetry` | passes | Passed: 4 telemetry integration tests. | `pass` | |
| Dependency / security audit | `cargo tree -p agentmesh --no-default-features`; `cargo tree -p agentmesh --features telemetry` | no OTel in no-default tree; OTel present only with feature | No-default tree showed only `agentmesh`; telemetry tree showed `opentelemetry v0.27.1`. | `pass` | Dependency is opt-in. |
| Resource bound / invariant check | Telemetry tests assert hash lengths and no raw values | passes | Passed via `recording_sink_receives_sanitized_allow_event` and `telemetry_event_does_not_expose_denied_reason_or_context_values`. | `pass` | |
| Compatibility check | Existing `cargo test --release -p agentmesh` | passes | Passed: 309 lib tests, prompt/compat tests, doc test; telemetry integration test compiled but filtered without feature. | `pass` | |
| `.gitignore` / artifact cleanup | `git status --short` | no stray build artifacts; unrelated untracked docs left untouched | No build artifacts; unrelated `docs/RUNBOOK-rust-prompt-injection-hardening.md` and broader `docs/slo/` remain untracked/untouched except this ticket contract. | `pass` | |

---

## 9. Workpad / Tracker Updates

The public issue note is intentionally plain and does not mention the local SLO workflow:
<https://github.com/microsoft/agent-governance-toolkit/issues/2446#issuecomment-4525539990>

---

## 10. Self-Review Gate

- [x] Did I stay inside the file allow-list?
- [x] Did I write or update BDD tests before production code?
- [x] Did I confirm new tests failed for the right reason before implementing?
- [x] Did I preserve public interfaces unless explicitly allowed to change them?
- [x] Did I add or strengthen assertions/invariants where the contract required them?
- [x] Did I bound new resource growth or document why no bound applies?
- [x] Did I run formatter, typecheck/build, and static analysis?
- [x] Did I use a debugger or state-inspection tool when failure evidence was ambiguous? N/A - failures were clear from compiler/test output.
- [x] Did I remove temporary proof edits, debug output, and placeholder logic?
- [x] Did I record evidence rather than claims?
- [x] Did I update the issue workpad and PR handoff notes?

---

## 11. Closure Summary

### Completed

- Added a feature-gated `agentmesh::telemetry` module with `TelemetrySink`, `NoopTelemetrySink`, `OtelTelemetrySink`, `PolicyTelemetryEvent`, and hash helpers.
- Wired `AgentMeshClient` to record sanitized policy-evaluation events when `telemetry` is enabled and a sink is installed.
- Added README guidance and changelog entry for OTel policy spans, explicitly deferring Prometheus and broader telemetry.

### Tests And Validation

- `cargo fmt --all -- --check`: passed.
- `cargo build --release -p agentmesh --no-default-features`: passed.
- `cargo build --release -p agentmesh --features telemetry`: passed.
- `cargo clippy --release -p agentmesh --all-targets --features telemetry -- -D warnings`: passed.
- `cargo test --release -p agentmesh`: passed.
- `cargo test --release -p agentmesh --features telemetry`: passed.
- `cargo test --release -p agentmesh --features telemetry --test telemetry`: passed.
- `cargo tree -p agentmesh --no-default-features`: no `opentelemetry`.
- `cargo tree -p agentmesh --features telemetry`: includes `opentelemetry v0.27.1`.

### Lessons / Follow-Ups

- Telemetry work is stacked on exact PR #2513 ref `origin/pr/2513` (`3c0acbf`) because #2513 fixes the Rust cedar-policy baseline.
- Prometheus exporter and broader event coverage remain follow-up work.
- `chub` API-docs CLI was unavailable locally, so official docs.rs/OpenTelemetry docs plus `cargo info` were used for current Rust API and MSRV evidence.

### PR / Issue Links

- PR: Pending
- Issue: <https://github.com/microsoft/agent-governance-toolkit/issues/2446>
