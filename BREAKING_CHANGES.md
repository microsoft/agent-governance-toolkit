# Breaking Changes

This file records breaking changes that require consumer-side updates. Newer
entries appear first.

---

## acs-generator is now a CLI-only package

**Date:** TBD (next `acs-generator` release)

**Affected:**

- `acs-generator` top-level Python imports such as `GenerationEngine`,
  `GenerationError`, `FakeLanguageModel`, `LanguageModel`, and
  `OpenAICompatibleLanguageModel`

**What changed:**

`acs-generator` `0.4.0b0` no longer re-exports implementation classes from its
package initializer. The package remains the `acs` and `acs-generate` command
line artifact generator. Reusable artifact validation moved to
`agent_control_specification.validation`.

**Why:**

The generator is an authoring CLI, not the owner of reusable runtime-facing
APIs. Keeping validation in the Python SDK gives API consumers one supported
surface and prevents the generator package from becoming a second SDK.

**How to migrate:**

- Replace `from acs_generator import validate_acs_artifacts` with
  `from agent_control_specification.validation import validate_acs_artifacts`.
- Invoke generation through `acs` or `acs-generate`. Code that imported
  generator implementation classes must move to the CLI or maintain its own
  integration with the internal modules.

---

## MuteAgentValidator now runs capability validators consistently and honors strict_mode

**Date:** TBD (next release of `microsoft/agent-governance-toolkit`)

**Affected:**

- `agent-governance-python` (`agent_control_plane.mute_agent`):
  `MuteAgentValidator.validate_request`, `MuteAgentValidator.validate_action`,
  `MuteAgentConfig.strict_mode`

**What changed:**

Three input-handling defects that silently weakened validation are fixed. Each
changes the outcome for inputs that previously slipped through:

1. **Dict-shaped requests are now validated.** `validate_request` previously ran
   a capability's parameter validator only when the request was an
   `ExecutionRequest` object (it gated on `hasattr(request, "action_type")`). A
   dict request carries `action_type` as a key, so validators were skipped and a
   dict request with dangerous parameters was approved. Requests are now
   normalized to a shape-independent view and validated the same way whether they
   are objects or dicts. A dict request that fails a validator is now rejected.
2. **`validate_action` now runs validators.** The lightweight
   `validate_action(action_type, parameters)` path previously ignored
   `parameters` and returned success on an action-type match alone. It now runs
   the matching capabilities' validators against `parameters` and can reject.
3. **`strict_mode` is now honored.** `MuteAgentConfig.strict_mode` was never
   read; out-of-capability actions were always rejected. `strict_mode=False` now
   allows well-formed out-of-capability actions (as documented), while
   `strict_mode=True` (the default) continues to reject them. Malformed or
   unrecognized `action_type` is rejected in both modes.

**Why:**

Validation strength must not depend on the in-memory shape of the request, a
config flag that was silently ignored, or which entry point a caller used. All
three were fail-open gaps in a validator whose job is to reject.

**How to migrate:**

- If you send dict requests or use `validate_action` and relied on validators
  being skipped, ensure your requests satisfy the capability validators.
- If you set `strict_mode=False` assuming it was inert, note it now relaxes
  out-of-capability actions; set `strict_mode=True` (the default) to keep strict
  enforcement.

---

## GovernanceLayer.check_alignment fails closed; get_audit_log(0) returns zero entries

**Date:** TBD (next release of `microsoft/agent-governance-toolkit`)

**Affected:**

- `agent-governance-python` (`agent_control_plane.governance_layer`):
  `GovernanceLayer.check_alignment`, `GovernanceLayer.get_audit_log`

**What changed:**

1. **A raising alignment validator is no longer treated as compliant.**
   `check_alignment` previously logged an audit event when a rule's validator
   raised but did not record a violation, so a validator that threw was silently
   reported as `aligned=True` with no violations. It now records a
   `validator_error` violation and returns `aligned=False`.
2. **`get_audit_log(0)` now returns an empty list.** A `limit` of `0` was falsy
   and returned the entire log (`self._audit_log[-0:]` is the whole list). It now
   returns `[]`. `get_audit_log(None)` still returns the full log; a negative
   limit now raises `ValueError`.

**Why:**

An alignment gate that reports a throwing validator as compliant is fail-open,
and a limit of `0` returning everything is a silent wrong result for any caller
that computes a limit which can legitimately be `0`.

**How to migrate:**

- If you relied on `check_alignment` returning `aligned=True` when a validator
  raised, fix the validator; a raise is now a violation.
- If you called `get_audit_log(0)` expecting the full log, pass `None` (or no
  argument) instead.

---

## KernelSpace fails closed when no policy engine is configured

**Date:** TBD (next release of `microsoft/agent-governance-toolkit`)

**Affected:**

- `agent-governance-python` (`agent_control_plane.kernel_space`,
  Layer 3 control plane): `KernelSpace`, `create_kernel`

**What changed:**

A `KernelSpace` constructed without a policy engine previously allowed every
syscall (fail-open), including `SYS_EXEC` tool execution. It now fails closed:

1. **External syscalls are denied by default.** With no `policy_engine`,
   syscalls that reach outside the agent's own sandbox (`SYS_EXEC`, IPC,
   signal delivery, agent spawn) are denied. The denial is returned as a clean
   `SyscallResult(success=False)`; it does not raise a kernel panic and is not
   counted as a policy violation.
2. **Self-scoped syscalls stay allowed.** `SYS_EXIT` and the agent's own VFS
   operations (`SYS_READ`, `SYS_WRITE`, `SYS_OPEN`, `SYS_CLOSE`, `SYS_STAT`)
   remain allowed so an agent can still use its own memory and exit cleanly.
3. **New `permissive` parameter.** `KernelSpace(..., permissive=True)` and
   `create_kernel(..., permissive=True)` restore the previous allow-all
   behavior as an explicit, auditable opt-in.

**Why:**

For a governance kernel, a missing policy engine allowing arbitrary tool
execution is a fail-open trust-boundary hole. The safe default for a missing
governance dependency is to refuse externally-visible actions.

**How to migrate:**

If you construct `KernelSpace()` or `create_kernel()` without a policy engine
and rely on tool execution or other external syscalls, either wire a policy
engine or pass `permissive=True` to keep the previous behavior. Agents that
only read and write their own VFS and exit need no change.

---

## Policy engines: default-deny and consistent warn/log semantics

**Date:** TBD (next release of `microsoft/agent-governance-toolkit`)

**Affected:**

- `agent-governance-python` (`agent_os.policies`)
- `agent-governance-typescript` (`src/policy.ts`)
- `agent-governance-dotnet` (`AgentGovernance.Policy`)

**What changed:**

The three SDKs previously disagreed on authorization outcomes for the same
policy input. This release standardizes all three on fail-closed semantics:

1. **Default action is now deny.** When `defaults.action` is omitted, or when
   no policies are loaded at all, the decision is now `deny` in every SDK.
   - Python: `PolicyDefaults.action` now defaults to `PolicyAction.DENY`, and
     the evaluator returns `deny` when no policies are loaded (previously both
     were `allow`, fail-open).
   - .NET: the zero-policy path now returns `PolicyDecision.DenyDefault`
     (previously `AllowDefault`).
   - TypeScript already defaulted to `deny`; no change.

2. **`warn` and `log` rules are advisory and still allow the request.** In
   TypeScript a matched `warn` or `log` rule now produces `allowed: true`,
   matching the existing .NET and Python behavior (previously TS denied them).

**Why:**

For a governance toolkit, an omitted default or an empty policy set producing
`allow` in one language and `deny` in another is a trust-boundary
inconsistency, not just a style difference. Fail-closed is the safe default.

**How to migrate:**

If you relied on the previous fail-open behavior (an empty or default policy
allowing requests), opt back in explicitly by setting the default action to
allow in your policy document:

```yaml
defaults:
  action: allow
```

No migration is required for consumers who already define explicit rules and
a default action.

---

## `agent-hypervisor` removes joint-liability, blockchain-commitment, and advanced-saga symbols

**Date:** TBD (next release of `microsoft/agent-governance-toolkit`)

**Affected:**

- `agent-hypervisor` (`hypervisor`)
- `agentmesh-runtime` (`agent_runtime`, which re-exported these symbols)

**What changed:**

The following public symbols are removed from `hypervisor` and from the
`agent_runtime` re-exports. Each backed a documented no-op stub (the ledger
always admitted, slashing and quarantine recorded events but enforced nothing,
the commitment engine stored in memory with no anchoring, and the saga DSL,
fan-out, and checkpoint modules had no runtime), so the removal is behavior
preserving:

- Joint liability: `VouchingEngine`, `VouchRecord`, `SlashingEngine`,
  `LiabilityLedger`, `LedgerEntryType`, `LiabilityMatrix`, `QuarantineManager`,
  `QuarantineReason`, `CausalAttributor`, `AttributionResult`
- Session intent locks: `IntentLockManager`, `LockIntent`,
  `LockContentionError`, `DeadlockError`
- Advanced saga: `FanOutOrchestrator`, `FanOutPolicy`, `SagaDSLParser`,
  `SagaDefinition`, `CheckpointManager`, `SemanticCheckpoint`
- Audit and clock internals: `CommitmentEngine`, `EphemeralGC`,
  `VectorClockManager`

**Why:**

These surfaces were Public Preview stubs that advertised capabilities the
runtime never applied, so keeping them exported implied enforcement that did
not exist. Public Preview status permits removal without a deprecation cycle.

**How to migrate:**

Remove imports of these symbols. The supported runtime surface is unchanged:
execution rings, session isolation, the hash-chained delta audit trail,
`SagaOrchestrator` (ordered steps, retries, timeout handling, and reverse-order
compensation), the kill switch, rate limiting, and observability.

---

## Composite action: `toolkit-version` is now **required**

**Date:** TBD (next release of `microsoft/agent-governance-toolkit`)

**Affected:**

- `microsoft/agent-governance-toolkit/action`

**What changed:**

The `toolkit-version` input was previously optional and defaulted to the
latest published toolkit release at action-update time. That behaviour created
a silent supply-chain coupling: a compromised, yanked, or unintentionally
broken toolkit release could land in any consumer's CI on the next workflow
run, with no version pin under the consumer's control.

`toolkit-version` is now **required**, and the action validates the value
against a strict regex that accepts only `X.Y.Z`, `X.Y.ZaN`, `X.Y.ZbN`, and
`X.Y.ZrcN`. Floating refs (`3.7.*`, `>=3.7`), post-releases (`3.7.0.post1`),
dev-releases (`3.7.0.dev0`), local-version identifiers (`3.7.0+local`), URL /
VCS references, and environment markers are all rejected.

**Why:**

This closes a class of supply-chain finding raised during the
`jackbatzner/harden-ci-review-automation` review: an attacker who can
republish or yank a toolkit release should not automatically execute in
consumer pipelines, and the version pin must be explicit and auditable in
the consumer's repository.

**How to migrate:**

1. **Pin the action to the major tag you were already using.** The major tag
   (e.g. `@v3`) continues to point at the latest release within that major,
   so the toolkit-version requirement does not break your pipeline at
   action-update time:

   ```yaml
   - uses: microsoft/agent-governance-toolkit/action@v3
     with:
       toolkit-version: "3.7.0"          # <-- now required
   ```

2. **Bump `toolkit-version` deliberately** when a new release ships. Treat
   it the same way you would a pinned npm or pip dependency: review the
   changelog and the release notes before bumping.

3. **Consider Dependabot** for the version-bump itself. `toolkit-version` is
   a string, so a small ecosystem-specific updater or a regex-based custom
   updater is the easiest fit.

If your workflow run fails with:

```
::error::toolkit-version must be an exact release or pre-release (e.g. 3.7.0 or 3.7.0rc1); got: ...
```

then the value you supplied does not match the accepted syntax. See
[`action/README.md`](action/README.md#accepted-version-syntax) for the full
list of accepted and rejected forms.

**Operational note:** the action's own version (`@v3`, `@v3.7.0`, or a
commit SHA) is independent of `toolkit-version`. Pinning the action to a
commit SHA is recommended for high-trust pipelines (see GitHub's
[hardening guide for third-party actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)).
