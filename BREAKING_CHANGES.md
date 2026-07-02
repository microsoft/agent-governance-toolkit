# Breaking Changes

This file records breaking changes that require consumer-side updates. Newer
entries appear first.

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
