# 2026-06-10 - Policy Pinning and Fail-Closed Scoped Evaluation

PR: [microsoft/agent-governance-toolkit#2946](https://github.com/microsoft/agent-governance-toolkit/pull/2946)

Fixes #2929.

## What changed and why

This PR closes two governance gaps in the agent-os enforcement path:

- **Gap 1 (policy pinning):** `BaseIntegration.pre_execute_check` and
  `post_execute_check` read the live `self.policy` instead of the deep-copied
  `ctx.policy` that `create_context` pins to the session. Every per-call gate
  (`max_tool_calls`, `timeout_seconds`, blocked patterns, `require_human_approval`,
  `confidence_threshold`, the drift gate, and `checkpoint_frequency`) now reads
  `ctx.policy`. This makes enforcement consistent with the `create_context`
  pinning contract and with `compute_drift`, which already read
  `ctx.policy.drift_threshold`. Previously the drift gate compared against
  `self.policy.drift_threshold` while the drift computation used
  `ctx.policy.drift_threshold`, so a mid-session mutation could make the two
  disagree.
- **Gap 2 (fail closed in scoped evaluation):** `PolicyEvaluator._evaluate_scoped`
  ran `discover_policies`, `PolicyDocument.from_yaml`, and `merge_policies`
  outside any try block. A malformed `governance.yaml` anywhere in the folder
  chain made `evaluate()` raise instead of denying. That discovery, parse, and
  merge phase is now wrapped in the same fail-closed try/except already used by
  `_evaluate_flat`, returning a deny `PolicyDecision` on any error.

**Why now:** Both gaps are silent failures of the deny path. Gap 1 let a
mid-session policy edit either tighten or loosen enforcement of an already
running session, contradicting the documented pinning guarantee. Gap 2 let a
malformed policy file convert a deny into an unhandled exception, which a caller
that swallows exceptions could treat as a permit.

## Threat model impact

This change **strengthens** the deny path and removes a fail-open edge. It does
not add new attack surface, identity, trust, or cryptographic code.

| Dimension | Direction |
|---|---|
| Policy bypass surface | **Reduced.** Enforcement now reads the pinned, deep-copied `ctx.policy`, so a mutation of `self.policy` mid-session can no longer relax (or unexpectedly tighten) gates on an in-flight session. |
| Fail-open risk | **Reduced.** A malformed `governance.yaml` in scoped mode now yields a deny `PolicyDecision` instead of raising. The scoped path matches the flat path's fail-closed behavior. |
| Information leakage | **No new exposure.** The fail-closed deny reason is a fixed string ("Policy evaluation error, access denied (fail closed)"); parse-error details go to the logger and the structured `audit_entry`, not to the caller-facing reason. |
| Privilege boundaries | **Unchanged.** Execution rings, kill switch, and approval gates are untouched. |
| Authentication / identity | **Unchanged.** No identity, signing, or trust-handshake code is modified. |
| New trust assumptions | **None.** The set of inputs trusted by the evaluator is unchanged; only the handling of bad input changed (deny instead of raise). |
| Backward compatibility | **Preserved for correct callers.** Sessions whose `ctx.policy` matches the integration policy (the result of `create_context`) behave identically. Only callers that constructed an `ExecutionContext` with a divergent policy and relied on `self.policy` being enforced instead see a change, which is the intended fix. |

### Specific mitigations applied

- **Pin enforcement to the session policy.** All per-call gates read
  `ctx.policy`, the deep copy taken at `create_context` time, so enforcement is
  immutable for the life of the session.
- **Symmetric fail-closed paths.** The scoped discovery/parse/merge phase is
  wrapped in the same try/except shape as `_evaluate_flat`, returning a deny
  decision with `audit_entry["error"] = True` on any exception.
- **No new error-message disclosure.** The exception is logged with
  `exc_info=True` server-side; the caller-facing `reason` is a constant.

## Test coverage

| File | Purpose |
|---|---|
| `tests/test_session_pinning_and_aliases.py` | A mid-session mutation of `self.policy` no longer changes enforcement for an already-created context; the stale test that documented the old `self.policy` behavior was updated. |
| `tests/test_folder_governance.py` | A malformed `governance.yaml` in a scoped folder yields a deny decision rather than raising. |
| `tests/test_base_cedar_integration.py` | Cedar-plus-policy composition tests now build the context via `create_context` so the enforced (pinned) policy matches the configured policy. |

All targeted tests pass, and the broad `policy or cedar or pin` selection shows
no new failures introduced by this change.
