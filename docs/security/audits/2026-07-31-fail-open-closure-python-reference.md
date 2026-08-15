---
title: "Security Audit: Fail-open closure in the Python accumulated-context reference (agent-os)"
last_reviewed: 2026-07-31
owner: agt-maintainers
---

# 2026-07-31 - Fail-open closure in the Python accumulated-context reference (agent-os)

PR: microsoft/agent-governance-toolkit#3524

## What changed and why

An adversarial re-review of the sibling SDK ports (TS #3199, Go #3261, .NET
#3443, Rust #3450) surfaced two spots where the Python reference
(`agent-governance-python/agent-os/src/agent_os/policies/`) was the laxest
implementation. Both fail open. This PR closes them:

| Gap | Site | Before | After |
|-----|------|--------|-------|
| Geography default fail-open | `data_classification.py` `_evaluate_single` | `policy.required_geography and data_label.geography and data_label.geography != policy.required_geography` — an absent (empty string) geography short-circuited the check, so a label with no geography bypassed a policy that requires one | `policy.required_geography is not None and data_label.geography != policy.required_geography` — a required geography that is absent or mismatched denies |
| Empty label set matches everything | `context_aggregation.py` `AggregationRule` | a rule with `all_labels=frozenset()` matched every envelope (`frozenset() <= labels` is always true), raising sensitivity and suppressing the escalation backstop | `__post_init__` raises `ValueError` when `all_labels` is empty; the rule can no longer be constructed |

The restriction-gating gap from the same review (the `decide_next` gate and
obligations reading pre-existing `env.restrictions` instead of the
aggregation-effective set) is out of scope for this PR because it is fixed by
microsoft/agent-governance-toolkit#3523, which additionally names an obligation
when a floor-triggered `CONSTRAIN` carries no restrictions.

## Threat model impact

Both changes move the Python reference from fail-open to fail-closed for
inputs that were previously silently permissive.

| Dimension | Direction |
|-----------|-----------|
| Data exfiltration via geography | Closed. A data label with no geography no longer satisfies a policy that requires one. An agent bound to `required_geography="US"` can no longer read unlabeled data that should be treated as not-US. This matches the TS port's deliberate fail-closed behavior and the ABAC intent that absence of an attribute grants nothing. |
| Escalation backstop integrity | Closed. The monotone backstop exists so that label combinations not covered by a rule escalate for review instead of passing. An empty-label rule previously matched every envelope, which both forced sensitivity to the rule's floor and cleared `escalate`. Rejecting empty label sets at construction keeps the backstop reachable and makes match-all behavior impossible to author accidentally or by a config mistake. |
| Existing valid configurations | Unchanged. Rules in the repo and tests all use non-empty label sets; policies without a `required_geography` still allow any label geography. The fail-open behavior being removed was undocumented and is not relied on by any call site. |
| New attack surface | None. No new inputs, network exposure, secrets, or trust decisions are introduced; both fixes only narrow acceptance at existing decision points. |

### What remains for review

The restriction-gating fail-open (a rule-implied restriction gating only one
interaction late) is addressed in #3523, which this PR deliberately does not
overlap with. After #3523 lands, the Python reference will be fail-closed on
all three gaps from the re-review.

## Test coverage

Each regression test was verified to fail with its fix reverted and pass with
it applied.

| Test | Validates |
|------|-----------|
| `tests/test_data_classification.py::TestGeography::test_missing_geography_denied_when_required` | a label with empty `geography=""` is denied when the policy sets `required_geography="US"` |
| `tests/test_data_classification.py::TestGeography::test_matching_geography_allowed` | an explicit matching geography is still allowed |
| `tests/test_data_classification.py::TestGeography::test_mismatched_geography_denied` | an explicit non-matching geography is denied |
| `tests/test_data_classification.py::TestGeography::test_no_geography_requirement_allows_any` | a policy without `required_geography` still allows any label geography |
| `tests/policies/test_context_aggregation.py::test_empty_all_labels_rejected` | constructing `AggregationRule(all_labels=frozenset())` raises `ValueError` |

The agent-os unit suite (including `tests/policies/test_context_aggregation.py`
and `tests/test_data_classification.py`) passes on the branch.
