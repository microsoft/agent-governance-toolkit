<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# Chapter 7: Policy Versioning

Chapter 6 proved that your policies work *right now*. But policies change.
Legal tells you that `send_email` should be a hard block, not an escalation.
Someone fixes that — and accidentally breaks `transfer_funds` in the same
edit. You need a way to compare two versions, test both, and catch the
regression before the new version goes live.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [Two versions side by side](#step-1-two-versions-side-by-side) | What changed between v1 and v2 |
| [Diff with the CLI](#step-2-diff-with-the-cli) | See every structural change in one command |
| [Test both versions](#step-3-test-both-versions) | Run the same contexts against v1 and v2 |
| [Catch the regression](#step-4-catch-the-regression) | Separate expected changes from accidents |

---

## Step 1: Two versions side by side

Version 1.0 is the production baseline — the same combined policy from
Chapter 6 with five rules covering all decision tiers.

Version 2.0 has three changes:

| # | Change | Intentional? |
|---|--------|-------------|
| 1 | `block-write-file` priority raised from 70 to 95 | Yes — fixes the Chapter 6 surprise where the environment policy overrode the block |
| 2 | `escalate-send-email` message no longer says "requires human approval" | Yes — legal decided send_email should be fully blocked |
| 3 | `escalate-transfer-funds` message no longer says "requires human approval" | No — accidental edit, breaks the escalation |

Changes 1 and 2 are intentional. Change 3 happened because someone edited
both escalation rules instead of just one. The YAML diff looks like a
routine cleanup. The damage is invisible without a behavioral test.

---

## Step 2: Diff with the CLI

The built-in `diff` command compares two policy files structurally:

```bash
python -m agent_os.policies.cli diff \
    examples/07_policy_v1.yaml \
    examples/07_policy_v2.yaml
```

```
rule escalate-transfer-funds: message: Sensitive action: transfer_funds requires human approval -> Sensitive action: transfer_funds is blocked
rule escalate-send-email: message: Sensitive action: send_email requires human approval -> Communication: send_email is blocked by policy
rule block-write-file: priority: 70 -> 95
version: 1.0 -> 2.0
```

Every structural change is listed: two messages changed, one priority
raised, and the version bumped. But the diff does not tell you which change
breaks behavior. For that, you need to run both versions through the same
tests.

---

## Step 3: Test both versions

Load v1 and v2 into separate evaluators and run the same five tools through
both. Use the `classify()` helper from Chapter 6 to tag each result as
allow, escalate, or deny:

```python
from pathlib import Path

from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

examples_dir = Path("docs/tutorials/policy-as-code/examples")

v1 = PolicyDocument.from_yaml(examples_dir / "07_policy_v1.yaml")
v2 = PolicyDocument.from_yaml(examples_dir / "07_policy_v2.yaml")

eval_v1 = PolicyEvaluator(policies=[v1])
eval_v2 = PolicyEvaluator(policies=[v2])

ESCALATION_KEYWORD = "requires human approval"

def classify(decision):
    if decision.allowed:
        return "allow"
    if decision.reason and ESCALATION_KEYWORD in decision.reason.lower():
        return "escalate"
    return "deny"

tools = ["search_documents", "write_file", "send_email",
         "delete_database", "transfer_funds"]

for tool in tools:
    ctx = {"tool_name": tool}
    t1 = classify(eval_v1.evaluate(ctx))
    t2 = classify(eval_v2.evaluate(ctx))
    changed = "⚠️" if t1 != t2 else ""
    print(f"{tool:<22s} {t1:<12s} {t2:<12s} {changed}")
```

### Example output

```
  Tool                   v1             v2             Changed?
  ----------------------------------------------------------
  search_documents       ✅ allow        ✅ allow
  write_file             🚫 deny         🚫 deny
  send_email             ⏳ escalate     🚫 deny         ⚠️  yes
  delete_database        🚫 deny         🚫 deny
  transfer_funds         ⏳ escalate     🚫 deny         ⚠️  yes

  2 tool(s) changed behavior between versions.
```

Two tools changed: `send_email` and `transfer_funds`. Both went from
escalate to deny. The structural diff showed three changes, but the
behavioral test shows only two matter. The `write_file` priority change
does not affect single-policy evaluation — it matters when combined with
the environment policy (that is what the Chapter 6 test matrix would
catch).

---

## Step 4: Catch the regression

The team planned one behavioral change: `send_email` should become a hard
deny. Anything else that changed is a regression.

```python
expected_changes = {"send_email"}

for tool, tier1, tier2, changed in results:
    if not changed:
        continue
    if tool in expected_changes:
        print(f"✅ {tool}: {tier1} → {tier2} (expected)")
    else:
        print(f"❌ {tool}: {tier1} → {tier2} (REGRESSION)")
```

```
  ✅ send_email: escalate → deny (expected — legal decision)
  ❌ transfer_funds: escalate → deny (REGRESSION)

  ❌ Regression: transfer_funds
     Was 'escalate' in v1, now 'deny' in v2.
     The v2 edit removed the escalation keyword from the
     message, so the action that used to pause for human
     review now silently blocks.

  Fix the regression in v2, then re-run this comparison.
  Do not deploy until all changes are expected.
```

The regression is the same type Chapter 6 caught in Part 4 — removing
`"requires human approval"` silently converts an escalation into a hard
deny. But this time, the test compares *two versions* instead of checking
one version in isolation. That is what makes it a versioning check: you can
see exactly when the behavior changed and which edit caused it.

---

## Full example

```bash
python docs/tutorials/policy-as-code/examples/07_policy_versioning.py
```

```
============================================================
  Chapter 7: Policy Versioning
============================================================

--- Part 1: Load both versions ---

  v1: 'production-policy' version 1.0  (5 rules)
  v2: 'production-policy' version 2.0  (5 rules)

--- Part 2: Diff the two versions ---

  version: 1.0 → 2.0
  rule escalate-transfer-funds: message changed
    was: "Sensitive action: transfer_funds requires human approval"
    now: "Sensitive action: transfer_funds is blocked"
  rule escalate-send-email: message changed
    was: "Sensitive action: send_email requires human approval"
    now: "Communication: send_email is blocked by policy"
  rule block-write-file: priority 70 → 95

  The diff lists every structural change. But a diff cannot
  tell you whether a change is safe. You need to test both
  versions and compare the results.

--- Part 3: Test both versions ---

  Tool                   v1             v2             Changed?
  ----------------------------------------------------------
  search_documents       ✅ allow        ✅ allow
  write_file             🚫 deny         🚫 deny
  send_email             ⏳ escalate     🚫 deny         ⚠️  yes
  delete_database        🚫 deny         🚫 deny
  transfer_funds         ⏳ escalate     🚫 deny         ⚠️  yes

  2 tool(s) changed behavior between versions.

--- Part 4: Detect regressions ---

  ✅ send_email: escalate → deny (expected — legal decision)
  ❌ transfer_funds: escalate → deny (REGRESSION)

  ❌ Regression: transfer_funds
     Was 'escalate' in v1, now 'deny' in v2.
     The v2 edit removed the escalation keyword from the
     message, so the action that used to pause for human
     review now silently blocks.

  Fix the regression in v2, then re-run this comparison.
  Do not deploy until all changes are expected.

============================================================
  Policy versioning closes the loop.
  Tag a version, diff it, test both, catch regressions.
  No policy update ships without passing this check.
============================================================
```

---

## How does it work?

```
  v1.yaml          v2.yaml
     │                │
     └────────┬───────┘
              ▼
  ┌───────────────────────────┐
  │  1. Diff                  │
  │     CLI: policy diff      │
  │     List structural diffs │
  └──────────┬────────────────┘
             ▼
  ┌───────────────────────────┐
  │  2. Test both             │
  │     Same contexts, same   │
  │     classify() function   │
  └──────────┬────────────────┘
             │
      ┌──────┴──────┐
      ▼             ▼
  No changes    Changes found
  ✅ Safe to     ↓
  deploy      ┌──────────────┐
              │ 3. Classify  │
              │ Expected vs  │
              │ Regression   │
              └──────┬───────┘
                     │
              ┌──────┴──────┐
              ▼             ▼
          Expected      Regression
          ✅ Deploy     ❌ Fix first
```

| Tool | What it does |
|------|-------------|
| `policy diff v1.yaml v2.yaml` | CLI: structural diff between two policy files |
| `PolicyDocument.from_yaml(path)` | Load and validate a policy file |
| `PolicyEvaluator(policies=[doc])` | Create an evaluator from a PolicyDocument |
| `evaluator.evaluate(context)` | Return a `PolicyDecision` with `allowed`, `action`, `reason` |
| `classify(decision)` | Tag a decision as allow, escalate, or deny (from Chapter 6) |

---

## Try it yourself

1. **Add a new rule in v2.** Create a rule `block-execute-code` that denies
   `execute_code` in v2 only. Re-run the diff — it should show "rule
   added." Test both versions to confirm the new rule only affects v2, and
   add it to `expected_changes` so it does not flag as a regression.

2. **Bridge conversion.** Import `governance_to_document` from
   `agent_os.policies.bridge` and convert a `GovernancePolicy` object
   into a `PolicyDocument`. Diff the result against v1 to see how the
   legacy format maps to the declarative format.

3. **Automate the gate.** Write a function `is_safe_to_deploy(v1_path,
   v2_path, expected)` that loads both files, diffs them, tests both,
   and returns `True` only if every behavioral change is in the
   `expected` set. This is a deploy gate — run it in CI before any policy
   update ships.

---

## What you've built

Over seven chapters, you built a complete policy governance system:

| Chapter | Layer |
|---------|-------|
| 1 | Block dangerous tools |
| 2 | Scope permissions by role |
| 3 | Rate-limit actions |
| 4 | Resolve conflicts between policies |
| 5 | Escalate sensitive actions to humans |
| 6 | Test policies automatically |
| 7 | Update policies safely with regression detection |

Each layer added one concept. Together, they form a system that can
govern AI agents in production: who can do what, how often, who approves,
how you test it, and how you update it without breaking what already works.

**Previous:** [Chapter 6 — Policy Testing](06-policy-testing.md)
