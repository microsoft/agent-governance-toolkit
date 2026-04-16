<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# Chapter 6: Policy Testing

In Chapters 1–5, you checked your policies by running a script and eyeballing
the output. That works when you have five rules. But you now have role-based
policies, environment-aware rules, conflict resolution, and escalation
workflows. A single typo in a YAML file can silently change an escalation into
a hard deny — and nobody notices until a real transfer fails in production.

Manual checking does not scale. You need **automated tests** that verify every
tool gets the right decision, for every role, every time.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [The problem](#the-problem) | Why eyeballing output is not enough |
| [Validate the structure](#step-1-validate-the-structure) | Catch structural errors before anything runs |
| [Write test scenarios](#step-2-write-test-scenarios) | Declare expected outcomes, run them automatically |
| [The test matrix](#step-3-the-test-matrix) | Combine policies from chapters 2 + 4, test every role × environment × tool |
| [Catch a regression](#step-4-catch-a-regression) | Find the bug that manual checking misses |
| [Try it yourself](#try-it-yourself) | Exercises |

---

## The problem

Manual checking breaks down fast. Once you have multiple policies, you need a
repeatable way to say "for this context, I expect this decision" and verify the
result automatically.

---

## Step 1: Validate the structure

Before testing any decisions, make sure the YAML is well-formed. A misspelled
operator or a missing field will cause confusing failures later. Catch
structural errors first.

If you are using the checked-in example files from the repo root, use the full
paths shown in the commands below. If you created your own copies locally,
replace them with your local filenames.

### A valid policy (`06_test_policy.yaml`)

This policy combines concepts from earlier chapters — allow, deny, escalation,
and a default — into a single file designed for testing:

```yaml
version: "1.0"
name: test-policy
description: >
  Combined policy for automated testing.  Covers allow, deny,
  escalation-tagged deny, and default-allow so that test scenarios
  can verify every decision path in one pass.

rules:
  # Tier 1: Always denied — irreversibly destructive
  - name: block-delete-database
    condition:
      field: tool_name
      operator: eq
      value: delete_database
    action: deny
    priority: 100
    message: "Destructive action: deleting databases is never allowed"

  # Tier 2: Escalation — needs human review
  - name: escalate-transfer-funds
    condition:
      field: tool_name
      operator: eq
      value: transfer_funds
    action: deny
    priority: 90
    message: "Sensitive action: transfer_funds requires human approval"

  - name: escalate-send-email
    condition:
      field: tool_name
      operator: eq
      value: send_email
    action: deny
    priority: 85
    message: "Sensitive action: send_email requires human approval"

  # Tier 3: Always allowed — safe, read-only actions
  - name: allow-search-documents
    condition:
      field: tool_name
      operator: eq
      value: search_documents
    action: allow
    priority: 80
    message: "Safe action: searching documents is always allowed"

  # Tier 4: Explicit deny — not needed by this agent
  - name: block-write-file
    condition:
      field: tool_name
      operator: eq
      value: write_file
    action: deny
    priority: 70
    message: "Write access is not permitted for this agent"

defaults:
  action: allow
  max_tool_calls: 10
```

Five rules, four decision tiers, one default. Enough to test every path.

### Loading and validating

```python
from pathlib import Path

from agent_os.policies.schema import PolicyDocument

examples_dir = Path("docs/tutorials/policy-as-code/examples")

policy = PolicyDocument.from_yaml(examples_dir / "06_test_policy.yaml")
print(policy.name)        # "test-policy"
print(len(policy.rules))  # 5
```

`PolicyDocument.from_yaml()` does two things: it parses the YAML and validates
it against the schema. If the file is valid, you get a `PolicyDocument` object.
If not, you get a `ValidationError` that tells you exactly what is wrong.

### A broken policy

What if someone types `equals` instead of `eq`?

```python
from pydantic import ValidationError

broken = {
    "version": "1.0",
    "name": "broken-policy",
    "rules": [{
        "name": "bad-rule",
        "condition": {
            "field": "tool_name",
            "operator": "equals",   # wrong — should be "eq"
            "value": "send_email",
        },
        "action": "deny",
    }],
}

try:
    PolicyDocument.model_validate(broken)
except ValidationError as exc:
    print(exc.errors()[0]["msg"])
```

### Example output

```
  🚫 Validation failed (as expected):
     Field:   rules -> 0 -> condition -> operator
     Problem: Input should be 'eq', 'ne', 'gt', 'lt', 'gte', 'lte', 'in', 'matches' or 'contains'
```

The error message tells you the exact path (`rules -> 0 -> condition ->
operator`) and the valid values. You do not need to guess.

### Using the CLI

The same validation is available as a command:

```bash
python -m agent_os.policies.cli validate \
  docs/tutorials/policy-as-code/examples/06_test_policy.yaml
```

```
OK
```

Exit code 0 means the file is valid. Exit code 1 means validation failed
(with the error printed to stderr). Exit code 2 means the file could not be
found or parsed.

---

## Step 2: Write test scenarios

Validation tells you the YAML is *structured correctly*. Test scenarios tell
you the policy *behaves correctly* — that each tool gets the right decision.

### The scenarios file (`06_test_scenarios.yaml`)

```yaml
scenarios:
  # Always allowed
  - name: search-documents-allowed
    context: { tool_name: search_documents }
    expected_action: allow

  # Always denied (destructive)
  - name: delete-database-denied
    context: { tool_name: delete_database }
    expected_action: deny

  # Escalation-tagged (deny with "requires human approval")
  - name: transfer-funds-denied
    context: { tool_name: transfer_funds }
    expected_action: deny

  - name: send-email-denied
    context: { tool_name: send_email }
    expected_action: deny

  # Explicit deny
  - name: write-file-denied
    context: { tool_name: write_file }
    expected_action: deny

  # Default action (tool not in any rule)
  - name: unknown-tool-uses-default
    context: { tool_name: read_logs }
    expected_action: allow

  # Same checks using expected_allowed (boolean)
  - name: search-documents-is-allowed
    context: { tool_name: search_documents }
    expected_allowed: true

  - name: delete-database-is-not-allowed
    context: { tool_name: delete_database }
    expected_allowed: false
```

Each scenario names a context and an expected result. You can check either the
action string (`expected_action`) or the boolean (`expected_allowed`).

### Running with the CLI

```bash
python -m agent_os.policies.cli test \
  docs/tutorials/policy-as-code/examples/06_test_policy.yaml \
  docs/tutorials/policy-as-code/examples/06_test_scenarios.yaml
```

```
8/8 scenarios passed
```

If any scenario fails, the CLI prints which one and what went wrong:

```
FAIL: transfer-funds-denied: expected deny, got allow
7/8 scenarios passed
```

Exit code 0 means all passed. Exit code 1 means at least one failed.

### Running in Python

The CLI is convenient, but sometimes you want the results in Python — for
custom formatting, integration with a CI pipeline, or testing multiple
policies at once.

```python
from pathlib import Path

import yaml
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

examples_dir = Path("docs/tutorials/policy-as-code/examples")

policy = PolicyDocument.from_yaml(examples_dir / "06_test_policy.yaml")
evaluator = PolicyEvaluator(policies=[policy])

with open(examples_dir / "06_test_scenarios.yaml") as f:
    scenarios = yaml.safe_load(f)["scenarios"]

for scenario in scenarios:
    decision = evaluator.evaluate(scenario["context"])
    expected = scenario.get("expected_action")
    actual = decision.action
    ok = (expected is None) or (actual == expected)
    status = "✅ pass" if ok else "❌ FAIL"
    print(f"{scenario['name']}: {status}")
```

### Example output

```
  Scenario                         Expected   Actual     Result
  --------------------------------------------------------------------
  search-documents-allowed         allow      allow      ✅ pass
  delete-database-denied           deny       deny       ✅ pass
  transfer-funds-denied            deny       deny       ✅ pass
  send-email-denied                deny       deny       ✅ pass
  write-file-denied                deny       deny       ✅ pass
  unknown-tool-uses-default        allow      allow      ✅ pass
  search-documents-is-allowed      true       true       ✅ pass
  delete-database-is-not-allowed   false      false      ✅ pass

  ✅ 8/8 scenarios passed
```

---

## Step 3: The test matrix

The scenarios in Step 2 test one policy in isolation. But in production,
**multiple policies apply at the same time**: the reader policy from Chapter 2
and the environment policy from Chapter 4. When both are active, their rules
merge and interact. A rule from one policy can override a rule from another —
and the result might not be what anyone intended.

A **test matrix** crosses every role, every environment, and every tool. It
tests the *combined system*, not individual pieces.

### Building the combined system

Load the role policies from Chapter 2 and the environment policy from Chapter
4. For each role, combine its policy with the shared environment policy:

```python
from pathlib import Path

from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

examples_dir = Path("docs/tutorials/policy-as-code/examples")

reader_policy = PolicyDocument.from_yaml(examples_dir / "02_reader_policy.yaml")
admin_policy = PolicyDocument.from_yaml(examples_dir / "02_admin_policy.yaml")
env_policy = PolicyDocument.from_yaml(examples_dir / "04_env_policy.yaml")

# Each role gets its own policy + the shared environment policy.
# The evaluator merges all rules and sorts by priority.
role_policies = {
    "reader": [reader_policy, env_policy],
    "admin":  [admin_policy, env_policy],
}

tools = ["search_documents", "write_file", "send_email",
         "delete_database", "transfer_funds"]
environments = ["development", "production"]

for tool in tools:
    for role, policies in role_policies.items():
        for env in environments:
            evaluator = PolicyEvaluator(policies=list(policies))
            decision = evaluator.evaluate({"tool_name": tool, "environment": env})
            # check against expected ...
```

When two policies are loaded into one evaluator, their rules are merged into a
single list sorted by priority. The first rule that matches the context wins.
This is where surprising interactions happen.

### Example output

```
  Tool                   reader/dev  reader/prod  admin/dev   admin/prod
  -----------------------------------------------------------------------
  search_documents       ✅ allow     🚫 deny      ✅ allow    🚫 deny
  write_file             ✅ allow ⚠️  🚫 deny      ✅ allow    🚫 deny
  send_email             🚫 deny      🚫 deny      ✅ allow    🚫 deny
  delete_database        🚫 deny      🚫 deny      🚫 deny    🚫 deny
  transfer_funds         ✅ allow     🚫 deny      ✅ allow    🚫 deny

  19/20 cells match expectations.  1 surprise:

  ⚠️  reader + development + write_file
     Expected: deny (reader policy blocks write_file at priority 80)
     Actual:   allow (environment policy allows development at priority 90)
     Reason:   Development environment: agents can act freely
```

### What just happened?

The matrix found a real interaction bug. `block-write-file` is priority 80, but
`allow-development` is priority 90, so the environment rule wins first and the
reader is allowed to write files in development. You would not catch that by
reading the YAML files one at a time.

---

## Step 4: Catch a regression

This is the payoff. Here is a bug that would be nearly invisible to a human
reviewer — but a test catches it instantly.

### The scenario

Someone edits the policy and changes the `transfer_funds` rule's message from:

```
"Sensitive action: transfer_funds requires human approval"
```

to:

```
"Sensitive action: transfer_funds is blocked"
```

The rule still says `action: deny`. Nothing else changed. A YAML diff shows
one line modified. A human reviewer might glance at it and approve.

But in the code, the escalation system uses the phrase `"requires human
approval"` in the message to distinguish an escalation from a hard deny
(Chapter 5). Removing that phrase silently converts an escalation — where a
human could approve the transfer — into an unconditional block.

### What the test shows

```
  Original policy:  transfer_funds → ⏳ escalate (escalate)
  Modified policy:  transfer_funds → 🚫 deny     (deny)

  ❌ Regression detected!
     transfer_funds changed from 'escalate' to 'deny'.
     The edit removed the escalation keyword, so the action
     that used to pause for human review now silently blocks.
```

The test compared the *classification* of the decision, not just the raw
action string. Both versions return `action: deny`, but only the original still
means "escalate."

---

## Full example

```bash
python docs/tutorials/policy-as-code/examples/06_policy_testing.py
```

```
============================================================
  Chapter 6: Policy Testing
============================================================

--- Part 1: Validate the structure ---

  ✅ 'test-policy' loaded successfully
     5 rules, default action: allow

  🚫 Validation failed (as expected):
     Field:   rules -> 0 -> condition -> operator
     Problem: Input should be 'eq', 'ne', 'gt', 'lt', 'gte', 'lte', 'in', 'matches' or 'contains'

  PolicyDocument.from_yaml() catches structural errors
  before any rule is evaluated. A typo like 'equals'
  instead of 'eq' is caught immediately.

--- Part 2: Run test scenarios ---

  Scenario                         Expected   Actual     Result
  --------------------------------------------------------------------
  search-documents-allowed         allow      allow      ✅ pass
  delete-database-denied           deny       deny       ✅ pass
  transfer-funds-denied            deny       deny       ✅ pass
  send-email-denied                deny       deny       ✅ pass
  write-file-denied                deny       deny       ✅ pass
  unknown-tool-uses-default        allow      allow      ✅ pass
  search-documents-is-allowed      true       true       ✅ pass
  delete-database-is-not-allowed   false      false      ✅ pass

  ✅ 8/8 scenarios passed

  Each scenario is one line in a YAML file. The test runner
  evaluates the policy and compares the actual result to the
  expected result. No manual checking required.

--- Part 3: The test matrix ---

  Loading policies from chapters 2 and 4...

  Tool                   reader/dev  reader/prod  admin/dev   admin/prod
  -----------------------------------------------------------------------
  search_documents       ✅ allow     🚫 deny      ✅ allow    🚫 deny
  write_file             ✅ allow ⚠️  🚫 deny      ✅ allow    🚫 deny
  send_email             🚫 deny      🚫 deny      ✅ allow    🚫 deny
  delete_database        🚫 deny      🚫 deny      🚫 deny    🚫 deny
  transfer_funds         ✅ allow     🚫 deny      ✅ allow    🚫 deny

  19/20 cells match expectations.  1 surprise(s):

  ⚠️  reader + development + write_file
     Expected: deny
     Actual:   allow (from rule: allow-development)
     Reason:   Development environment: agents can act freely

  The reader policy blocks write_file at priority 80.
  But the environment policy allows development at priority 90.
  Priority 90 beats 80 — the environment rule fires first.
  Without the test matrix, this interaction is invisible.

--- Part 4: Catch a regression ---

  Scenario: someone edits the policy and removes the phrase
  "requires human approval" from the transfer_funds rule.
  The tool silently flips from escalate to hard deny.

  Original policy:  transfer_funds → ⏳ escalate (escalate)
  Modified policy:  transfer_funds → 🚫 deny     (deny)

  ❌ Regression detected!
     transfer_funds changed from 'escalate' to 'deny'.
     The edit removed the escalation keyword, so the action
     that used to pause for human review now silently blocks.

  A human scanning the YAML diff might miss this. But a test
  scenario that checks for the escalation keyword catches it
  instantly. That is the value of automated policy testing:
  changes that look harmless cannot silently break behavior.

============================================================
  Policies are code. Test them like code.
  Validate the structure, write expected outcomes,
  run them automatically, and catch regressions
  before they reach production.
============================================================
```

---

## How does it work?

```
  Role policy     Environment policy
  (ch2)           (ch4)
      │                │
      └────────┬───────┘
               ▼
  ┌─────────────────────────────────┐
  │  1. Validate each file          │
  │     PolicyDocument.from_yaml()  │
  └──────────┬──────────────────────┘
             ▼
  ┌─────────────────────────────────┐
  │  2. Test each policy alone      │
  │     CLI: policy test            │
  └──────────┬──────────────────────┘
             ▼
  ┌─────────────────────────────────┐
  │  3. Test the combined system    │
  │     Python: multi-policy eval   │
  └──────────┬──────────────────────┘
             │
      ┌──────┴──────┐
      ▼             ▼
  All pass     Surprises found
  ✅ Deploy    ❌ Fix and re-run
```

| Tool | What it does |
|------|-------------|
| `PolicyDocument.from_yaml(path)` | Load YAML and validate against Pydantic schema |
| `PolicyDocument.model_validate(dict)` | Validate a Python dict without loading a file |
| `PolicyEvaluator(policies=[...])` | Merge rules from multiple policies |
| `evaluator.evaluate(context)` | Return a `PolicyDecision` with `allowed`, `action`, `reason` |
| `policy validate <file>` | CLI: validate structure, print OK or FAIL |
| `policy test <policy> <scenarios>` | CLI: run scenarios, print pass count |

---

## Try it yourself

1. **Fix the surprise.** The test matrix found that `reader + development +
   write_file` is unexpectedly allowed. Edit `02_reader_policy.yaml` and
   raise `block-write-file`'s priority to 95 (above the environment policy's
   90). Re-run the script — the ⚠️ should disappear.

2. **Add a staging environment.** The environment policy has rules for
   development and production, but not staging. Add `staging` to the
   environments list in the test matrix. What happens? Does the default deny
   or allow? Add a scenario to verify.

3. **Extend the matrix.** Create a third policy file for an "operator" role
   that can search documents and send emails but cannot write files or delete
   databases. Add it to the Python test matrix and verify the results across
   all environments.

---

## What's missing?

Policies change over time. Legal tells you that `write_file` must now be
blocked in production, not just for readers. The policy needs to be updated
from version 1.0 to version 2.0. But how do you make that change without
accidentally breaking something that was already working?

You need a way to **compare two versions** side by side — see exactly what
changed, run the test suite against *both* versions, and find regressions
before the new version goes live. That is policy versioning.

**Previous:** [Chapter 5 — Approval Workflows](05-approval-workflows.md)
**Next:** [Chapter 7 — Policy Versioning](07-policy-versioning.md) — compare
v1 vs v2 behavior, catch regressions before deploying.
