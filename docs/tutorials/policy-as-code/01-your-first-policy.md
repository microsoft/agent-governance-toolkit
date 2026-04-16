<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# Chapter 1: Your First Policy

In this chapter you will write a YAML policy file that blocks dangerous agent
actions and then evaluate it with a few lines of Python.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [What is a policy?](#what-is-a-policy) | The core idea behind policy-as-code |
| [Write the YAML](#step-1-write-the-yaml-policy) | Create your first policy file |
| [Evaluate with Python](#step-2-evaluate-with-python) | Load and test the policy |
| [Try it yourself](#try-it-yourself) | Exercises to reinforce what you learned |

---

## What is a policy?

A **policy** is a set of rules that decide whether an agent's action is allowed
or denied. Think of it like a checklist a security guard follows:

- Agent wants to **delete a database** → check the list → **not allowed**
- Agent wants to **send an email** → check the list → **not allowed**
- Agent wants to **search documents** → check the list → nothing says no → **allowed**

With policy-as-code, those rules live in a YAML file that anyone can read,
review, and version-control — not buried inside application logic.

---

## Step 1: Write the YAML policy

Create a file called `01_first_policy.yaml`:

```yaml
version: "1.0"
name: my-first-policy
description: A simple policy that blocks dangerous agent actions

rules:
  - name: block-delete-database
    condition:
      field: tool_name
      operator: eq
      value: delete_database
    action: deny
    priority: 100
    message: "Deleting databases is not allowed"

  - name: block-send-email
    condition:
      field: tool_name
      operator: eq
      value: send_email
    action: deny
    priority: 90
    message: "Sending emails requires approval"

defaults:
  action: allow
  max_tool_calls: 10
```

Let's break that down piece by piece.

### The header

```yaml
version: "1.0"
name: my-first-policy
description: A simple policy that blocks dangerous agent actions
```

Every policy needs a `version`, a `name`, and a short `description`. These help
you identify the policy later when you have many of them.

### A single rule

```yaml
- name: block-delete-database
  condition:
    field: tool_name
    operator: eq
    value: delete_database
  action: deny
  priority: 100
  message: "Deleting databases is not allowed"
```

| Field | Meaning |
|-------|---------|
| `name` | A human-readable label for this rule |
| `condition.field` | Which piece of context to check — here, the name of the tool the agent wants to use |
| `condition.operator` | How to compare — `eq` means "equals" |
| `condition.value` | The value to compare against |
| `action` | What to do when the condition matches — `deny` blocks the action |
| `priority` | Higher numbers are checked first |
| `message` | Explanation shown when the rule triggers |

Reading it out loud: *"If the tool name equals `delete_database`, deny the
action."*

### Defaults

```yaml
defaults:
  action: allow
  max_tool_calls: 10
```

If none of the rules match, the **default** action applies. Here we set it to
`allow` — meaning anything not explicitly blocked is permitted.

---

## Step 2: Evaluate with Python

Now we use `PolicyEvaluator` to load the YAML file and check agent actions
against it.

```python
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

# 1. Create an evaluator and load a specific policy file
evaluator = PolicyEvaluator()
policy = PolicyDocument.from_yaml("01_first_policy.yaml")
evaluator.policies.append(policy)

# 2. Simulate an agent action — a dictionary describing what the agent wants to do
context = {"tool_name": "delete_database"}

# 3. Evaluate the context against the loaded policy
decision = evaluator.evaluate(context)

# 4. Check the result
print(decision.allowed)  # False
print(decision.reason)   # "Deleting databases is not allowed"
```

The four steps are always the same: **create → load → evaluate → act on the
decision**.

### Full example output

Run the complete example:

```bash
python docs/tutorials/policy-as-code/examples/01_first_policy.py
```

```
============================================================
  Chapter 1: Your First Policy
============================================================

🚫 Agent tries to delete a database
   Tool:   delete_database
   Result: DENIED
   Reason: Deleting databases is not allowed

🚫 Agent tries to send an email
   Tool:   send_email
   Result: DENIED
   Reason: Sending emails requires approval

✅ Agent tries to search documents
   Tool:   search_documents
   Result: ALLOWED
   Reason: No rules matched; default action applied

============================================================
  Done. 3 actions evaluated.
============================================================
```

Notice how `search_documents` was allowed — no rule mentions it, so the default
`allow` action kicks in.

---

## How does it work?

Here is what happens inside `evaluator.evaluate(context)`:

```
context = {"tool_name": "search_documents"}
        │
        ▼
┌────────────────────────────────────┐
│  Rule: block-delete-database       │
│  tool_name == delete_database?     │──▶ No, skip
└────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────┐
│  Rule: block-send-email            │
│  tool_name == send_email?          │──▶ No, skip
└────────────────────────────────────┘
        │
        ▼
   No rule matched
        │
        ▼
   Apply default → ALLOW ✅
```

Rules are checked in priority order (highest first). The first rule that matches
determines the decision. If nothing matches, the default action applies.

---

## Try it yourself

1. **Add a new rule** that blocks `restart_server` and re-run the example.
2. **Change the default** from `allow` to `deny`. What happens to
   `search_documents` now?
3. **Add a rule** that explicitly *allows* `search_documents` with action
   `allow` — does it still work when the default is `deny`?

---

## What's missing?

This policy works, but it's not production-ready yet. Right now every agent
shares the same rules — a read-only assistant and a powerful admin are treated
identically. In the next chapter we fix that by giving each role its own policy.

**Next:** [Chapter 2 — Capability Scoping](02-capability-scoping.md) — give
different agents different permissions.
