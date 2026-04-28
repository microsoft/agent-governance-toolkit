<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# Chapter 2: Capability Scoping

In Chapter 1 you created a single policy that applies to every agent. In
practice, different agents need different permissions — a **reader** agent should
only search and read, while an **admin** agent can do more.

This chapter shows how to scope capabilities by assigning each role its own
policy file.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [The idea](#the-idea) | Why different agents need different rules |
| [Two policy files](#step-1-create-a-policy-per-role) | A restrictive reader policy and a permissive admin policy |
| [Evaluate both roles](#step-2-evaluate-both-roles) | Load the right policy for the right agent |
| [Try it yourself](#try-it-yourself) | Exercises |

---

## The idea

Imagine a company with two types of AI assistants:

| Role | Allowed actions | Blocked actions |
|------|----------------|-----------------|
| **Reader** | Search documents | Send email, write files, delete databases |
| **Admin** | Search, send email, write files | Delete databases |

The key principle is **least privilege** — every agent gets the minimum
permissions it needs to do its job and nothing more.

The simplest way to implement this: **one YAML policy file per role**.

---

## Step 1: Create a policy per role

### Reader policy (`02_reader_policy.yaml`)

```yaml
version: "1.0"
name: reader-policy
description: Restrictive policy for read-only agents

rules:
  - name: block-delete-database
    condition:
      field: tool_name
      operator: eq
      value: delete_database
    action: deny
    priority: 100
    message: "Reader agents cannot delete databases"

  - name: block-send-email
    condition:
      field: tool_name
      operator: eq
      value: send_email
    action: deny
    priority: 90
    message: "Reader agents cannot send emails"

  - name: block-write-file
    condition:
      field: tool_name
      operator: eq
      value: write_file
    action: deny
    priority: 80
    message: "Reader agents cannot write files"

defaults:
  action: allow
  max_tool_calls: 10
```

Three rules, each blocking a specific tool. Everything else is allowed by
default, so `search_documents` passes through.

### Admin policy (`02_admin_policy.yaml`)

```yaml
version: "1.0"
name: admin-policy
description: Permissive policy for admin agents

rules:
  - name: block-delete-database
    condition:
      field: tool_name
      operator: eq
      value: delete_database
    action: deny
    priority: 100
    message: "Nobody is allowed to delete databases"

defaults:
  action: allow
  max_tool_calls: 50
```

Only one rule — even admins cannot delete a database. Everything else is allowed.
Notice the admin also gets a higher `max_tool_calls` limit (50 vs 10).

### Comparing the two

| Action | Reader | Admin |
|--------|--------|-------|
| `search_documents` | allowed | allowed |
| `send_email` | **denied** | allowed |
| `write_file` | **denied** | allowed |
| `delete_database` | **denied** | **denied** |

---

## Step 2: Evaluate both roles

To scope capabilities, you load the correct policy file for the agent's role:

```python
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

def load_single_policy(filename: str) -> PolicyEvaluator:
    """Create an evaluator loaded with one specific policy file."""
    evaluator = PolicyEvaluator()
    policy = PolicyDocument.from_yaml(filename)
    evaluator.policies.append(policy)
    return evaluator

# Each role gets its own evaluator
reader_evaluator = load_single_policy("02_reader_policy.yaml")
admin_evaluator = load_single_policy("02_admin_policy.yaml")

# Same action, different result depending on the role
reader_decision = reader_evaluator.evaluate({"tool_name": "send_email"})
admin_decision = admin_evaluator.evaluate({"tool_name": "send_email"})

print(reader_decision.allowed)  # False — reader can't send email
print(admin_decision.allowed)   # True  — admin can
```

### Full example output

```bash
python docs/tutorials/policy-as-code/examples/02_capability_scoping.py
```

```
================================================================
  Chapter 2: Capability Scoping
================================================================

  Action                    Reader          Admin
  -------------------------------------------------------
  search_documents          ✅ allowed       ✅ allowed
  send_email                🚫 denied        ✅ allowed
  write_file                🚫 denied        ✅ allowed
  delete_database           🚫 denied        🚫 denied

================================================================
  Same actions, different permissions per role.
================================================================
```

Same four actions, but the reader is blocked from three of them while the admin
is only blocked from one.

---

## When to use this pattern

Capability scoping works well when:

- You have **distinct agent roles** with clearly different permission levels
- You want to **review and audit** each role's permissions in a separate file
- You want to **add a new role** by simply adding a new YAML file

In a real application, your code would pick the right policy file based on the
agent's identity — for example by looking up the agent's role from a
configuration or trust credential.

---

## Try it yourself

1. **Create a `moderator-policy.yaml`** that can send emails and search, but
   cannot write files or delete databases. Add it to the script and compare all
   three roles.
2. **What happens if you load both policy files** into the same evaluator? Which
   rules win? (Hint: think about priority numbers.)
3. **Change the reader's default** from `allow` to `deny`. Now the reader is
   blocked from everything *except* actions you explicitly allow. Add a rule
   that allows `search_documents`.

---

## What's missing?

We now have per-role permissions, but nothing prevents an agent from calling the
same tool over and over. A reader agent could fire `search_documents` a thousand
times in a second — burning tokens, overloading APIs, and running up costs. In
production, you need **rate limits**.

**Previous:** [Chapter 1 — Your First Policy](01-your-first-policy.md)
**Next:** [Chapter 3 — Rate Limiting](03-rate-limiting.md) — prevent agents from
doing too many things too fast.
