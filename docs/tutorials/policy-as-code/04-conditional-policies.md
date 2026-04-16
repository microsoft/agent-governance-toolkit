<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# Chapter 4: Conditional Policies

In Chapters 1-3 each policy stood on its own — one file, one evaluator, one
decision. But in a real company, policies come from different places. The
security team writes company-wide rules. Individual teams write rules for
their own agents. When those policies disagree, the system needs a way to
pick a winner.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [The problem](#the-problem) | Why the same tool needs different rules in different contexts |
| [Environment-aware rules](#step-1-environment-aware-rules) | Same tool, different answer in dev vs prod |
| [Two policies, one agent](#step-2-two-policies-one-agent) | A global security policy and a team-level policy |
| [Spot the conflict](#step-3-spot-the-conflict) | Loading both and seeing where they disagree |
| [Conflict resolver](#step-4-resolve-the-conflict) | Four strategies for picking a winner |
| [Scopes](#step-5-scopes) | How organizational hierarchy affects the outcome |
| [Try it yourself](#try-it-yourself) | Exercises |

---

## The problem

In Chapters 1–3, every rule applied the same way everywhere. But in a real
company, context matters. An agent that can freely call tools in a dev
environment should be locked down in production. And when the security team
and a product team write separate policies for the same agent, those
policies can disagree.

This chapter covers both problems: **environment-aware rules** (dev vs prod)
and **conflict resolution** (what happens when two policies disagree).

---

## Step 1: Environment-aware rules

The simplest conditional policy: the same tool gets a different answer
depending on the environment.

### The policy (`04_env_policy.yaml`)

```yaml
version: "1.0"
name: environment-policy
description: Rules that change based on the deployment environment

rules:
  - name: block-production
    condition:
      field: environment
      operator: eq
      value: production
    action: deny
    priority: 100
    message: "Production environment: all agent actions require approval"

  - name: allow-development
    condition:
      field: environment
      operator: eq
      value: development
    action: allow
    priority: 90
    message: "Development environment: agents can act freely"

defaults:
  action: deny
  max_tool_calls: 5
```

The key idea: the `condition` checks the **environment** field, not the tool
name. The same agent hitting the same tool gets a different answer depending
on where it runs.

### Evaluating it

```python
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

policy = PolicyDocument.from_yaml("04_env_policy.yaml")
evaluator = PolicyEvaluator(policies=[policy])

dev = evaluator.evaluate({"environment": "development"})
prod = evaluator.evaluate({"environment": "production"})

print(dev.allowed)   # True  — dev is open
print(prod.allowed)  # False — production is locked down
```

### Example output

```
  Environment      Decision     Reason
  -------------------------------------------------------
  development      ✅ allow     Development environment: agents can act freely
  staging          🚫 deny      No rules matched; default action applied
  production       🚫 deny      Production environment: all agent actions require approval
```

Notice that `staging` falls through to the default (deny) because no rule
matches it. You decide whether that's safe-by-default or an oversight —
either way, it's explicit.

### When is this enough?

Environment-aware rules work when **one team writes all the rules**. But in
a real company, the security team writes company-wide rules and individual
teams write rules for their own agents. When those policies disagree about
the same tool, the system needs a way to pick a winner.

---

## Step 2: Two policies, one agent

A company has a **security team** that writes rules for all agents. They
decide: "No agent should send emails without controls." They update the
company-wide policy to block `send_email`.

But the **customer support team** pushes back: "Our agent's entire job is
emailing customers. If you block `send_email`, our agent is useless."

Both teams have valid reasons. The security team is protecting the company.
The support team needs their agent to work. Their policies now disagree about
the same tool.

This is not a hypothetical problem. In any organization, broad security
rules and specific team needs will clash. The question is: **who gets the
final say?**

### Global security policy (`04_global_policy.yaml`)

Written by the security team. Applies to every agent in the company.

```yaml
version: "1.0"
name: global-security-policy
description: Company-wide rules set by the security team

rules:
  - name: block-delete-database
    condition:
      field: tool_name
      operator: eq
      value: delete_database
    action: deny
    priority: 100
    message: "Company policy: no agent may delete databases"

  - name: block-send-email
    condition:
      field: tool_name
      operator: eq
      value: send_email
    action: deny
    priority: 90
    message: "Company policy: agents may not send emails without controls"

defaults:
  action: allow
  max_tool_calls: 10
```

Two tools are blocked. Everything else — including `write_file` and
`search_documents` — is allowed by default.

### Support team policy (`04_support_team_policy.yaml`)

Written by the support team lead. Applies only to the support team's agent.

```yaml
version: "1.0"
name: support-team-policy
description: Rules for the customer support team's agent

rules:
  - name: allow-send-email
    condition:
      field: tool_name
      operator: eq
      value: send_email
    action: allow
    priority: 90
    message: "Support team: our agent needs to email customers"

  - name: block-write-file
    condition:
      field: tool_name
      operator: eq
      value: write_file
    action: deny
    priority: 80
    message: "Support team: our agent does not need to write files"

  - name: block-delete-database
    condition:
      field: tool_name
      operator: eq
      value: delete_database
    action: deny
    priority: 100
    message: "Support team: deleting databases is never allowed"

defaults:
  action: allow
  max_tool_calls: 20
```

The support team explicitly allows `send_email` (their agent needs it),
blocks `write_file` (not needed), and blocks `delete_database` (obviously
dangerous). Everything else is allowed.

### Where they agree and disagree

| Tool | Global policy | Team policy | Conflict? |
|------|--------------|-------------|-----------|
| `send_email` | deny | allow | **Yes** — security says no, support says yes |
| `write_file` | allow (default) | deny | **Yes** — opposite directions |
| `delete_database` | deny | deny | No — both agree |
| `search_documents` | allow (default) | allow (default) | No — both agree |

Two out of four tools are in conflict. The interesting one is `send_email` —
a deliberate disagreement between two parts of the organization.

---

## Step 3: Spot the conflict

Load both policies and evaluate each tool against each one separately:

```python
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

global_policy = PolicyDocument.from_yaml("04_global_policy.yaml")
team_policy = PolicyDocument.from_yaml("04_support_team_policy.yaml")

global_eval = PolicyEvaluator(policies=[global_policy])
team_eval = PolicyEvaluator(policies=[team_policy])

g = global_eval.evaluate({"tool_name": "send_email"})
t = team_eval.evaluate({"tool_name": "send_email"})

print(g.allowed)  # False — global says deny
print(t.allowed)  # True  — team says allow
```

Both policies have an opinion about `send_email`, and they disagree.
Loading them both into a single evaluator would merge the rules and pick
one based on priority — but that is fragile and depends on which rule
happens to come first. We need a deliberate strategy.

---

## Step 4: Resolve the conflict

`PolicyConflictResolver` takes conflicting decisions and picks a winner
based on a strategy you choose.

First, wrap each policy's decision into a `CandidateDecision` — a container
that carries the decision along with metadata about where it came from:

```python
from agent_os.policies import (
    CandidateDecision,
    ConflictResolutionStrategy,
    PolicyConflictResolver,
    PolicyScope,
)

# The global policy is company-wide → scope is GLOBAL.
global_candidate = CandidateDecision(
    action="deny",
    priority=90,
    scope=PolicyScope.GLOBAL,
    policy_name="global-security-policy",
    rule_name="block-send-email",
    reason="Company policy: agents may not send emails without controls",
)

# The team policy is for one team → scope is TENANT.
team_candidate = CandidateDecision(
    action="allow",
    priority=90,
    scope=PolicyScope.TENANT,
    policy_name="support-team-policy",
    rule_name="allow-send-email",
    reason="Support team: our agent needs to email customers",
)
```

Now resolve with a strategy:

```python
resolver = PolicyConflictResolver(ConflictResolutionStrategy.DENY_OVERRIDES)
result = resolver.resolve([global_candidate, team_candidate])

print(result.winning_decision.action)       # "deny"
print(result.winning_decision.policy_name)  # "global-security-policy"
print(result.conflict_detected)             # True
```

### The four strategies

| Strategy | How it works | Who wins the send_email conflict? |
|----------|-------------|-----------------------------------|
| **DENY_OVERRIDES** | If anything says deny, deny wins | Security team (deny) |
| **ALLOW_OVERRIDES** | If anything says allow, allow wins | Support team (allow) |
| **PRIORITY_FIRST_MATCH** | Highest priority number wins; ties keep input order | Security team (deny) — listed first, same priority |
| **MOST_SPECIFIC_WINS** | More specific scope wins | Support team — TENANT beats GLOBAL |

Running all four:

```
DENY_OVERRIDES            🚫 deny   (from global-security-policy)
ALLOW_OVERRIDES           ✅ allow  (from support-team-policy)
PRIORITY_FIRST_MATCH      🚫 deny   (from global-security-policy)
MOST_SPECIFIC_WINS        ✅ allow  (from support-team-policy)
```

Same conflict, different outcomes. The strategy is a **business decision**:

- **DENY_OVERRIDES** means the security team always has veto power. This is
  the safest option — no team can override a company-wide block.
- **ALLOW_OVERRIDES** is the opposite — any explicit allow punches through a
  deny. Useful for exception-based governance.
- **PRIORITY_FIRST_MATCH** picks the highest priority number. When priorities
  tie (both are 90 here), the resolver falls back to **input order** — whichever
  candidate appears first in the list wins. The security policy was listed first,
  so it wins. If you swapped the order, the support team would win instead.
  This makes ties fragile, which is why you should avoid giving competing rules
  the same priority.
- **MOST_SPECIFIC_WINS** means the team closest to the agent gets the final
  say. This is more flexible — teams can grant exceptions for their own
  agents.

Most companies pick one strategy and use it consistently. There is no
universally "right" answer — it depends on how much control the security
team wants versus how much autonomy the teams need.

---

## Step 5: Scopes

Each `CandidateDecision` has a scope label that says how broad the policy is:

```
GLOBAL (0)  →  TENANT (1)  →  ORGANIZATION (2)  →  AGENT (3)
broadest                                            most specific
```

Think of it like a company org chart:

- **GLOBAL** = a rule from the CEO that applies to everyone
- **TENANT** = a rule from a division VP that applies to their division
- **ORGANIZATION** = a rule from a department manager within that division
- **AGENT** = a rule written for one specific agent

When using `MOST_SPECIFIC_WINS`, the more specific scope always wins. If two
candidates have the same scope, priority breaks the tie.

### Example: Same scope, priority breaks the tie

What if the security team writes an agent-specific policy too?

```python
# Security upgrades to AGENT scope with priority 95.
# Support stays at AGENT scope with priority 90.

resolver = PolicyConflictResolver(ConflictResolutionStrategy.MOST_SPECIFIC_WINS)
# Security priority: 95, Support priority: 90
# Same scope → higher priority wins → security wins → deny
```

When both policies are at the same scope level, specificity can't break the
tie — so the higher priority number wins, just like `PRIORITY_FIRST_MATCH`.

---

## Full example

```bash
python docs/tutorials/policy-as-code/examples/04_conditional_policies.py
```

```
============================================================
  Chapter 4: Conditional Policies
============================================================

--- Part 1: Environment-aware rules ---

  Environment      Decision     Reason
  -------------------------------------------------------
  development      ✅ allow     Development environment: agents can act freely
  staging          🚫 deny      No rules matched; default action applied
  production       🚫 deny      Production environment: all agent actions require approval

  Same agent, same tool — different answer depending on
  where it runs. Dev is open, production is locked down.

  This works when one team writes all the rules. But what
  happens when the security team and a product team each
  write their own policy — and they disagree?

--- Part 2: Two policies, one agent ---

  Tool                   Global policy      Team policy
  ----------------------------------------------------------
  send_email             🚫 deny             ✅ allow  ⚠️ CONFLICT
  write_file             ✅ allow            🚫 deny   ⚠️ CONFLICT
  delete_database        🚫 deny             🚫 deny
  search_documents       ✅ allow            ✅ allow

  The security team says: deny send_email.
  The support team says: allow send_email.
  Both policies apply to the same agent. Who wins?

--- Part 3: Resolving the send_email conflict ---

  Security team says: deny   send_email  (scope=global)
  Support team says:  allow  send_email  (scope=tenant)

--- Part 4: Four strategies, four outcomes ---

  DENY_OVERRIDES
    Result: 🚫 deny   (from global-security-policy)
    Why:    If anyone says deny, the answer is deny. Safety first.

  ALLOW_OVERRIDES
    Result: ✅ allow  (from support-team-policy)
    Why:    If anyone says allow, the answer is allow. Exceptions win.

  PRIORITY_FIRST_MATCH
    Result: 🚫 deny   (from global-security-policy)
    Why:    Highest priority number wins. Both are 90 — tie goes to whichever candidate was listed first.

  MOST_SPECIFIC_WINS
    Result: ✅ allow  (from support-team-policy)
    Why:    The more specific scope wins. TENANT beats GLOBAL.

--- Part 5: The scope hierarchy ---

  Scopes rank from broadest to most specific:

    GLOBAL (0)  →  TENANT (1)  →  ORGANIZATION (2)  →  AGENT (3)

  With MOST_SPECIFIC_WINS, a closer scope always beats a broader one.

  Scenario A: security=GLOBAL vs support=TENANT
    Winner: support-team-policy (✅ allow)
    TENANT (specificity 1) beats GLOBAL (specificity 0)

  Scenario B: security=GLOBAL vs support=AGENT
    Winner: support-team-policy (✅ allow)
    AGENT (specificity 3) beats GLOBAL (specificity 0)

  Scenario C: both at AGENT scope (tie on scope — priority breaks it)
    Security priority: 95, Support priority: 90
    Winner: global-security-policy (🚫 deny)
    Same scope, so higher priority wins.

============================================================
  Conflict resolution lets you layer policies from different
  parts of the organization without them breaking each other.
============================================================
```

---

## How does it work?

Here is what happens inside `resolver.resolve(candidates)`:

```
  Security team:  deny  send_email  (scope=GLOBAL, priority=90)
  Support team:   allow send_email  (scope=TENANT, priority=90)
        │
        ▼
  ┌──────────────────────────────┐
  │  Which strategy?             │
  └──────────┬───────────────────┘
             │
   ┌─────────┼─────────┬──────────────────┐
   ▼         ▼         ▼                  ▼
 DENY_     ALLOW_    PRIORITY_         MOST_
 OVERRIDES OVERRIDES FIRST_MATCH       SPECIFIC_WINS
   │         │         │                  │
   ▼         ▼         ▼                  ▼
 Any deny? Any allow? Highest          Highest
 Yes → deny Yes → allow priority?      specificity?
                      Both 90 (tie)    TENANT > GLOBAL
   │         │         │                  │
   ▼         ▼         ▼                  ▼
 🚫 deny   ✅ allow  🚫 deny          ✅ allow
```

The candidates stay the same. Only the strategy changes the outcome.

---

## Try it yourself

1. **Resolve the `write_file` conflict.** The global policy allows
   `write_file` (by default) and the team policy denies it. Create two
   `CandidateDecision` objects for this conflict and resolve with
   `DENY_OVERRIDES`. Who wins?

2. **Add a third policy.** Imagine a department-level policy (scope
   `ORGANIZATION`) that denies `send_email`. Now you have three candidates:
   GLOBAL (deny), ORGANIZATION (deny), and TENANT (allow). Resolve with
   `MOST_SPECIFIC_WINS`. Does the support team still win?

3. **Change the priority.** Give the security team's `block-send-email` rule
   priority 95 (higher than the team's 90). Re-run with
   `PRIORITY_FIRST_MATCH`. Now security wins — because its number is bigger.

---

## What's missing?

We can now layer policies from different parts of the organization and
resolve conflicts between them. But some actions are too important for any
automatic decision. Deleting a customer's account, transferring money, or
sending a mass email — these are actions where neither "allow" nor "deny" is
the right automatic answer. You want a **human to review and approve** before
the agent proceeds.

**Previous:** [Chapter 3 — Rate Limiting](03-rate-limiting.md)
**Next:** [Chapter 5 — Approval Workflows](05-approval-workflows.md) — route
dangerous actions to a human before execution.
