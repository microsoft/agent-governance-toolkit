<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# Chapter 5: Approval Workflows

In Chapters 1–4, every policy decision was instant: allow or deny. The system
evaluated the rules, picked a winner, and the agent moved on. But some actions
are too important for any automatic answer. Deleting a customer's account,
transferring money, or sending a mass email — these are cases where you want a
**human to review and approve** before the agent proceeds.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [The problem](#the-problem) | Why allow/deny is not enough for high-stakes actions |
| [The three-outcome model](#step-1-the-three-outcome-model) | Adding ESCALATE between ALLOW and DENY |
| [Create an escalation request](#step-2-create-an-escalation-request) | Building a "ticket" for human review |
| [Human approves](#step-3-human-approves) | What happens when the reviewer says yes |
| [Human denies](#step-4-human-denies) | What happens when the reviewer says no |
| [Timeout](#step-5-timeout--nobody-responds) | What happens when nobody responds |
| [Try it yourself](#try-it-yourself) | Exercises |

---

## The problem

Think of a bank teller. A customer walks up and asks to deposit a check —
the teller processes it immediately. But when a customer asks to wire $50,000
overseas, the teller does not press the button. They call a manager. The
manager reviews the request, checks the account, and either approves or
rejects it.

The agent is the teller. The policy system is the rule book that says which
transactions need a manager. And the `EscalationHandler` is the manager.

In Chapters 1–4, every tool call was like a deposit — the system gave an
instant answer. This chapter adds the wire transfer: actions where the system
says "I cannot decide this alone" and routes the request to a human.

The system goes from **two possible outcomes** (allow, deny) to **three**
(allow, deny, escalate). This is the first time a policy decision is not
immediate — the agent must pause until a human responds or a timeout triggers.

---

## Step 1: The three-outcome model

### The policy (`05_approval_policy.yaml`)

```yaml
version: "1.0"
name: approval-workflow-policy
description: >
  Policy with three decision tiers: allow, deny, and escalate.
  Tools whose message says "requires human approval" are routed
  to a human reviewer before the agent may proceed.

rules:
  # Tier 1: Always allowed — safe, read-only actions
  - name: allow-search-documents
    condition:
      field: tool_name
      operator: eq
      value: search_documents
    action: allow
    priority: 80
    message: "Safe action: searching documents is always allowed"

  # Tier 2: Always denied — irreversibly destructive
  - name: block-delete-database
    condition:
      field: tool_name
      operator: eq
      value: delete_database
    action: deny
    priority: 100
    message: "Destructive action: deleting databases is never allowed"

  # Tier 3: Escalate — needs human review
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

defaults:
  action: allow
  max_tool_calls: 10
```

Three tiers:

- **Tier 1 (allow):** `search_documents` is read-only — always safe.
- **Tier 2 (deny):** `delete_database` is irreversibly destructive — always
  blocked, no point asking a human.
- **Tier 3 (escalate):** `transfer_funds` and `send_email` are neither always
  safe nor always dangerous. Their message says `"requires human approval"` —
  the Python code sees that phrase and routes the tool call to a human
  reviewer instead of blocking it outright.

### Evaluating the policy

```python
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

policy = PolicyDocument.from_yaml("05_approval_policy.yaml")
evaluator = PolicyEvaluator(policies=[policy])

ESCALATION_KEYWORD = "requires human approval"

for tool in ["search_documents", "delete_database", "transfer_funds"]:
    decision = evaluator.evaluate({"tool_name": tool})
    if decision.allowed:
        print(f"{tool}: allow")
    elif ESCALATION_KEYWORD in decision.reason.lower():
        print(f"{tool}: escalate — needs human approval")
    else:
        print(f"{tool}: deny")
```

### Example output

```
  Tool                   Decision       Reason
  -------------------------------------------------------
  search_documents       ✅ allow     Safe action: searching documents is always allowed
  write_file             ✅ allow     No rules matched; default action applied
  delete_database        🚫 deny      Destructive action: deleting databases is never allowed
  transfer_funds         ⏳ escalate  Sensitive action: transfer_funds requires human approval
  send_email             ⏳ escalate  Sensitive action: send_email requires human approval
```

---

## Step 2: Create an escalation request

When the policy says "requires human approval", the agent cannot proceed on
its own. It creates an **escalation request** — a ticket that contains the
agent's ID, the action it wants to take, and why it needs approval.

```python
from agent_os.integrations.escalation import (
    EscalationHandler,
    InMemoryApprovalQueue,
)

queue = InMemoryApprovalQueue()
handler = EscalationHandler(backend=queue, timeout_seconds=300)

request = handler.escalate(
    agent_id="finance-agent",
    action="transfer_funds",
    reason="Agent wants to transfer $5,000 to vendor account",
)

print(request.request_id)  # a1b2c3d4-...  (unique ID)
print(request.decision)    # EscalationDecision.PENDING
print(len(queue.list_pending()))  # 1
```

### What just happened?

1. `handler.escalate()` created an `EscalationRequest` with a unique ID.
2. It submitted the request to the `InMemoryApprovalQueue`.
3. The request's status is `PENDING` — the agent is now **suspended**.
4. The queue has one pending item. Someone needs to review it.

### Example output

```
  Request ID:  a1b2c3d4...
  Agent:       finance-agent
  Action:      transfer_funds
  Reason:      Agent wants to transfer $5,000 to vendor account
  Status:      ⏳ PENDING

  Pending requests in queue: 1
```

The agent is waiting. What happens next depends on the human reviewer.

---

## Step 3: Human approves

A manager reviews the pending request and decides the transfer is legitimate:

```python
queue.approve(request.request_id, approver="manager@corp.com")
final = handler.resolve(request.request_id)

print(final)  # EscalationDecision.ALLOW
```

`queue.approve()` marks the request as approved and records **who** approved
it. `handler.resolve()` checks the queue and returns the final decision.

In production, the agent and the reviewer are on different sides. The agent
calls `handler.resolve()`, which blocks and waits. A human uses a separate
interface — a dashboard, a Slack bot, or an API endpoint — to call
`queue.approve()` or `queue.deny()`. Here we simulate both sides in one
script for simplicity.

### Example output

```
  manager@corp.com approved request a1b2c3d4...
  Final decision: ✅ ALLOW

  The manager approved the transfer. The agent can proceed.
```

The audit trail now records: the finance-agent requested `transfer_funds`,
it was escalated, and manager@corp.com approved it. Every step is traceable.

---

## Step 4: Human denies

Not every escalation gets approved. The compliance team reviews a request to
send a promotional email to 10,000 customers and says no:

```python
request2 = handler.escalate(
    agent_id="support-agent",
    action="send_email",
    reason="Agent wants to email 10,000 customers a promotional offer",
)

queue.deny(request2.request_id, approver="compliance@corp.com")
final2 = handler.resolve(request2.request_id)

print(final2)  # EscalationDecision.DENY
```

### Example output

```
  compliance@corp.com denied request e5f6g7h8...
  Final decision: 🚫 DENY

  Compliance reviewed the request and said no.
  The agent must not send the email.
```

This is different from the automatic deny in Step 1. `delete_database` is
blocked by the policy — no human is involved. But `send_email` was reviewed
by a person, and the audit trail records **who** made the call and **when**.

---

## Step 5: Timeout — nobody responds

What if the human reviewer is on vacation? Or the request lands in a queue
nobody checks? The agent cannot wait forever.

`EscalationHandler` has a **timeout** with a configurable **default action**.
When the timeout expires with no response, the system picks the default:

```python
from agent_os.integrations.escalation import DefaultTimeoutAction

timeout_handler = EscalationHandler(
    backend=InMemoryApprovalQueue(),
    timeout_seconds=300,            # 5 minutes in production
    default_action=DefaultTimeoutAction.DENY,  # safe default
)
```

If nobody approves or denies within 300 seconds, the system defaults to
**DENY**. The agent does not proceed.

### Why DENY is the safe default

An unanswered escalation should not silently become an approval. If a human
is supposed to review an action and nobody does, the safest assumption is
that the action should not happen. You can set `DefaultTimeoutAction.ALLOW`
for less critical actions, but that is rare — if the action were not
important, it would not need escalation in the first place.

### Example output

```
  Request i9j0k1l2... is waiting for approval...
  Timeout after 0s with no response.
  Final decision: 🚫 DENY (safe default)

  When nobody responds, the system fails safe.
  DefaultTimeoutAction.DENY ensures unanswered
  requests do not become silent approvals.
```

---

## Full example

```bash
python docs/tutorials/policy-as-code/examples/05_approval_workflows.py
```

```
============================================================
  Chapter 5: Approval Workflows
============================================================

--- Part 1: The three-outcome model ---

  Tool                   Decision       Reason
  -------------------------------------------------------
  search_documents       ✅ allow     Safe action: searching documents is always allowed
  write_file             ✅ allow     No rules matched; default action applied
  delete_database        🚫 deny      Destructive action: deleting databases is never allowed
  transfer_funds         ⏳ escalate  Sensitive action: transfer_funds requires human approval
  send_email             ⏳ escalate  Sensitive action: send_email requires human approval

  For the first time, the system has three outcomes.
  transfer_funds and send_email are not automatically
  allowed or denied — they are paused until a human reviews.

--- Part 2: Creating an escalation request ---

  Request ID:  a1b2c3d4...
  Agent:       finance-agent
  Action:      transfer_funds
  Reason:      Agent wants to transfer $5,000 to vendor account
  Status:      ⏳ PENDING

  Pending requests in queue: 1

  The agent is now suspended. A ticket exists in the
  approval queue. Someone needs to review it.

--- Part 3: Human approves ---

  manager@corp.com approved request a1b2c3d4...
  Final decision: ✅ ALLOW

  The manager approved the transfer. The agent can proceed.

--- Part 4: Human denies ---

  compliance@corp.com denied request e5f6g7h8...
  Final decision: 🚫 DENY

  Compliance reviewed the request and said no.
  The agent must not send the email.

--- Part 5: Timeout — nobody responds ---

  Request i9j0k1l2... is waiting for approval...
  Timeout after 0s with no response.
  Final decision: 🚫 DENY (safe default)

  When nobody responds, the system fails safe.
  DefaultTimeoutAction.DENY ensures unanswered
  requests do not become silent approvals.

  In production, timeouts are typically 300 seconds
  (5 minutes) or more — enough time for a human to
  review, but not so long that the agent waits forever.

============================================================
  The policy system now has three tiers: allow, deny,
  and escalate. Sensitive actions wait for a human
  before the agent proceeds — or time out safely.
============================================================
```

Note: Request IDs are randomly generated UUIDs — your output will show
different IDs than the examples above.

---

## How does it work?

Here is the lifecycle of an escalation, from the agent's tool call to the
final decision:

```
  Agent wants to call transfer_funds
        │
        ▼
  ┌──────────────────────────────┐
  │  Policy evaluator says:      │
  │  "requires human approval"   │
  └──────────┬───────────────────┘
             │
             ▼
  ┌──────────────────────────────┐
  │  EscalationHandler           │
  │  creates request (PENDING)   │
  │  submits to approval queue   │
  └──────────┬───────────────────┘
             │
      ┌──────┼──────────┐
      ▼      ▼          ▼
   Human   Human     Nobody
   approves denies   responds
      │      │          │
      ▼      ▼          ▼
   ✅ ALLOW 🚫 DENY  ⏳ TIMEOUT
                        │
                        ▼
                   Safe default
                   (usually DENY)
```

The key classes:

| Class | Role |
|-------|------|
| `InMemoryApprovalQueue` | Stores pending requests; humans call `approve()` or `deny()` on it |
| `EscalationHandler` | Creates requests, manages the timeout, resolves the final decision |
| `EscalationRequest` | The "ticket" — carries the agent ID, action, reason, and current status |
| `EscalationDecision` | Enum with five states: `ALLOW`, `DENY`, `ESCALATE`, `PENDING`, `TIMEOUT` |
| `DefaultTimeoutAction` | What to do when the timeout expires: `DENY` (safe) or `ALLOW` (rare) |

In production, the approval queue would not be in-memory — it would be backed
by a database, a message broker, or a webhook that pings a Slack channel or
email inbox. The library also provides `WebhookApprovalBackend` for HTTP-based
notification workflows. For critical actions that need multiple sign-offs, the
library supports quorum-based approval via `QuorumConfig`, where M of N
reviewers must agree before an action proceeds.

---

## Try it yourself

1. **Change the safe default.** In Part 5, swap `DefaultTimeoutAction.DENY`
   for `DefaultTimeoutAction.ALLOW` and re-run. What changes? When would
   this be appropriate?

2. **Add a new escalation rule.** Add `delete_account` to the YAML policy
   as an escalation-worthy tool (Tier 3). Update the Python script to
   include it in the tools list and verify it shows ⏳ escalate.

---

## What's missing?

We now have policies that allow, deny, and escalate. But how do you know they
work correctly **together**? What if someone edits the YAML and accidentally
removes the `"requires human approval"` message from the `transfer_funds`
rule? That tool would silently flip from "escalate" to "deny" — and nobody
would notice until a real transfer fails.

Manual checking does not scale. You need **automated tests** that verify
every tool gets the right decision in every environment. That is policy
testing.

**Previous:** [Chapter 4 — Conditional Policies](04-conditional-policies.md)
**Next:** [Chapter 6 — Policy Testing](06-policy-testing.md) — verify that every
policy rule works correctly, automatically.
