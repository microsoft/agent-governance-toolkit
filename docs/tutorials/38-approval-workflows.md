# Tutorial 38: Human-in-the-Loop Approval Workflows

> **Time**: 15 minutes · **Level**: Intermediate · **Prerequisites**: Tutorial 36 (govern basics)

## What You'll Build

An agent governance setup where high-risk actions (large transfers, data exports, admin operations) pause execution and wait for human approval before proceeding.

## Why This Matters

In regulated industries (FSI, healthcare, legal), certain agent actions require explicit human authorization. AGT's `require_approval` policy action pauses the agent, notifies a human, and resumes or denies based on their response.

---

## Step 1: Define a Policy with Approval Gates

```yaml
# financial-approval-policy.yaml
apiVersion: governance.toolkit/v1
name: financial-approvals
agents: ["*"]
default_action: allow

rules:
  - name: approve-large-transfer
    condition: "action.type == 'transfer'"
    action: require_approval
    approvers: ["treasury-ops", "compliance"]
    description: "All transfers require human approval"
    priority: 100

  - name: approve-account-close
    condition: "action.type == 'close_account'"
    action: require_approval
    approvers: ["branch-manager"]
    description: "Account closures need branch manager sign-off"
    priority: 100

  - name: block-delete
    condition: "action.type == 'delete'"
    action: deny
    description: "Delete operations are never allowed"
    priority: 1000
```

## Step 2: Simple Callback Approval

The simplest handler — a function that decides approval.

```python
from agentmesh.governance import (
    govern, CallbackApproval, ApprovalDecision, GovernanceDenied,
)

def process_transfer(action, amount, to_account):
    print(f"  💰 Transferring ${amount} to {to_account}")
    return {"transferred": True, "amount": amount}

# Approval logic — in production, this would call Slack/Teams/Jira
def my_approval_logic(request):
    print(f"\n  🔔 APPROVAL NEEDED")
    print(f"     Rule: {request.rule_name}")
    print(f"     Action: {request.action}")
    print(f"     Approvers: {', '.join(request.approvers)}")

    # Auto-approve for demo (in production: call external service)
    if request.action == "transfer":
        return ApprovalDecision(
            approved=True,
            approver="treasury-ops@company.com",
            reason="Within daily limit",
        )
    return ApprovalDecision(approved=False, approver="system", reason="Unknown action type")

handler = CallbackApproval(my_approval_logic, timeout_seconds=300)

safe_transfer = govern(
    process_transfer,
    policy="financial-approval-policy.yaml",
    approval_handler=handler,
)

# This triggers the approval flow
result = safe_transfer(action="transfer", amount=5000, to_account="ACC-789")
print(f"Result: {result}")
```

Output:
```
  🔔 APPROVAL NEEDED
     Rule: approve-large-transfer
     Action: transfer
     Approvers: treasury-ops, compliance
  💰 Transferring $5000 to ACC-789
Result: {'transferred': True, 'amount': 5000}
```

## Step 3: Webhook Approval (Slack/Teams)

For production, send approval requests to an external service:

```python
from agentmesh.governance import govern, WebhookApproval

handler = WebhookApproval(
    url="https://hooks.slack.com/services/T00/B00/xxx",
    timeout_seconds=300,    # 5 minutes to respond
    headers={"Authorization": "Bearer slack-token"},
)

safe_tool = govern(
    my_tool,
    policy="policy.yaml",
    approval_handler=handler,
)
```

The webhook receives a POST with:
```json
{
  "type": "approval_request",
  "rule_name": "approve-large-transfer",
  "policy_name": "financial-approvals",
  "agent_id": "*",
  "action": "transfer",
  "approvers": ["treasury-ops", "compliance"],
  "requested_at": "2026-04-23T12:00:00Z"
}
```

And must respond with:
```json
{
  "approved": true,
  "approver": "jane@company.com",
  "reason": "Reviewed and approved"
}
```

## Step 4: Conditional Approval Logic

Build smarter approval handlers that consider context:

```python
from agentmesh.governance import CallbackApproval, ApprovalDecision

def smart_approval(request):
    # Extract amount from the context
    amount = request.context.get("amount", {}).get("value", 0)

    # Auto-approve small amounts during business hours
    from datetime import datetime
    hour = datetime.now().hour
    if amount < 1000 and 9 <= hour <= 17:
        return ApprovalDecision(
            approved=True,
            approver="auto:business-hours-policy",
            reason=f"Auto-approved: ${amount} within business hours limit",
        )

    # Require human for everything else
    # In production: send to Slack, wait for callback
    return ApprovalDecision(
        approved=False,
        approver="system:pending",
        reason=f"${amount} requires manual review (outside auto-approve threshold)",
    )

handler = CallbackApproval(smart_approval)
```

## Step 5: Verify the Audit Trail

Every approval decision is logged with the approver's identity:

```python
safe = govern(tool, policy="policy.yaml", approval_handler=handler)
safe(action="transfer", amount=500)

# Check what happened
for entry in safe.audit_log.query(event_type="approval_decision"):
    print(f"  {entry.action} → {entry.outcome}")
    print(f"    Approver: {entry.data['approver']}")
    print(f"    Reason: {entry.data['reason']}")
```

## Key Behaviors

| Scenario | What Happens |
|----------|-------------|
| No handler configured | `require_approval` → auto-denied (fail-safe) |
| Handler approves | Action executes normally |
| Handler rejects | `GovernanceDenied` raised (or `on_deny` callback) |
| Handler times out | Auto-denied after timeout (default 5 min) |
| Handler throws error | Auto-denied (fail-safe) |
| `deny` rule matches | Denied immediately — approval handler never called |

---

## What to Try Next

- **Tutorial 35**: Policy composition (inherit approval rules from parent)
- **Tutorial 39**: Attribute ratchets (combine with approval for DLP)
- **Tutorial 41**: Defense-in-depth with advisory classifiers
