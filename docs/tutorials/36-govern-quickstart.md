# Tutorial 36: 2-Line Governance with govern()

> **Time**: 10 minutes · **Level**: Beginner · **Prerequisites**: `pip install agent-governance-toolkit`

## What You'll Build

A governed AI tool with full policy enforcement, audit logging, and denial handling — in just 2 lines of code.

## The Problem

Traditional AGT integration requires understanding multiple components and how to wire them:

```python
# ❌ The old way (10+ lines)
from agentmesh.governance import PolicyEngine, Policy, AuditLog

engine = PolicyEngine(conflict_strategy="deny_overrides")
engine.load_yaml(policy_yaml)
audit = AuditLog()
context = {"action": {"type": action}, ...}
decision = engine.evaluate("my-agent", context)
audit.log("policy_evaluation", "my-agent", action, outcome=decision.action, ...)
if not decision.allowed:
    raise Exception(f"Denied: {decision.reason}")
result = my_tool(**kwargs)
```

## The Solution

```python
# ✅ The new way (2 lines)
from agentmesh.governance import govern

safe_tool = govern(my_tool, policy="my-policy.yaml")
```

---

## Example 1: Governed Database Query Tool

```python
from agentmesh.governance import govern

def query_database(action="read", table="users", **filters):
    """Simulate a database query tool."""
    print(f"  Querying {table} ({action}) with filters: {filters}")
    return {"table": table, "action": action, "rows": 42}

# Create the governed version
safe_query = govern(query_database, policy="""
apiVersion: governance.toolkit/v1
name: db-access-policy
agents: ["*"]
default_action: allow
rules:
  - name: block-drop
    condition: "action.type == 'drop'"
    action: deny
    description: "DROP operations are never allowed"
    priority: 100

  - name: block-write-to-audit
    condition: "action.type == 'write' and table.value == 'audit_log'"
    action: deny
    description: "Audit log is append-only — no direct writes"
    priority: 100

  - name: require-approval-for-delete
    condition: "action.type == 'delete'"
    action: require_approval
    approvers: ["dba-team"]
    priority: 50
""")

# ✅ This works
result = safe_query(action="read", table="users", limit=10)
print(f"Result: {result}")

# ❌ This is denied
try:
    safe_query(action="drop", table="users")
except Exception as e:
    print(f"Blocked: {e}")
```

Output:
```
  Querying users (read) with filters: {'limit': 10}
Result: {'table': 'users', 'action': 'read', 'rows': 42}
Blocked: Action denied by policy rule 'block-drop': ...
```

## Example 2: Custom Deny Handler

Instead of raising exceptions, handle denials gracefully:

```python
from agentmesh.governance import govern

def send_email(to, subject, body):
    return {"sent": True, "to": to}

safe_send = govern(
    send_email,
    policy="email-policy.yaml",
    on_deny=lambda decision: {
        "sent": False,
        "blocked_by": decision.matched_rule,
        "reason": decision.reason,
    },
)

# If denied, returns the dict instead of raising
result = safe_send(action="send", to="external@gmail.com", subject="Q3 Revenue")
# → {"sent": False, "blocked_by": "block-external-pii", "reason": "..."}
```

## Example 3: File-Based Policy with Extends

```python
from agentmesh.governance import govern

safe_tool = govern(
    my_agent_tool,
    policy="policies/team-policy.yaml",   # loads extends chain automatically
    agent_id="customer-service-agent-1",
)
```

## Example 4: Inspect the Audit Trail

```python
safe_tool = govern(my_tool, policy="policy.yaml")

# Execute some actions
safe_tool(action="read")
safe_tool(action="query")

# Inspect what happened
for entry in safe_tool.audit_log.query():
    print(f"  {entry.action} → {entry.outcome} (rule: {entry.data.get('rule', 'none')})")
```

## Example 5: Access the Engine for Advanced Use

```python
safe = govern(my_tool, policy="policy.yaml")

# Direct policy evaluation (bypass the wrapper)
decision = safe.engine.evaluate("my-agent", {
    "action": {"type": "export"},
    "data": {"classification": "restricted"},
})
print(f"Would be: {decision.action} by {decision.matched_rule}")
```

---

## Quick Reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `policy` | str or Policy | required | File path, inline YAML, or Policy object |
| `agent_id` | str | `"*"` | Agent identifier for policy evaluation |
| `audit` | bool | `True` | Enable audit logging |
| `on_deny` | callable | `None` | Custom handler (default: raise GovernanceDenied) |
| `approval_handler` | ApprovalHandler | `None` | Human-in-the-loop handler |
| `advisory` | AdvisoryCheck | `None` | Non-deterministic defense-in-depth |
| `conflict_strategy` | str | `"deny_overrides"` | How to resolve rule conflicts |

## What to Try Next

- **Tutorial 35**: Policy composition with `extends`
- **Tutorial 38**: Human-in-the-loop approval workflows
- **Tutorial 39**: DLP with attribute ratchets
