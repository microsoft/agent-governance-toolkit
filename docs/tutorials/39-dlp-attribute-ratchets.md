# Tutorial 39: DLP with Attribute Ratchets

> **Time**: 15 minutes · **Level**: Intermediate · **Prerequisites**: Tutorial 37 (multi-stage pipeline)

## What You'll Build

A Data Loss Prevention (DLP) system where an agent's permissions tighten automatically after it touches sensitive data — and cannot be reset for the rest of the session.

## The Problem

Without session state, each tool call is evaluated independently:

```
Agent reads confidential document    → ✅ allowed
Agent sends email with that content  → ✅ allowed (policy doesn't know about the read!)
```

With attribute ratchets:

```
Agent reads confidential document    → ✅ allowed, sensitivity ratchets to "confidential"
Agent tries to send email externally → ❌ blocked (session.data_sensitivity == "confidential")
Agent tries to reset sensitivity     → ❌ ignored (monotonic — can only go up)
```

---

## Step 1: Define Session Attributes

```python
from agentmesh.governance import SessionState, SessionAttribute

state = SessionState([
    SessionAttribute(
        name="data_sensitivity",
        ordering=["public", "internal", "confidential", "restricted"],
        monotonic=True,
        initial="public",
    ),
    SessionAttribute(
        name="data_jurisdiction",
        ordering=["domestic", "eu", "cross_border"],
        monotonic=True,
        initial="domestic",
    ),
])

print(f"Initial sensitivity: {state.get('data_sensitivity')}")
# → "public"
```

## Step 2: Create DLP Policy

```yaml
# dlp-policy.yaml
apiVersion: governance.toolkit/v1
name: dlp-policy
agents: ["*"]
default_action: allow

rules:
  # Block email when handling sensitive data
  - name: block-email-sensitive
    stage: pre_tool
    condition: "action.type == 'send_email' and session.data_sensitivity in ['confidential', 'restricted']"
    action: deny
    description: "Cannot send emails after accessing confidential data"
    priority: 900

  # Block file export for restricted data
  - name: block-export-restricted
    stage: pre_tool
    condition: "action.type == 'export' and session.data_sensitivity == 'restricted'"
    action: deny
    description: "Restricted data cannot be exported"
    priority: 1000

  # Require approval for cross-border transfers
  - name: approve-cross-border
    stage: pre_tool
    condition: "action.type == 'transfer' and session.data_jurisdiction == 'cross_border'"
    action: require_approval
    approvers: ["data-protection-officer"]
    priority: 800

  # Allow read operations (but they may ratchet sensitivity)
  - name: allow-read
    stage: pre_tool
    condition: "action.type == 'read'"
    action: allow
    priority: 100
```

## Step 3: Simulate an Agent Session

```python
from agentmesh.governance import PolicyEngine, SessionState, SessionAttribute

engine = PolicyEngine(conflict_strategy="deny_overrides")
engine.load_yaml_file("dlp-policy.yaml")

state = SessionState([
    SessionAttribute(
        name="data_sensitivity",
        ordering=["public", "internal", "confidential", "restricted"],
        monotonic=True,
    ),
])

# ── Turn 1: Agent reads a public document ──────────────────
ctx1 = {"action": {"type": "read"}, "resource": {"type": "document", "classification": "public"}}
state.inject_context(ctx1)
result1 = engine.evaluate("*", ctx1)
print(f"1. Read public doc: {result1.action}")  # → allow

# Simulate: tool returns classification = public (no ratchet)

# ── Turn 2: Agent reads a confidential report ──────────────
ctx2 = {"action": {"type": "read"}, "resource": {"type": "document", "classification": "confidential"}}
state.inject_context(ctx2)
result2 = engine.evaluate("*", ctx2)
print(f"2. Read confidential report: {result2.action}")  # → allow

# Simulate: tool reports this document is confidential
state.set("data_sensitivity", "confidential")
print(f"   → Sensitivity ratcheted to: {state.get('data_sensitivity')}")

# ── Turn 3: Agent tries to email the content ───────────────
ctx3 = {"action": {"type": "send_email"}}
state.inject_context(ctx3)
result3 = engine.evaluate("*", ctx3)
print(f"3. Send email: {result3.action}")        # → DENY!
print(f"   Rule: {result3.matched_rule}")         # → block-email-sensitive

# ── Turn 4: Agent tries to "forget" the sensitivity ────────
reset_ok = state.set("data_sensitivity", "public")
print(f"4. Reset sensitivity: {reset_ok}")         # → False (monotonic!)
print(f"   Still: {state.get('data_sensitivity')}") # → confidential

# ── Turn 5: Sensitivity can still go UP ────────────────────
state.set("data_sensitivity", "restricted")
print(f"5. Ratcheted to: {state.get('data_sensitivity')}")  # → restricted
```

Output:
```
1. Read public doc: allow
2. Read confidential report: allow
   → Sensitivity ratcheted to: confidential
3. Send email: deny
   Rule: block-email-sensitive
4. Reset sensitivity: False
   Still: confidential
5. Ratcheted to: restricted
```

## Step 4: Parse from YAML

Define session attributes directly in your policy YAML:

```python
state = SessionState.from_policy_yaml("""
session_attributes:
  - name: data_sensitivity
    ordering: [public, internal, confidential, restricted]
    monotonic: true
    initial: public

  - name: user_verified
    ordering: [unverified, email_verified, mfa_verified]
    monotonic: true
    initial: unverified
""")
```

## Step 5: Reset Between Sessions

```python
# End of session — reset for next user
state.reset()
print(state.get("data_sensitivity"))  # → "public" (back to initial)
```

## Real-World DLP Patterns

| Attribute | Ordering | Use Case |
|-----------|----------|----------|
| `data_sensitivity` | public → restricted | Document classification ratchet |
| `data_jurisdiction` | domestic → cross_border | GDPR/data residency |
| `auth_level` | anonymous → mfa_verified | Progressive authentication |
| `risk_score` | low → critical | Cumulative risk escalation |
| `compliance_status` | clean → flagged → blocked | Compliance state machine |

---

## What to Try Next

- **Tutorial 37**: Multi-stage pipeline (post_tool sets sensitivity, pre_tool enforces it)
- **Tutorial 41**: Combine ratchets with advisory layer for ML-based classification
