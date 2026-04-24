# Tutorial 35: Policy Composition — Enterprise Governance Layers

> **Time**: 15 minutes · **Level**: Intermediate · **Prerequisites**: Tutorial 01 (policy basics)

## What You'll Build

A 3-tier policy hierarchy where an organization's CISO defines non-negotiable security baselines, a platform team adds shared-service controls, and an app team configures use-case-specific rules — all composed into a single enforceable policy at runtime.

```
org-baseline.yaml        ← CISO: "Never export PII"
    └── platform-shared.yaml   ← Platform: "Rate-limit API calls"
            └── app-policy.yaml    ← App team: "Allow read, deny write after hours"
```

## Why This Matters

Enterprise governance is never owned by one person. Without composition:
- Security rules get copy-pasted across 50 agent configs
- One team forgets to include the PII rule → data leak
- Updating a baseline means touching every agent's config

With `extends`, each team owns their layer. Changes propagate automatically.

---

## Step 1: Create the Org Baseline

This file lives in your central policy repo. No team can weaken these rules.

```yaml
# policies/org-baseline.yaml
apiVersion: governance.toolkit/v1
name: org-baseline
description: "Organization-wide non-negotiable controls"
default_action: deny

rules:
  - name: block-pii-export
    condition: "action.type == 'export' and data.contains_pii"
    action: deny
    description: "PII data must never leave the system"
    priority: 1000

  - name: block-credential-access
    condition: "action.type == 'read' and resource.type == 'credentials'"
    action: deny
    description: "Direct credential access is forbidden"
    priority: 1000

  - name: audit-everything
    condition: "true"
    action: log
    priority: 0
    description: "All actions are logged for compliance"
```

## Step 2: Create Platform Shared Controls

The platform team adds rate limiting and tool restrictions that apply across all agents on their infrastructure.

```yaml
# policies/platform-shared.yaml
apiVersion: governance.toolkit/v1
name: platform-shared
extends: org-baseline.yaml
description: "Platform-level controls for all agents"
default_action: deny

rules:
  - name: rate-limit-api
    condition: "action.type == 'api_call'"
    action: warn
    limit: "100/hour"
    priority: 500
    description: "API calls limited to 100/hour per agent"

  - name: block-external-network
    condition: "action.type == 'http_request' and target.is_external"
    action: require_approval
    approvers: ["platform-oncall"]
    priority: 800
    description: "External HTTP requests need platform team approval"
```

## Step 3: Create App-Specific Policy

The application team adds their use-case rules. Note: they **cannot** weaken the org baseline.

```yaml
# policies/customer-service-agent.yaml
apiVersion: governance.toolkit/v1
name: customer-service-agent
extends:
  - platform-shared.yaml
description: "Policy for customer service chatbot agent"
default_action: deny

rules:
  - name: allow-read-tickets
    condition: "action.type == 'read' and resource.type == 'ticket'"
    action: allow
    priority: 100

  - name: allow-send-response
    condition: "action.type == 'send_message' and target.type == 'customer'"
    action: allow
    priority: 100

  - name: block-refund-over-500
    condition: "action.type == 'refund' and amount.value > 500"
    action: require_approval
    approvers: ["cs-manager"]
    priority: 200
    description: "Refunds over $500 require manager approval"
```

## Step 4: Load and Evaluate

```python
from agentmesh.governance import PolicyEngine

engine = PolicyEngine(conflict_strategy="deny_overrides")
policy = engine.load_yaml_file("policies/customer-service-agent.yaml")

# Check: what rules did we inherit?
print(f"Loaded {len(policy.rules)} rules from 3-tier hierarchy:")
for rule in policy.rules:
    print(f"  [{rule.priority}] {rule.name} → {rule.action}")
```

Output:
```
Loaded 7 rules from 3-tier hierarchy:
  [1000] block-pii-export → deny
  [1000] block-credential-access → deny
  [0] audit-everything → log
  [500] rate-limit-api → warn
  [800] block-external-network → require_approval
  [100] allow-read-tickets → allow
  [100] allow-send-response → allow
```

## Step 5: Test Additive-Only Enforcement

What happens if the app team tries to override the PII export rule?

```yaml
# BAD: This rule will be silently ignored
rules:
  - name: block-pii-export      # same name as parent deny rule
    condition: "action.type == 'export'"
    action: allow                # trying to weaken parent deny!
```

AGT logs a warning and drops the override:
```
WARNING - Policy 'customer-service-agent' rule 'block-pii-export' attempts to weaken parent deny — ignored
```

## Step 6: Use with govern()

```python
from agentmesh.governance import govern

def process_ticket(action, **kwargs):
    return {"action": action, "status": "done", **kwargs}

safe_process = govern(
    process_ticket,
    policy="policies/customer-service-agent.yaml",
)

# ✅ Allowed — reading tickets is in the app policy
safe_process(action="read", resource={"type": "ticket"})

# ❌ Denied — PII export blocked by org baseline (inherited)
safe_process(action="export", data={"contains_pii": True})
# GovernanceDenied: Policy 'org-baseline' blocked export. Rule: 'block-pii-export'.
```

---

## What to Try Next

- **Diamond inheritance**: Two policies extending the same parent (rules deduplicated automatically)
- **4+ levels**: Organization → Division → Team → Agent
- **Combine with stages**: Parent defines `pre_input` rules, child adds `post_tool` rules (Tutorial 37)
