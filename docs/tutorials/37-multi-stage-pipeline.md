# Tutorial 37: Multi-Stage Policy Pipeline

> **Time**: 15 minutes · **Level**: Intermediate · **Prerequisites**: Tutorial 36 (govern basics)

## What You'll Build

A 4-stage governance pipeline that checks agent actions at every point in the execution lifecycle — from user input to agent response.

```
User Input → [pre_input] → Agent Reasoning → [pre_tool] → Tool Call → [post_tool] → [pre_output] → Response
               ↓ deny?                         ↓ deny?                  ↓ deny?        ↓ deny?
            "Injection!"                     "Not allowed"           "PII in output"  "Secrets leaked"
```

## The 4 Stages

| Stage | When It Runs | What It Catches |
|-------|-------------|-----------------|
| `pre_input` | Before agent processes user input | Prompt injection, jailbreak patterns |
| `pre_tool` | Before a tool call executes | Unauthorized actions, rate limits (default) |
| `post_tool` | After tool returns, before agent uses result | PII in tool output, data classification |
| `pre_output` | Before agent response reaches the user | Credential leaks, hallucinated secrets |

## Complete Example: Financial Agent

```yaml
# financial-agent-policy.yaml
apiVersion: governance.toolkit/v1
name: financial-agent
agents: ["*"]
default_action: allow

rules:
  # ── Stage 1: Pre-Input ──────────────────────────────────
  - name: block-injection
    stage: pre_input
    condition: "input.contains_injection"
    action: deny
    description: "Prompt injection detected"
    priority: 1000

  - name: block-role-override
    stage: pre_input
    condition: "input.has_role_override"
    action: deny
    description: "Role override attempt detected"
    priority: 1000

  # ── Stage 2: Pre-Tool ──────────────────────────────────
  - name: block-unauthorized-transfer
    stage: pre_tool
    condition: "action.type == 'transfer' and amount.value > 10000"
    action: require_approval
    approvers: ["treasury-manager"]
    description: "Transfers > $10K need treasury approval"
    priority: 500

  - name: block-external-api
    stage: pre_tool
    condition: "action.type == 'http_request' and target.is_external"
    action: deny
    description: "No external API calls from financial agents"
    priority: 800

  - name: allow-read-accounts
    stage: pre_tool
    condition: "action.type == 'read' and resource.type == 'account'"
    action: allow
    priority: 100

  # ── Stage 3: Post-Tool ──────────────────────────────────
  - name: block-pii-in-response
    stage: post_tool
    condition: "tool.output.contains_pii"
    action: deny
    description: "Tool returned PII — must be redacted before agent uses it"
    priority: 900

  - name: classify-sensitive-output
    stage: post_tool
    condition: "tool.output.classification == 'restricted'"
    action: deny
    description: "Restricted data cannot be forwarded to the agent"
    priority: 950

  # ── Stage 4: Pre-Output ──────────────────────────────────
  - name: block-credential-leak
    stage: pre_output
    condition: "response.contains_credentials"
    action: deny
    description: "Agent response contains credentials — blocked"
    priority: 1000

  - name: block-internal-urls
    stage: pre_output
    condition: "response.contains_internal_urls"
    action: deny
    description: "Internal URLs must not reach the end user"
    priority: 800
```

## Using It with govern()

```python
from agentmesh.governance import govern, PolicyEngine

# Load the multi-stage policy
engine = PolicyEngine(conflict_strategy="deny_overrides")
policy = engine.load_yaml_file("financial-agent-policy.yaml")

# Group rules by stage
from collections import Counter
stage_counts = Counter(r.stage for r in policy.rules)
print("Rules per stage:", dict(stage_counts))
# → {'pre_input': 2, 'pre_tool': 3, 'post_tool': 2, 'pre_output': 2}
```

## Manual Stage-by-Stage Evaluation

For agents that need explicit control over when each stage fires:

```python
from agentmesh.governance import PolicyEngine

engine = PolicyEngine(conflict_strategy="deny_overrides")
engine.load_yaml_file("financial-agent-policy.yaml")

# Stage 1: Check user input
input_check = engine.evaluate("*", {
    "input": {"contains_injection": False, "has_role_override": False},
}, stage="pre_input")
print(f"Input check: {input_check.action}")  # → allow

# Stage 2: Check tool call
tool_check = engine.evaluate("*", {
    "action": {"type": "read"},
    "resource": {"type": "account"},
}, stage="pre_tool")
print(f"Tool check: {tool_check.action}")    # → allow

# Stage 3: Check tool output
output_check = engine.evaluate("*", {
    "tool": {"output": {"contains_pii": True}},
}, stage="post_tool")
print(f"Output check: {output_check.action}")  # → deny (PII detected!)

# Stage 4: Check agent response (only if stage 3 passed)
response_check = engine.evaluate("*", {
    "response": {"contains_credentials": False, "contains_internal_urls": False},
}, stage="pre_output")
print(f"Response check: {response_check.action}")  # → allow
```

## Combining Stages with Composition

Parent policies can define `pre_input` rules while children add `post_tool` rules:

```yaml
# org-baseline.yaml — CISO defines input security
rules:
  - name: org-injection-block
    stage: pre_input
    condition: "input.contains_injection"
    action: deny

# app-policy.yaml — App team adds DLP checks
extends: org-baseline.yaml
rules:
  - name: app-pii-check
    stage: post_tool
    condition: "tool.output.contains_pii"
    action: deny
```

The merged policy has rules across multiple stages from different governance layers.

---

## What to Try Next

- **Tutorial 39**: Attribute ratchets (post_tool sets sensitivity → pre_tool blocks export)
- **Tutorial 40**: OTel observability (trace each stage independently)
