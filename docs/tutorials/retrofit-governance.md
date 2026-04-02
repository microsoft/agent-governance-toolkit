# Retrofit Governance onto an Existing Agent

Got an AI agent already running in production? This tutorial shows you how to
add policy enforcement, blocked-pattern detection, and an audit trail in **three
steps** — without rewriting your existing logic.

**What you'll learn:**

| Step | What happens |
|------|-------------|
| [1. Install](#step-1-install) | Add the toolkit with one command |
| [2. Wrap](#step-2-wrap-your-agent) | Two lines of code around your existing agent |
| [3. Configure](#step-3-configure-policy-with-yaml) | Drop in a single YAML file to define your rules |
| [Verify](#verify-it-works) | Run the companion script and see governance in action |

---

## The Agent We're Starting With

Here's a typical "before" agent — useful, but completely ungoverned. It happily
executes whatever it's asked:

```python
# before.py  ← your existing code, untouched
def run_agent(user_input: str) -> str:
    """A simple agent with no guardrails."""
    # ... your existing LLM calls, tool calls, etc.
    return f"Agent result for: {user_input}"

# No checks, no audit trail, no blocked patterns
result = run_agent("DROP TABLE users;")
print(result)  # 😬 executes without question
```

By the end of this tutorial, the same `run_agent` call will be intercepted,
evaluated against policy, and either allowed or blocked — with every decision
written to an audit trail.

---

## Step 1: Install

```bash
pip install agent-governance-toolkit[full]
```

That's it. No infrastructure changes, no config files yet.

> **Note:** `[full]` pulls in YAML policy support, framework integrations, and
> audit tooling. For a minimal install you can use `pip install agent-os-kernel`
> instead, but YAML policy loading requires the `[nexus]` or `[full]` extra.

---

## Step 2: Wrap Your Agent

Add two imports and wrap your existing function with a governance kernel. Your
original `run_agent` logic stays completely unchanged:

```python
# after.py  ← the only new code you write
from agent_os.integrations import LangChainKernel          # swap for your framework
from agent_os.integrations.base import GovernancePolicy

# --- NEW: create a kernel (one-time setup) ---
policy = GovernancePolicy(
    name="my-agent-policy",
    blocked_patterns=["DROP TABLE", "rm -rf", "os.system"],
    max_tool_calls=10,
)
kernel = LangChainKernel(policy=policy)
ctx = kernel.create_context("my-agent")

# --- your original function, unchanged ---
def run_agent(user_input: str) -> str:
    """A simple agent with no guardrails."""
    return f"Agent result for: {user_input}"

# --- NEW: check before every call ---
def governed_run(user_input: str) -> str:
    allowed, reason = kernel.pre_execute(ctx, user_input)
    if not allowed:
        print(f"🚫 BLOCKED — {reason}")
        return ""
    result = run_agent(user_input)
    print(f"✅ ALLOWED — {result}")
    return result
```

The key additions are:

1. **`GovernancePolicy`** — declares what's blocked and what limits apply.
2. **`kernel.pre_execute(ctx, input)`** — evaluates the input against that
   policy before your code runs. Returns `(allowed: bool, reason: str)`.

Don't use LangChain? Swap `LangChainKernel` for `OpenAIAgentsKernel`,
`CrewAIKernel`, or `AutoGenKernel` — the `pre_execute` API is identical across
all integrations. See [Tutorial 03 — Framework Integrations](03-framework-integrations.md).

---

## Step 3: Configure Policy with YAML

Inline Python policy is fine for quick tests, but for real projects you want
policy in a file you can review, version-control, and update without touching
code.

Create `policies/my-agent.yaml`:

```yaml
# policies/my-agent.yaml
version: "1.0"
name: my-agent-policy
description: >
  Governance policy for my existing agent.
  Blocks destructive commands and PII leakage.

rules:
  - name: block-destructive-sql
    condition:
      field: input
      operator: contains_any
      value: ["DROP TABLE", "TRUNCATE", "DELETE FROM"]
    action: block
    priority: 100
    message: "Destructive SQL is not permitted."

  - name: block-shell-injection
    condition:
      field: input
      operator: regex
      value: '(rm\s+-rf|os\.system|subprocess\.call)'
    action: block
    priority: 90
    message: "Shell injection patterns are blocked."

  - name: flag-pii
    condition:
      field: input
      operator: regex
      value: '\b\d{3}-\d{2}-\d{4}\b'   # SSN pattern
    action: audit                         # log it, but don't block
    priority: 50
    message: "Possible SSN detected — logged for review."

defaults:
  action: allow
  max_tool_calls: 10
```

Then load it with the policy evaluator instead of the inline `GovernancePolicy`:

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_policies("./policies/")          # loads all .yaml files in the dir

def governed_run(user_input: str) -> str:
    decision = evaluator.evaluate({"input": user_input})
    if not decision.allowed:
        print(f"🚫 BLOCKED [{decision.action}] — {decision.reason}")
        return ""
    result = run_agent(user_input)
    print(f"✅ ALLOWED — {result}")
    return result
```

Now your entire policy lives in YAML: easy to audit, diff in pull requests, and
hand off to a security team.

---

## Verify It Works

Run the standalone companion script included with this tutorial:

```bash
python examples/quickstart/retrofit_governed.py
```

Expected output:

```
============================================================
  Retrofit Governance — Verification Demo
============================================================

[1] Dangerous SQL input …
    🚫 BLOCKED — policy=my-agent-policy  reason=Blocked pattern matched: 'DROP TABLE'

[2] Shell injection attempt …
    🚫 BLOCKED — policy=my-agent-policy  reason=Blocked pattern matched: 'rm -rf'

[3] Safe input …
    ✅ ALLOWED — Agent result for: Summarise last week's sales report

── Audit Trail ─────────────────────────────────────────────
  [1] 2025-...  input='DROP TABLE users;'     status=BLOCKED
  [2] 2025-...  input='rm -rf /data'          status=BLOCKED
  [3] 2025-...  input='Summarise last week…'  status=ALLOWED

🎉 Governance is working. 3 decisions logged.
```

If you see this output, your agent is now governed. Every decision — allow or
block — is written to the audit trail automatically.

---

## What Changed? (Before vs. After)

| | Before | After |
|---|---|---|
| **Lines of new code** | — | ~10 |
| **Original agent logic** | unchanged | unchanged |
| **Policy location** | none | `policies/my-agent.yaml` |
| **Blocked patterns** | none | `DROP TABLE`, `rm -rf`, shell injection |
| **Audit trail** | none | every decision logged with timestamp |
| **Deployment change** | — | none — pure Python, no infra required |

---

## Next Steps

- **[Tutorial 01 — Policy Engine](01-policy-engine.md):** Full YAML syntax,
  operators, conflict resolution.
- **[Tutorial 02 — Trust & Identity](02-trust-and-identity.md):** Add
  cryptographic agent identity and trust scoring.
- **[Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md):** Persist
  your audit trail and generate OWASP ASI compliance reports.
- **[Example policies](../../examples/policies/):** Drop-in YAML files for
  SQL safety, PII detection, MCP security, and more.