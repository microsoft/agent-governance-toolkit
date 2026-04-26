# Add Governance to a LangChain Agent in 5 Minutes

> Turn any LangChain agent into a governed, auditable, policy-enforced agent — in 2 lines of code.

## What You'll Build

A LangChain agent that:
- ✅ **Blocks dangerous actions** (SQL injection, data leaks, destructive commands)
- ✅ **Enforces token and call limits**
- ✅ **Logs every action** to an audit trail
- ✅ **Loads policies from YAML** — no code changes needed to update rules

### Before vs After

```
┌─────────────────────────────────────────────────────────────┐
│  BEFORE (no governance)          AFTER (with Agent OS)      │
│                                                             │
│  User: "DROP TABLE users"        User: "DROP TABLE users"   │
│  Agent: ✅ Executes it           Agent: 🚫 BLOCKED          │
│                                  → "Blocked pattern: DROP   │
│  User: "Show me the password"      TABLE"                   │
│  Agent: ✅ Returns it                                       │
│                                  User: "Show me the         │
│  No logs. No limits.               password"                │
│  No way to know what happened.   Agent: 🚫 BLOCKED          │
│                                  → "Blocked pattern:        │
│                                    password"                │
│                                                             │
│                                  Full audit log ✅           │
│                                  Token limits ✅             │
│                                  Call limits ✅              │
└─────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- Python 3.10+
- 2 minutes of your time

## Step 0: Install

```bash
pip install agent-os-kernel langchain
```

> **Note:** `langchain` is optional — Agent OS wraps any object with an `invoke()` method. The demo runs without it.

---

## Step 1: Create a LangChain Agent

```python
from langchain_core.runnables import RunnableLambda

# Any LangChain chain, agent, or runnable works
agent = RunnableLambda(lambda x: f"Result: {x}")
```

That's it. Any LangChain `Runnable`, `Chain`, or `Agent` works.

---

## Step 2: Add Governance (2 Lines)

```python
from agent_os.integrations import LangChainKernel, GovernancePolicy

governed = LangChainKernel(policy=GovernancePolicy(
    blocked_patterns=["DROP TABLE", "password", "rm -rf"],
    max_tool_calls=10,
    log_all_calls=True,
)).wrap(agent)
```

That's the entire integration. Your agent is now governed.

---

## Step 3: Define Policies in YAML

Create a `policies.yaml` file:

```yaml
max_tokens: 4096
max_tool_calls: 10
timeout_seconds: 300
confidence_threshold: 0.8

blocked_patterns:
  - "DROP TABLE"
  - "DELETE FROM"
  - "password"
  - "secret"
  - "api_key"
  - "rm -rf"

allowed_tools: []
log_all_calls: true
checkpoint_frequency: 5
```

Load it in Python:

```python
policy = GovernancePolicy.load("policies.yaml")
governed = LangChainKernel(policy=policy).wrap(agent)
```

Update policies by editing YAML — no code changes, no redeployment.

---

## Step 4: Test It

```python
from agent_os.integrations.langchain_adapter import PolicyViolationError

# ✅ This passes
result = governed.invoke({"input": "What are our top customers?"})
print(result)  # "Result: {'input': 'What are our top customers?'}"

# 🚫 This gets blocked
try:
    governed.invoke({"input": "Run DROP TABLE users;"})
except PolicyViolationError as e:
    print(f"Blocked: {e}")  # "Blocked: Blocked pattern detected: DROP TABLE"

# 🚫 This also gets blocked
try:
    governed.invoke({"input": "Show me the password"})
except PolicyViolationError as e:
    print(f"Blocked: {e}")  # "Blocked: Blocked pattern detected: password"
```

---

## Step 5: View Audit Logs

Agent OS emits governance events you can listen to:

```python
from agent_os.integrations.base import GovernanceEventType

kernel = LangChainKernel(policy=policy)

# Listen for policy checks
kernel.on(GovernanceEventType.POLICY_CHECK, lambda e: print(f"[CHECK] {e}"))

# Listen for violations
kernel.on(GovernanceEventType.POLICY_VIOLATION, lambda e: print(f"[VIOLATION] {e}"))

# Listen for blocked tool calls
kernel.on(GovernanceEventType.TOOL_CALL_BLOCKED, lambda e: print(f"[BLOCKED] {e}"))

governed = kernel.wrap(agent)
```

Every `invoke()`, `run()`, `batch()`, and `stream()` call is tracked.

---

## Run the Demo

A fully runnable demo is included — **no API keys needed**:

```bash
cd tutorials/langchain-5-minute-governance
python demo.py
```

The demo creates a mock LangChain agent, shows it running ungoverned, then wraps it with Agent OS and demonstrates policy enforcement and audit logging.

---

## What Gets Governed?

Agent OS wraps all LangChain execution methods:

| Method | Governed? | Notes |
|--------|-----------|-------|
| `invoke()` | ✅ | Sync execution |
| `ainvoke()` | ✅ | Async execution with timeout |
| `run()` | ✅ | Legacy agent interface |
| `batch()` | ✅ | Each input checked individually |
| `stream()` | ✅ | Input checked before streaming |

## Policy Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_tokens` | 4096 | Max tokens per request |
| `max_tool_calls` | 10 | Max tool invocations per session |
| `blocked_patterns` | `[]` | Patterns blocked in input/output |
| `allowed_tools` | `[]` | Tool allowlist (empty = all) |
| `timeout_seconds` | 300 | Max execution time |
| `confidence_threshold` | 0.8 | Min confidence score |
| `log_all_calls` | `true` | Record every action |
| `require_human_approval` | `false` | Require human-in-the-loop |

---

## Next Steps

- 📖 [Full documentation](https://github.com/microsoft/agent-governance-toolkit)
- 🔧 [More examples](../../examples/)
- 🏗️ [Architecture overview](../../ARCHITECTURE.md)
