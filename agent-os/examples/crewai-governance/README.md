# 🛡️ Using Agent OS with CrewAI Agents

> **Govern your CrewAI crews at the kernel level — per-role policies, tool allow-lists, and tamper-proof audit logs.**

---

## Why Govern CrewAI Agents?

CrewAI makes it easy to spin up autonomous multi-agent crews. That power comes with risk:

| Risk | Example |
|------|---------|
| **Over-privileged agents** | A "researcher" agent calling `write_file` or `execute_command` |
| **Prompt injection** | A task input tricks an agent into running `rm -rf /` |
| **No audit trail** | You can't prove *which* agent touched *which* resource |
| **Compliance gaps** | SOC 2 / HIPAA require evidence of access controls |

Agent OS solves these by inserting a **governance kernel** between your crew and the outside world. Every tool call passes through policy checks before it executes — no prompt engineering required.

---

## Quick Start

### 1. Install

```bash
pip install agent-os-kernel crewai   # crewai is optional for the demo
```

### 2. Run the Demo (no API keys needed)

```bash
git clone https://github.com/microsoft/agent-governance-toolkit
cd agent-os/examples/crewai-governance
python demo.py
```

The demo creates three mock agents — **researcher**, **writer**, **reviewer** — and runs them through a policy engine loaded from `policies.yaml`.

---

## How It Works

### Wrap a CrewAI Crew with Agent OS

```
  ┌─────────────┐     ┌──────────────────┐     ┌──────────┐
  │  CrewAI      │────▶│  Agent OS Kernel  │────▶│  Tools   │
  │  Agent       │     │  (policy check)   │     │          │
  └─────────────┘     └──────────────────┘     └──────────┘
         │                     │
         │              ┌──────┴──────┐
         │              │  Audit Log  │
         │              └─────────────┘
         ▼
   If blocked → PermissionError (action never reaches the tool)
```

In code:

```python
from agent_os_governance import RolePolicyEngine, GovernedKernel, AuditLog

engine = RolePolicyEngine("policies.yaml")
audit  = AuditLog()
kernel = GovernedKernel(engine, audit)

# Every tool call goes through the kernel
result = kernel.execute(
    agent_id="agent-researcher",
    role="researcher",
    tool="web_search",
    params="latest AI safety papers",
)
```

---

## Policy Enforcement

Policies are declared in `policies.yaml`:

```yaml
shared:
  blocked_patterns:
    - "rm -rf"
    - "sudo"
    - "DROP TABLE"

roles:
  researcher:
    allowed_tools: [web_search, read_file, list_directory]
    blocked_patterns: [write_file, delete_file, execute_command]
    max_actions: 20

  writer:
    allowed_tools: [read_file, write_file, list_directory]
    blocked_patterns: [web_search, execute_command, delete_file]
    max_actions: 15

  reviewer:
    allowed_tools: [read_file, list_directory]
    blocked_patterns: [write_file, delete_file, web_search, execute_command]
    max_actions: 10
```

### Enforcement layers (checked in order)

1. **Shared blocked patterns** — denied for *every* role (e.g. `rm -rf`, `sudo`).
2. **Role-specific blocked patterns** — denied for a particular role.
3. **Tool allow-list** — only tools explicitly listed may be invoked.
4. **Action budget** — caps the total number of actions per role per task.

---

## Audit Logging

Every action — allowed or blocked — is recorded with:

| Field | Description |
|-------|-------------|
| `timestamp` | UTC ISO-8601 |
| `agent_id` | Unique agent identifier |
| `role` | CrewAI role name |
| `tool` | Tool that was requested |
| `input_hash` | SHA-256 hash of raw input (never logs raw data) |
| `decision` | `ALLOWED` or `BLOCKED` |
| `reason` | Human-readable explanation |

Export the log as JSON for your compliance pipeline:

```python
print(audit.to_json())
```

---

## Before / After

### ❌ Before — Ungoverned CrewAI Crew

```python
from crewai import Agent, Task, Crew

researcher = Agent(role="Researcher", tools=[web_search, read_file, write_file])
# ⚠️  researcher can write files — no guardrails
# ⚠️  no audit trail
# ⚠️  a prompt injection could trigger destructive tools
crew = Crew(agents=[researcher], tasks=[...])
crew.kickoff()
```

### ✅ After — Governed with Agent OS

```python
from crewai import Agent, Task, Crew

# 1. Load policies
engine = RolePolicyEngine("policies.yaml")
audit  = AuditLog()
kernel = GovernedKernel(engine, audit)

# 2. Wrap tools so every call routes through the kernel
safe_search = kernel.wrap_tool("researcher", web_search)
safe_read   = kernel.wrap_tool("researcher", read_file)

researcher = Agent(role="Researcher", tools=[safe_search, safe_read])
crew = Crew(agents=[researcher], tasks=[...])
crew.kickoff()

# 3. Export audit log
print(audit.to_json())
```

**What changed?**
- The researcher can *only* invoke `web_search` and `read_file`.
- `write_file` calls are blocked at the kernel level — even if the LLM tries.
- Every action is logged with a SHA-256 input hash for compliance.

---

## Files

| File | Purpose |
|------|---------|
| `demo.py` | Runnable demo — no API keys required |
| `policies.yaml` | Per-role governance policies |
| `README.md` | This tutorial |

---

## Learn More

- [Agent OS repository](https://github.com/microsoft/agent-governance-toolkit)
- [CrewAI documentation](https://docs.crewai.com)
- [Agent OS architecture](../../ARCHITECTURE.md)
