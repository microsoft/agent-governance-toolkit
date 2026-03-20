# Testing Guide — How to Use the Agent Governance Toolkit

> This guide walks you through using the Agent Governance Toolkit as an external
> customer would, from zero to a fully governed AI agent. No prior knowledge required.

## What Is This Toolkit?

The Agent Governance Toolkit is **not** a portal or a UI. It's a **Python library** that sits
between your AI agent and the tools it uses (APIs, databases, files). Think of it as a
security middleware — every action your agent tries to take gets checked against your
policies before it's allowed to execute.

```
Your Agent → [Governance Toolkit] → Tool/API/Database
                    ↓
              Policy check: ALLOW or DENY
              Audit log: who did what, when
```

## Prerequisites

- Python 3.10+ installed
- An API key for any LLM provider (OpenAI, Azure OpenAI, or Google Gemini)
- 10 minutes

---

## Path 1: Run the Live Demo (Fastest — 5 minutes)

This is the best way to see what the toolkit does. The demo runs 4 governance
scenarios with a real LLM and shows you policy enforcement in action.

### Step 1: Clone and install

```bash
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-governance-toolkit
pip install -e "packages/agent-os[dev]"
pip install -e "packages/agent-mesh"
pip install -e "packages/agent-compliance"
pip install httpx pyyaml
```

### Step 2: Set your LLM API key

Pick ONE of these (the demo auto-detects which one you have):

```bash
# Option A: OpenAI
export OPENAI_API_KEY="sk-..."

# Option B: Azure OpenAI
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"

# Option C: Google Gemini
export GOOGLE_API_KEY="..."
```

On Windows PowerShell, use `$env:OPENAI_API_KEY = "sk-..."` instead of `export`.

### Step 3: Run the demo

```bash
python demo/maf_governance_demo.py
```

You'll see 4 scenarios:

| Scenario | What Happens | What Governance Does |
|----------|-------------|---------------------|
| 1. Policy Enforcement | Agent tries to use tools | Policies allow/deny based on YAML rules |
| 2. Capability Sandboxing | Agent tries a blocked tool | Governance blocks it before execution |
| 3. Rogue Agent Detection | Agent behaves suspiciously | Behavioral scoring flags the anomaly |
| 4. Content Filtering | Agent gets a dangerous prompt | Governance blocks it pre-LLM |

### Step 4: Run adversarial attacks

```bash
python demo/maf_governance_demo.py --include-attacks
```

This adds a 5th scenario that tries to break governance:
- Prompt injection ("ignore all previous instructions...")
- Tool alias bypass (calling a blocked tool by another name)
- Trust score manipulation
- SQL injection

You'll see each attack attempt and whether governance blocked it.

### What to look for

- **⚠ Storage: IN-MEMORY ONLY** warning at startup (expected — demo doesn't persist)
- **⚠ Policy: SAMPLE CONFIG** warning (expected — demo uses sample policies)
- **BLOCKED** messages when governance denies an action
- **Audit entries** count at the end showing all governance decisions were logged

---

## Path 2: Govern Your Own Agent (15 minutes)

This shows how a real customer would add governance to their existing agent code.

### Step 1: Install

```bash
pip install agent-governance-toolkit[full]
```

### Step 2: Create a policy file

Save this as `my-policy.yaml`:

```yaml
version: "1.0"
name: my-first-policy
description: Basic governance for testing

kernel:
  mode: strict

policies:
  - name: tool-restrictions
    description: Control which tools agents can use
    deny:
      - patterns:
          - "execute_shell"
          - "run_command"
          - "delete_.*"
    allow:
      - action: "search_web"
      - action: "read_file"
      - action: "write_report"
    limits:
      - action: tool_call
        max_per_session: 20

audit:
  enabled: true
  level: all
```

### Step 3: Use the toolkit in your code

```python
from agent_os import StatelessKernel, ExecutionContext, Policy

# Create the governance kernel
kernel = StatelessKernel()

# Define what this agent is allowed to do
ctx = ExecutionContext(
    agent_id="my-test-agent",
    policies=[
        Policy.read_only(),                     # No write operations
        Policy.rate_limit(100, "1m"),           # Max 100 calls/minute
        Policy.require_approval(
            actions=["send_email", "deploy_*"],  # These need human OK
            min_approvals=1,
        ),
    ],
)

# This is where your agent's tool call gets intercepted
result = await kernel.execute(
    action="search_web",
    params={"query": "latest AI news"},
    context=ctx,
)
print(f"Allowed: {result.allowed}")
print(f"Reason: {result.reason}")

# Try a blocked action
result2 = await kernel.execute(
    action="execute_shell",
    params={"command": "rm -rf /"},
    context=ctx,
)
print(f"Allowed: {result2.allowed}")  # False
print(f"Reason: {result2.reason}")    # "Blocked by policy"
```

### Step 4: Add to a LangChain/CrewAI/ADK agent

See the quickstart examples:
- `examples/quickstart/langchain_governed.py`
- `examples/quickstart/crewai_governed.py`
- `examples/quickstart/google_adk_governed.py`
- `examples/quickstart/openai_agents_governed.py`
- `examples/quickstart/autogen_governed.py`

Each is a single file that creates a governed agent in the respective framework.

---

## Path 3: Test the SQL Policy (Security Focus)

This tests the specific security policies that were recently hardened.

### Step 1: Install

```bash
pip install -e "packages/agent-os[dev]"
```

### Step 2: Run the SQL policy tests

```bash
cd packages/agent-os
python -m pytest modules/control-plane/tests/test_sql_policy.py -v
```

You should see 40 tests passing — covering:
- DROP, TRUNCATE, ALTER blocked
- GRANT, REVOKE blocked (privilege escalation)
- CREATE USER blocked (backdoor creation)
- EXEC xp_cmdshell blocked (OS command execution)
- UPDATE without WHERE blocked (mass data modification)
- SELECT, INSERT, UPDATE with WHERE allowed

### Step 3: Test with custom YAML config

```python
from agent_control_plane.policy_engine import create_policies_from_config

# Load the strict SQL policy (SELECT only)
rules = create_policies_from_config("examples/policies/sql-strict.yaml")

# Or the balanced default
rules = create_policies_from_config("examples/policies/sql-safety.yaml")

# Or the read-only policy
rules = create_policies_from_config("examples/policies/sql-readonly.yaml")
```

---

## Path 4: Run the Full Test Suite

```bash
# Run all 6,100+ tests
cd packages/agent-os && python -m pytest tests/ -q
cd ../agent-mesh && python -m pytest tests/ -q
cd ../agent-hypervisor && python -m pytest tests/ -q
cd ../agent-sre && python -m pytest tests/ -q
cd ../agent-compliance && python -m pytest tests/ -q
```

---

## What to Test (Test Matrix)

| Area | How to Test | Expected Result |
|------|------------|-----------------|
| **Install** | `pip install agent-governance-toolkit[full]` | Installs cleanly, no errors |
| **Demo** | `python demo/maf_governance_demo.py` | 4 scenarios run, blocked actions shown |
| **Adversarial** | `python demo/maf_governance_demo.py --include-attacks` | All 4 attacks blocked |
| **Policy loading** | Load YAML from `examples/policies/` | Policies parse without errors |
| **SQL safety** | Run `test_sql_policy.py` | 40 tests pass |
| **Framework integration** | Run any `examples/quickstart/*.py` | Governed agent works end-to-end |
| **Audit trail** | Check `evaluator.get_audit_log()` after actions | All decisions logged with timestamps |
| **Trust identity** | `from agentmesh import AgentIdentity` | Ed25519 DID generated |
| **CLI** | `agent-governance --help` | CLI shows available commands |

---

## Common Issues

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'yaml'` | `pip install pyyaml` |
| `ModuleNotFoundError: No module named 'cryptography'` | `pip install cryptography` |
| Demo shows "no backend detected" | Set one of the API key env vars (see Step 2 above) |
| `DeprecationWarning: create_default_policies()` | Expected — use `create_policies_from_config()` instead |
| Tests fail with import errors | Run `pip install -e ".[dev]"` in the package directory |

---

## Architecture Summary

```
┌─────────────────────────────────────────────┐
│            Your Agent (any framework)        │
│  LangChain / CrewAI / ADK / AutoGen / etc.  │
└──────────────────┬──────────────────────────┘
                   │ Tool call
                   ▼
┌─────────────────────────────────────────────┐
│         Agent Governance Toolkit             │
│                                              │
│  1. Identity Check (Ed25519 DID)            │
│  2. Policy Evaluation (YAML/OPA/Cedar)      │
│  3. Action: ALLOW / DENY / ESCALATE         │
│  4. Audit Log (tamper-proof)                │
└──────────────────┬──────────────────────────┘
                   │ If ALLOWED
                   ▼
┌─────────────────────────────────────────────┐
│         Tool / API / Database                │
└─────────────────────────────────────────────┘
```

---

## Questions?

- **GitHub Discussions**: https://github.com/microsoft/agent-governance-toolkit/discussions
- **Issues**: https://github.com/microsoft/agent-governance-toolkit/issues
