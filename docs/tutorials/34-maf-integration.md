# Tutorial 34 — Governing Agents with Microsoft Agent Framework (MAF)

> **Level:** Intermediate · **Time:** 30 min · **Prerequisites:** Tutorial 01 (Policy Engine), Python 3.10+, `pip install agent-framework agent-os-kernel`
>
> **Status:** ✅ Implemented — Middleware adapter with 18 passing tests. Joint integration with MAF team in progress.

This tutorial shows how to add AGT governance to agents built with the [Microsoft Agent Framework](https://github.com/microsoft/agent-framework). You'll wire policy enforcement, capability guards, and audit logging into MAF's middleware pipeline so governance is transparent to the agent.

### Implementation Reference

| Component | Location |
|-----------|----------|
| MAF Adapter | `agent-governance-python/agent-os/src/agent_os/integrations/maf_adapter.py` |
| Tests (18/18 passing) | `agent-governance-python/agent-os/tests/test_maf_adapter.py` |
| Quick start | `from agent_os.integrations.maf_adapter import maf_govern` |

## Why Govern MAF Agents?

MAF provides the orchestration layer — agent construction, tool registration, middleware pipelines, multi-agent coordination. AGT provides the governance layer — policy enforcement, PII detection, capability sandboxing, and audit trails. Together:

| MAF Handles | AGT Adds |
|---|---|
| Agent lifecycle | Policy enforcement per message |
| Tool registration | Capability allow/deny lists |
| Middleware pipeline | Governance middleware (3 layers) |
| Multi-agent orchestration | Cross-agent trust scoring |
| LLM integration | Prompt injection detection |

## Architecture

```
User Message
    │
    ▼
┌─────────────────────────────────────────────┐
│  MAF Agent Pipeline                          │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │  AuditTrailMiddleware (AgentMiddleware) │  │  ← Logs every interaction
│  │  ┌──────────────────────────────────┐  │  │
│  │  │  GovernancePolicyMiddleware      │  │  │  ← Evaluates YAML policies
│  │  │  ┌────────────────────────────┐  │  │  │
│  │  │  │  CapabilityGuardMiddleware │  │  │  │  ← Blocks unauthorized tools
│  │  │  │  ┌──────────────────────┐  │  │  │  │
│  │  │  │  │  LLM + Tool Calls    │  │  │  │  │  ← Agent logic runs here
│  │  │  │  └──────────────────────┘  │  │  │  │
│  │  │  └────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────┘  │  │
│  └────────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
    │
    ▼
Agent Response (or governance block)
```

## Step 1 — Install Dependencies

```bash
pip install agent-framework          # Microsoft Agent Framework
pip install agent-os-kernel          # AGT policy engine
pip install agentmesh-platform       # AGT identity + audit
pip install agent-sre                # AGT anomaly detection (optional)
```

## Step 2 — Define Governance Policies

Create `policies/bank-policy.yaml`:

```yaml
name: contoso-bank-policy
version: "1.0"
description: Governance policy for banking agents

defaults:
  action: allow

rules:
  - name: block-fund-transfers
    condition:
      field: input_text
      operator: matches
      value: "(?i)(transfer|wire|send)\\s+\\$?\\d+"
    action: deny
    message: "Fund transfers must go through the secure payments portal"
    priority: 1000

  - name: block-ssn-disclosure
    condition:
      field: input_text
      operator: matches
      value: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    action: deny
    message: "SSN detected — blocked for PII protection"
    priority: 900

  - name: audit-loan-queries
    condition:
      field: input_text
      operator: matches
      value: "(?i)(loan|mortgage|credit|interest)"
    action: audit
    message: "Loan query logged for compliance"
    priority: 100
```

## Step 3 — Wire Governance into MAF

This is the key integration step — register AGT middleware in MAF's pipeline:

```python
from agent_framework import Agent, AgentKernel
from agent_os.integrations.maf_adapter import (
    GovernancePolicyMiddleware,
    CapabilityGuardMiddleware,
    AuditTrailMiddleware,
)

# Create AGT governance middleware
policy_mw = GovernancePolicyMiddleware(policy_directory="policies/")
capability_mw = CapabilityGuardMiddleware(
    allowed_tools=["check_loan_status", "calculate_interest", "get_account_summary"]
)
audit_mw = AuditTrailMiddleware()

# Create MAF kernel with governance middleware
kernel = AgentKernel()

# Registration order = execution order (outermost first)
kernel.add_agent_middleware(audit_mw)         # 1. Log everything
kernel.add_agent_middleware(policy_mw)        # 2. Enforce policies
kernel.add_function_middleware(capability_mw) # 3. Guard tool calls

# Create the agent with the governed kernel
agent = Agent(
    name="loan-processor",
    instructions="You are a Contoso Bank loan processing assistant.",
    kernel=kernel,
)
```

**Key point:** AGT middleware implements MAF's `AgentMiddleware` and `FunctionMiddleware` protocols. No adapters or wrappers — it plugs directly into the pipeline.

## Step 4 — Run the Agent

```python
import asyncio

async def main():
    # ✅ Allowed: loan inquiry (audited)
    response = await agent.invoke("What's the interest rate for a 30-year mortgage?")
    print(f"Agent: {response.content}")

    # ❌ Blocked: fund transfer attempt
    try:
        response = await agent.invoke("Transfer $50,000 to account 12345")
    except Exception as e:
        print(f"Blocked: {e}")
        # → "Fund transfers must go through the secure payments portal"

    # ❌ Blocked: PII in message
    try:
        response = await agent.invoke("My SSN is 123-45-6789, look up my loan")
    except Exception as e:
        print(f"Blocked: {e}")
        # → "SSN detected — blocked for PII protection"

asyncio.run(main())
```

The governance layer intercepts every message **before** it reaches the LLM. The agent never sees blocked content.

## Step 5 — Role-Based Capability Guards

Different agents can have different tool permissions:

```python
# Tier 1 support: read-only
tier1_kernel = AgentKernel()
tier1_kernel.add_function_middleware(
    CapabilityGuardMiddleware(
        allowed_tools=["check_ticket_status", "search_knowledge_base"]
    )
)

# Admin: full access
admin_kernel = AgentKernel()
admin_kernel.add_function_middleware(
    CapabilityGuardMiddleware(
        allowed_tools=[
            "check_ticket_status", "search_knowledge_base",
            "restart_service", "deploy_to_production",
        ]
    )
)

tier1_agent = Agent(name="tier1-support", kernel=tier1_kernel, ...)
admin_agent = Agent(name="admin-support", kernel=admin_kernel, ...)
```

See the full demo: [`demo/maf-integration/02_helpdesk_it.py`](../../demo/maf-integration/02_helpdesk_it.py)

## Step 6 — Prompt Injection Detection

Protect customer-facing agents from jailbreak attacks:

```python
injection_policy = PolicyDocument(
    name="injection-defense",
    rules=[
        PolicyRule(
            name="block-jailbreak",
            condition=PolicyCondition(
                field="input_text",
                operator=PolicyOperator.MATCHES,
                value=r"(?i)(ignore\s+previous\s+instructions|you\s+are\s+now|pretend\s+you)",
            ),
            action=PolicyAction.DENY,
            message="Prompt injection detected",
            priority=1000,
        ),
    ],
)

kernel = AgentKernel()
kernel.add_agent_middleware(
    GovernancePolicyMiddleware(policies=[injection_policy])
)

support_agent = Agent(name="support", kernel=kernel, ...)
```

See the full demo: [`demo/maf-integration/03_contoso_support.py`](../../demo/maf-integration/03_contoso_support.py)

## Step 7 — Folder-Level Policies for Multi-Agent Systems

For monorepos with multiple agents, use [folder-level governance](../proposals/folder-level-governance.md):

```
agents/
  governance.yaml                    # Baseline: all agents
  loan-processor/
    governance.yaml                  # Stricter PII rules
    agent.py
  support-chat/
    governance.yaml                  # Injection defense
    agent.py
```

```python
evaluator = PolicyEvaluator(root_dir="agents/")
result = evaluator.evaluate({
    "tool_name": "export_pii",
    "path": "agents/loan-processor/agent.py",
})
# → Evaluates baseline + loan-processor policies (merged)
```

## Demos

| Demo | Scenario | Key Governance Features |
|---|---|---|
| [`01_contoso_bank.py`](../../demo/maf-integration/01_contoso_bank.py) | Banking | PII blocking, fund transfer denial, SOC2 audit trail |
| [`02_helpdesk_it.py`](../../demo/maf-integration/02_helpdesk_it.py) | IT Support | Role-based tool access, privilege escalation prevention |
| [`03_contoso_support.py`](../../demo/maf-integration/03_contoso_support.py) | Customer Chat | Jailbreak detection, system prompt extraction defense |

## Next Steps

- **[Tutorial 01 — Policy Engine](01-policy-engine.md)** — YAML policy syntax deep dive
- **[Tutorial 03 — Framework Integrations](03-framework-integrations.md)** — LangChain, CrewAI, AutoGen adapters
- **[Tutorial 14 — Kill Switch](14-kill-switch-and-rate-limiting.md)** — Emergency agent termination
- **[Tutorial 43 — .NET MAF Hook Integration](43-dotnet-maf-hook-integration.md)** — See the .NET `Microsoft.Agents.AI` extension package and `WithGovernance(...)` hook
- **[Folder-Level Governance Spec](../proposals/folder-level-governance.md)** — Path-scoped policy inheritance
