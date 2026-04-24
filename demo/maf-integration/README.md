# AGT × Microsoft Agent Framework — Integration Demos

These demos show **how to add AGT governance to an existing MAF agent** — not conceptual examples, but actual MAF wiring that developers can copy into their projects.

## Prerequisites

```bash
pip install agent-framework          # Microsoft Agent Framework
pip install agent-os-kernel          # AGT policy engine
pip install agentmesh-platform       # AGT identity + audit
pip install agent-sre                # AGT anomaly detection
```

## Demos

| # | Scenario | What It Demonstrates |
|---|----------|---------------------|
| 1 | **Contoso Bank** | Policy middleware blocks PII + fund transfers, audit trail |
| 2 | **HelpDesk IT** | Capability guard restricts tools by agent role |
| 3 | **Contoso Support** | Prompt injection detection in chat messages |

Each demo is a single file that runs standalone:

```bash
python demo/maf-integration/01_contoso_bank.py
python demo/maf-integration/02_helpdesk_it.py
python demo/maf-integration/03_contoso_support.py
```

## Key MAF Wiring Points

```python
from agent_framework import Agent, AgentKernel
from agent_os.integrations.maf_adapter import (
    GovernancePolicyMiddleware,
    CapabilityGuardMiddleware,
    AuditTrailMiddleware,
)

# 1. Create governance middleware
policy_mw = GovernancePolicyMiddleware(policy_directory="policies/")
capability_mw = CapabilityGuardMiddleware(allowed_tools=["web_search"])
audit_mw = AuditTrailMiddleware()

# 2. Register middleware in MAF pipeline (order matters!)
kernel = AgentKernel()
kernel.add_agent_middleware(audit_mw)        # Outermost: logs everything
kernel.add_agent_middleware(policy_mw)       # Middle: enforces policy
kernel.add_function_middleware(capability_mw) # Inner: guards tool calls

# 3. Create agent with governance-enabled kernel
agent = Agent(
    name="contoso-bank-agent",
    instructions="You are a banking assistant.",
    kernel=kernel,
)

# 4. Agent runs normally — governance is transparent
response = await agent.invoke("Transfer $50,000 to account 12345")
# → GovernancePolicyMiddleware intercepts, evaluates policy, blocks if denied
```

## Policy Files

Each demo includes a `policies/` directory with YAML policies. These are standard AGT PolicyDocuments — the same format used across all AGT integrations.
