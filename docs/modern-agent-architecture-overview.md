# Modern Agent Architecture & the Agent Governance Toolkit (AGT)

> **Audience:** Technical decision-makers evaluating governance for enterprise AI agent deployments
>
> **Repo:** [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) — MIT Licensed, Public Preview

---

## The Problem: AI Agents Are Powerful… and Ungoverned

Enterprise AI is shifting from chat-based copilots to **autonomous agents** — systems that reason, plan, use tools, and coordinate with other agents. This creates a governance gap:

| Promise | Reality Without Governance |
|---------|---------------------------|
| "Automate everything" | Agent creates a PR with a security vulnerability |
| "Works autonomously" | Agent hallucinates, you debug for hours |
| "Ship 10× faster" | 40% of time reviewing agent output |

Current frameworks (LangChain, CrewAI, AutoGen) rely on **prompt-based safety** — asking the LLM to follow rules. That's like asking a driver to self-enforce the speed limit.

**Benchmark result:** Prompt-based safety has a **26.67% policy violation rate**. AGT's kernel-level enforcement: **0.00%**.

---

## Architecture Overview: The Governance Stack

AGT provides **runtime governance infrastructure** — it sits between your agent framework and the actions agents take. It governs what agents **do**, not what they say.

```
╔══════════════════════════════════════════════════════════════════════╗
║                    AGENT GOVERNANCE TOOLKIT                         ║
║              pip install agent-governance-toolkit[full]              ║
║                                                                     ║
║   Agent Action ───► POLICY CHECK ───► Allow / Deny    (< 0.1 ms)   ║
║                                                                     ║
║   ┌──────────────────────────┐     ┌───────────────────────────┐    ║
║   │      AGENT OS ENGINE     │◄───►│        AGENTMESH          │    ║
║   │                          │     │                           │    ║
║   │  ● Policy Engine         │     │  ● Zero-Trust Identity    │    ║
║   │  ● Capability Model      │     │  ● Ed25519 / SPIFFE Certs │    ║
║   │  ● Audit Logging         │     │  ● Trust Scoring (0-1000) │    ║
║   │  ● Action Interception   │     │  ● A2A + MCP Bridge       │    ║
║   └────────────┬─────────────┘     └──────────────┬────────────┘    ║
║                │                                  │                 ║
║                ▼                                  ▼                 ║
║   ┌──────────────────────────┐     ┌───────────────────────────┐    ║
║   │     AGENT RUNTIME        │     │        AGENT SRE          │    ║
║   │                          │     │                           │    ║
║   │  ● 4-Tier Privilege Rings│     │  ● SLOs + Error Budgets   │    ║
║   │  ● Resource Limits       │     │  ● Replay & Chaos Testing │    ║
║   │  ● Saga Orchestration    │     │  ● Circuit Breakers       │    ║
║   │  ● Kill Switch           │     │  ● Progressive Delivery   │    ║
║   └──────────────────────────┘     └───────────────────────────┘    ║
║                                                                     ║
║   ┌──────────────────────────┐     ┌───────────────────────────┐    ║
║   │   AGENT MARKETPLACE      │     │     AGENT LIGHTNING       │    ║
║   │                          │     │                           │    ║
║   │  ● Plugin Discovery      │     │  ● RL Training Governance │    ║
║   │  ● Signing & Verification│     │  ● Policy Rewards         │    ║
║   └──────────────────────────┘     └───────────────────────────┘    ║
╚══════════════════════════════════════════════════════════════════════╝
```

### How It Works: The Kernel Analogy

Think of AGT like a **Linux kernel for AI agents**:

| OS Concept | AGT Equivalent | What It Does |
|-----------|----------------|--------------|
| Kernel | **Agent OS Policy Engine** | Evaluates every action before execution |
| User/Kernel boundary | **Capability Model** | Agents can only call tools they're allowed to |
| Process isolation | **Privilege Rings** | 4 tiers from admin → sandboxed |
| Signals (SIGKILL) | **Kill Switch** | Terminate non-compliant agents instantly |
| Audit logs | **Flight Recorder** | Append-only, hash-chained audit trail |
| Certificate Authority | **AgentMesh Identity** | Ed25519 cryptographic agent credentials |

**Key insight:** Current frameworks ask LLMs to *decide* whether to follow rules. AGT inverts this: **the kernel decides, the LLM computes.**

---

## Core Capabilities

### 1. Deterministic Policy Enforcement (Agent OS)

Define exactly what each agent can and cannot do — enforced at the application layer, not by prompts:

```python
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import (
    PolicyDocument, PolicyRule, PolicyCondition,
    PolicyAction, PolicyOperator, PolicyDefaults,
)

policy = PolicyDocument(
    name="agent-safety",
    version="1.0",
    description="Block dangerous tools and sensitive data patterns",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[
        PolicyRule(
            name="block-dangerous-tools",
            condition=PolicyCondition(
                field="tool_name",
                operator=PolicyOperator.IN,
                value=["execute_code", "delete_file"],
            ),
            action=PolicyAction.DENY,
            message="Tool is blocked by policy",
            priority=100,
        ),
        PolicyRule(
            name="block-ssn-patterns",
            condition=PolicyCondition(
                field="input_text",
                operator=PolicyOperator.MATCHES,
                value=r"\b\d{3}-\d{2}-\d{4}\b",
            ),
            action=PolicyAction.DENY,
            message="SSN pattern detected",
            priority=90,
        ),
    ],
)

evaluator = PolicyEvaluator(policies=[policy])
result = evaluator.evaluate({"tool_name": "delete_file", "input_text": "/etc/passwd"})
# result.allowed == False — blocked deterministically, not probabilistically
```

Supports **OPA/Rego** and **Cedar** policies so you can reuse existing infrastructure policies.

### 2. Zero-Trust Agent Identity (AgentMesh)

Every agent gets cryptographic identity with trust scoring:

```python
from agentmesh import MeshNode

node = MeshNode(agent_id="supply-chain-optimizer")
# Agent receives Ed25519 credentials + trust score (0-1000)
# Score changes based on: policy compliance, task success, anomalies
```

| Trust Score | Tier | Privileges |
|------------|------|-----------|
| 900–1000 | Verified Partner | Full access, cross-org delegation |
| 700–899 | Trusted | Elevated privileges |
| 500–699 | Standard | Default for new agents |
| 300–499 | Probationary | Limited, under observation |
| 0–299 | Untrusted | Read-only or blocked |

### 3. Execution Sandboxing (Agent Runtime)

4-tier privilege rings inspired by OS hardware rings:

- **Ring 0 (Admin):** Full tool access — for trusted orchestrators
- **Ring 1 (Standard):** Scoped tool access — most production agents
- **Ring 2 (Restricted):** Read-only + approved writes — new/untested agents
- **Ring 3 (Sandboxed):** No external access — training and testing

Includes **saga orchestration** for multi-step workflows: if step 4 fails, compensating actions undo steps 1–3 automatically.

### 4. Agent SRE (Reliability Engineering)

Apply SRE practices to your agent fleet:

- **SLOs & Error Budgets:** "99.5% of agent actions must comply with policy"
- **Chaos Engineering:** Inject failures to test agent resilience
- **Circuit Breakers:** Automatically stop agents that exceed error thresholds
- **Replay Debugging:** Deterministically replay agent sessions for root-cause analysis

### 5. MCP Security Scanner

Detect attacks on MCP (Model Context Protocol) tool definitions:

```bash
agent-governance mcp-scan --server my-mcp-server
```

Catches: tool poisoning, typosquatting, hidden instructions, rug-pull attacks.

---

## OWASP Agentic Top 10 Coverage (10/10)

| Risk | ID | AGT Control |
|------|----|-------------|
| Agent Goal Hijacking | ASI-01 | Policy engine blocks unauthorized goal changes |
| Excessive Capabilities | ASI-02 | Capability model enforces least-privilege |
| Identity & Privilege Abuse | ASI-03 | Zero-trust identity with Ed25519 certs |
| Uncontrolled Code Execution | ASI-04 | Execution rings + sandboxing |
| Insecure Output Handling | ASI-05 | Content policies validate all outputs |
| Memory Poisoning | ASI-06 | Episodic memory with integrity checks |
| Unsafe Inter-Agent Communication | ASI-07 | Encrypted channels + trust gates |
| Cascading Failures | ASI-08 | Circuit breakers + SLO enforcement |
| Human-Agent Trust Deficit | ASI-09 | Full audit trails + flight recorder |
| Rogue Agents | ASI-10 | Kill switch + ring isolation + behavioral anomaly detection |

---

## Regulatory Alignment

| Regulation | Deadline | AGT Coverage |
|-----------|----------|-------------|
| **EU AI Act** — High-Risk AI (Annex III) | August 2, 2026 | Audit trails (Art. 12), risk management (Art. 9), human oversight (Art. 14) |
| **Colorado AI Act** (SB 24-205) | June 30, 2026 | Risk assessments, human oversight, consumer disclosures |
| **EU AI Act** — GPAI Obligations | Active | Transparency, copyright, systemic risk assessment |

---

## Quick Start: 10 Minutes to Governed Agents

### Step 1: Install

```bash
pip install agent-governance-toolkit[full]
```

Also available for: **TypeScript** (`npm install @microsoft/agentmesh-sdk`), **.NET** (`dotnet add package Microsoft.AgentGovernance`), **Rust** (`cargo add agentmesh`), **Go**

### Step 2: Your First Governed Agent

```python
from agent_os.policies import PolicyEvaluator

# Load YAML policy rules
evaluator = PolicyEvaluator()
evaluator.load_policies("policies/")

# Allowed
result = evaluator.evaluate({"tool_name": "web_search", "input_text": "quarterly sales data"})
print(f"Allowed: {result.allowed}")  # True

# Blocked — deterministically, not probabilistically
result = evaluator.evaluate({"tool_name": "delete_file", "input_text": "/critical/data.csv"})
print(f"Allowed: {result.allowed}")  # False
```

### Step 3: Wrap an Existing Framework

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_policies("policies/")

# Evaluate before any framework tool call
decision = evaluator.evaluate({
    "agent_id": "langchain-agent-1",
    "tool_name": "web_search",
    "action": "tool_call",
})

if decision.allowed:
    result = your_langchain_agent.run(...)
else:
    print(f"Blocked: {decision.reason}")
```

For deeper integration, use framework-specific adapters:

```bash
pip install langchain-agentmesh      # LangChain
pip install llamaindex-agentmesh     # LlamaIndex
pip install crewai-agentmesh         # CrewAI
```

### Step 4: Verify OWASP Coverage

```bash
agent-governance verify         # Text summary
agent-governance verify --json  # JSON for CI/CD
agent-governance verify --badge # Badge for your README
```

---

## Framework Compatibility

Works with **20+ agent frameworks** — no vendor lock-in:

| Framework | Integration |
|-----------|-------------|
| Microsoft Agent Framework | Native Middleware |
| Semantic Kernel | Native (.NET + Python) |
| AutoGen | Adapter |
| LangChain / LangGraph | Adapter |
| CrewAI | Adapter |
| OpenAI Agents SDK | Middleware |
| Google ADK | Adapter |
| LlamaIndex | Middleware |
| Dify | Plugin |
| AWS Bedrock | Adapter |
| Azure AI Foundry | Deployment Guide |

---

## Enterprise Use Cases

### Manufacturing & Supply Chain (e.g., CPG)
- **Multi-agent supply chain optimization** with deterministic safety guardrails
- **Quality control agents** governed by compliance policies (ISO, HACCP)
- **Demand forecasting agents** with audit trails for regulatory review
- **Cross-supplier agent coordination** via zero-trust identity and trust scoring

### Financial Services
- SOC2-compliant trading and analysis agents
- Policy enforcement for PII/PCI data handling
- Multi-agent fraud detection with circuit breakers

### Healthcare
- HIPAA-compliant medical data agents
- Automatic PHI protection via blocked patterns
- Multi-agent diagnostic workflows with full audit trails

---

## Deployment Options

| Option | Best For |
|--------|----------|
| `pip install` | Local development, quick evaluation |
| Docker Compose | Team environments, CI/CD |
| AKS (Azure Kubernetes) | Production enterprise deployment |
| Azure AI Foundry | Managed AI workloads |
| Container Apps | Serverless agent hosting |

---

## Resources

| Resource | Link |
|----------|------|
| GitHub Repo | [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) |
| Quick Start Guide | [QUICKSTART.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/QUICKSTART.md) |
| Architecture Docs | [docs/ARCHITECTURE.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/ARCHITECTURE.md) |
| OWASP Compliance | [docs/OWASP-COMPLIANCE.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/OWASP-COMPLIANCE.md) |
| Tutorials (27) | [docs/tutorials/](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs/tutorials) |
| Threat Model | [docs/THREAT_MODEL.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/THREAT_MODEL.md) |
| DeepWiki | [deepwiki.com/microsoft/agent-governance-toolkit](https://deepwiki.com/microsoft/agent-governance-toolkit) |

---

*Agent Governance Toolkit is a Microsoft open-source project (MIT License). Public Preview — production-quality with 9,500+ tests.*
