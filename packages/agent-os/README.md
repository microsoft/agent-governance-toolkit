<div align="center">

# Agent OS — Community Edition

**A kernel architecture for governing autonomous AI agents**

[![GitHub Stars](https://img.shields.io/github/stars/microsoft/agent-governance-toolkit?style=social)](https://github.com/microsoft/agent-governance-toolkit/stargazers)
[![Sponsor](https://img.shields.io/badge/sponsor-❤️-ff69b4)](https://github.com/microsoft/agent-governance-toolkit)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-os-kernel)](https://pypi.org/project/agent-os-kernel/)
[![Downloads](https://img.shields.io/pypi/dm/agent-os-kernel)](https://pypi.org/project/agent-os-kernel/)
[![OWASP](https://img.shields.io/badge/OWASP_Agentic_Top_10-9/10_Covered-brightgreen)](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/OWASP-COMPLIANCE.md)
[![Glama](https://glama.ai/mcp/servers/@microsoft/agentos-mcp-server/badge?features=false&install=false)](https://glama.ai/mcp/servers/@microsoft/agentos-mcp-server)
[![VS Code Extension](https://img.shields.io/badge/VS%20Code-Extension-007ACC?logo=visual-studio-code)](https://marketplace.visualstudio.com/items?itemName=agent-os.agent-os-vscode)
[![Documentation](https://img.shields.io/badge/docs-microsoft.github.io-blue)](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs)
[![Featured in awesome-llm-apps](https://img.shields.io/badge/Featured%20in-awesome--llm--apps-orange)](https://github.com/Shubhamsaboo/awesome-llm-apps)
[![awesome-mcp-servers](https://img.shields.io/badge/awesome--mcp--servers-listed-blue)](https://github.com/punkpeye/awesome-mcp-servers)
[![Integrated in agent-lightning](https://img.shields.io/badge/Microsoft-agent--lightning-purple?logo=microsoft)](https://github.com/microsoft/agent-lightning/tree/main/contrib/recipes/agentos)
[![Integrated in LlamaIndex](https://img.shields.io/badge/LlamaIndex-integrated-purple)](https://github.com/run-llama/llama_index/pull/20644)
[![awesome-AI-Agents](https://img.shields.io/badge/Awesome--AI--Agents-listed-orange)](https://github.com/Jenqyang/Awesome-AI-Agents/pull/45)
[![awesome-agent-skills](https://img.shields.io/badge/awesome--agent--skills-listed-orange)](https://github.com/heilcheng/awesome-agent-skills/pull/34)
[![awesome-devops-mcp](https://img.shields.io/badge/awesome--devops--mcp-listed-orange)](https://github.com/rohitg00/awesome-devops-mcp-servers/pull/27)
[![Downloads](https://static.pepy.tech/badge/agent-os-kernel)](https://pepy.tech/project/agent-os-kernel)
[![Discussions](https://img.shields.io/github/discussions/microsoft/agent-governance-toolkit)](https://github.com/microsoft/agent-governance-toolkit/discussions)

> ⭐ **If this project helps you, please star it!** It helps others discover Agent OS.

> 📦 **Install the full stack:** `pip install ai-agent-governance[full]` — [PyPI](https://pypi.org/project/ai-agent-governance/) | [GitHub](https://github.com/microsoft/agent-governance-toolkit)

[Quick Start](#quick-example) • [Documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs) • [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=agent-os.agent-os-vscode) • [Examples](examples/) • [Agent Hypervisor](https://github.com/microsoft/agent-governance-toolkit) • [AgentMesh](https://github.com/microsoft/agent-governance-toolkit) • [Agent SRE](https://github.com/microsoft/agent-governance-toolkit)

<br/>

[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/microsoft/agent-governance-toolkit)

*Try Agent OS instantly in your browser - no installation required*

</div>

### Integrated With

<p align="center">
  <a href="https://github.com/langgenius/dify-plugins/pull/2060"><img src="https://img.shields.io/badge/Dify-Merged-success?style=flat-square" alt="Dify"></a>
  <a href="https://github.com/run-llama/llama_index/pull/20644"><img src="https://img.shields.io/badge/LlamaIndex-Merged-success?style=flat-square" alt="LlamaIndex"></a>
  <a href="https://github.com/microsoft/agent-lightning/pull/478"><img src="https://img.shields.io/badge/Agent--Lightning-Merged-success?style=flat-square" alt="Agent-Lightning"></a>
  <a href="https://pypi.org/project/langgraph-trust/"><img src="https://img.shields.io/badge/LangGraph-PyPI-blue?style=flat-square" alt="LangGraph"></a>
  <a href="https://pypi.org/project/openai-agents-trust/"><img src="https://img.shields.io/badge/OpenAI_Agents-PyPI-blue?style=flat-square" alt="OpenAI Agents"></a>
  <a href="https://clawhub.ai/microsoft/agentmesh-governance"><img src="https://img.shields.io/badge/OpenClaw-ClawHub-purple?style=flat-square" alt="OpenClaw"></a>
</p>

### Featured In

<p align="center">
  <a href="https://github.com/Shubhamsaboo/awesome-llm-apps"><img src="https://img.shields.io/badge/awesome--llm--apps-92K_%E2%AD%90-orange?style=flat-square" alt="awesome-llm-apps"></a>
  <a href="https://github.com/Jenqyang/Awesome-AI-Agents/pull/45"><img src="https://img.shields.io/badge/Awesome--AI--Agents-listed-orange?style=flat-square" alt="Awesome-AI-Agents"></a>
  <a href="https://github.com/github/awesome-copilot/pull/755"><img src="https://img.shields.io/badge/awesome--copilot-listed-orange?style=flat-square" alt="awesome-copilot"></a>
  <a href="https://github.com/heilcheng/awesome-agent-skills/pull/34"><img src="https://img.shields.io/badge/awesome--agent--skills-listed-orange?style=flat-square" alt="awesome-agent-skills"></a>
  <a href="https://github.com/TensorBlock/awesome-mcp-servers/pull/66"><img src="https://img.shields.io/badge/awesome--mcp--servers-listed-orange?style=flat-square" alt="awesome-mcp-servers"></a>
  <a href="https://github.com/rohitg00/awesome-devops-mcp-servers/pull/27"><img src="https://img.shields.io/badge/awesome--devops--mcp-listed-orange?style=flat-square" alt="awesome-devops-mcp"></a>
</p>across 170K+ GitHub stars. Governance for [Dify](https://github.com/langgenius/dify-plugins/pull/2060) (65K ⭐), [LlamaIndex](https://github.com/run-llama/llama_index/pull/20644) (47K ⭐), [LangGraph](https://pypi.org/project/langgraph-trust/), [OpenAI Agents](https://pypi.org/project/openai-agents-trust/), [Agent-Lightning](https://github.com/microsoft/agent-lightning/pull/478), and [OpenClaw](https://clawhub.ai/microsoft/agentmesh-governance).

## 📊 By The Numbers

<table>
<tr>
<td align="center"><h3>1,680+</h3><sub>Tests Passing</sub></td>
<td align="center"><h3>12</h3><sub>Framework Integrations</sub></td>
<td align="center"><h3>170K+</h3><sub>Combined Stars of<br/>Integrated Projects</sub></td>
<td align="center"><h3>&lt;0.1ms p99</h3><sub>Governance Latency<br/><a href="benchmarks/results/BENCHMARKS.md">Benchmarks</a></sub></td>
<td align="center"><h3>9</h3><sub>More Framework Proposals<br/>Under Review</sub></td>
</tr>
</table>

### 🏢 Adopted By Leading AI Frameworks

| Framework | Stars | Status | Link |
|-----------|-------|--------|------|
| **Dify** | 65K ⭐ | ✅ Merged | [dify-plugins#2060](https://github.com/langgenius/dify-plugins/pull/2060) |
| **LlamaIndex** | 47K ⭐ | ✅ Merged | [llama_index#20644](https://github.com/run-llama/llama_index/pull/20644) |
| **Microsoft Agent-Lightning** | 15K ⭐ | ✅ Merged | [agent-lightning#478](https://github.com/microsoft/agent-lightning/pull/478) |
| **LangGraph** | 24K ⭐ | 📦 Published on PyPI | [langgraph-trust](https://pypi.org/project/langgraph-trust/) |
| **OpenAI Agents SDK** | — | 📦 Published on PyPI | [openai-agents-trust](https://pypi.org/project/openai-agents-trust/) |
| **OpenClaw** | — | 📦 Published on ClawHub | [agentmesh-governance](https://clawhub.ai/microsoft/agentmesh-governance) |

<details>
<summary><b>📋 Proposals under review at 10+ frameworks (click to expand)</b></summary>

| Framework | Stars | Proposal |
|-----------|-------|----------|
| AutoGen | 54K ⭐ | [microsoft/autogen#7242](https://github.com/microsoft/autogen/issues/7242) |
| CrewAI | 44K ⭐ | [crewAIInc/crewAI#4502](https://github.com/crewAIInc/crewAI/issues/4502) |
| Haystack | 22K ⭐ | [deepset-ai/haystack#10615](https://github.com/deepset-ai/haystack/issues/10615) |
| Semantic Kernel | 27K ⭐ | [microsoft/semantic-kernel#13556](https://github.com/microsoft/semantic-kernel/issues/13556) |
| smolagents | 25K ⭐ | ✅ Adapter built — [huggingface/smolagents#1989](https://github.com/huggingface/smolagents/issues/1989) |
| LangGraph | 24K ⭐ | [langchain-ai/langgraph#6824](https://github.com/langchain-ai/langgraph/issues/6824) |
| Google ADK | 18K ⭐ | ✅ Adapter built — [google/adk-python#4517](https://github.com/google/adk-python/issues/4517) |
| PydanticAI | 15K ⭐ | ✅ Adapter built — [pydantic/pydantic-ai#4335](https://github.com/pydantic/pydantic-ai/issues/4335) |
| OpenAI Agents SDK | — | [openai/openai-agents-python#2515](https://github.com/openai/openai-agents-python/issues/2515) |
| A2A Protocol | 21K ⭐ | [a2aproject/A2A#1501](https://github.com/a2aproject/A2A/issues/1501) |
| Oracle Agent Spec | — | [oracle/agent-spec#105](https://github.com/oracle/agent-spec/issues/105) |
| AI Card Spec | — | [agent-card/ai-card#16](https://github.com/Agent-Card/ai-card/issues/16) |

</details>

### 💡 Why Agent OS?

> **The AI agent market is projected to reach $47B by 2030.** As enterprises deploy autonomous agents at scale, governance becomes the critical infrastructure layer. Agent OS is the kernel that ensures every agent action is policy-enforced, auditable, and compliant — making AI agents enterprise-ready.

**The problem:** AI agents can execute arbitrary tools, access sensitive data, and make autonomous decisions — with no built-in governance, audit trails, or policy enforcement.

**Our solution:** A governance kernel that sits between agents and their actions, providing deterministic policy enforcement in <1ms with zero agent code changes.

### How Agent OS Compares

| Tool | Focus | When it acts |
|------|-------|--------------|
| LangChain/CrewAI | Building agents | N/A (framework) |
| NeMo Guardrails | Input/output filtering | Before/after LLM call |
| LlamaGuard | Content classification | Before/after LLM call |
| **Agent OS** | **Action interception** | **During execution** |

> **Agent frameworks** build agents. **Safety tools** filter I/O. **Agent OS** intercepts actions mid-execution — the only kernel-level governance layer.

### 🛡️ OWASP Agentic Top 10 Coverage

Agent OS + ecosystem covers **8 out of 10** [OWASP Agentic Application Security risks](docs/owasp-agentic-top10-mapping.md):

| Risk | Coverage | Module |
|------|----------|--------|
| ASI01 Agent Goal Hijack | ✅ Full | `GovernancePolicy.blocked_patterns` |
| ASI02 Tool Misuse | ✅ Full | `MCPGateway` — tool filtering, rate limiting, audit |
| ASI03 Identity & Privilege | ✅ Full | `require_human_approval`, RBAC policies |
| ASI04 Supply Chain | ⚠️ Partial | Tool allowlisting (no deep scanning yet) |
| ASI05 Code Execution | ✅ Full | `blocked_patterns`, sandbox integration |
| ASI06 Memory Poisoning | ✅ Full | `MemoryGuard` — hash integrity, injection detection |
| ASI07 Inter-Agent Comms | ✅ Full | AgentMesh trust handshake, HMAC auth |
| ASI08 Cascading Failures | ✅ Full | Agent SRE circuit breakers, cascade detection |
| ASI09 Human-Agent Trust | ✅ Full | Human approval workflows, audit logging |
| ASI10 Rogue Agents | ⚠️ Partial | Agent Hypervisor execution rings, kill switch |

> 📄 [Full OWASP mapping →](docs/owasp-agentic-top10-mapping.md)

### 🌐 The Agent Governance Ecosystem

| Layer | Package | Purpose | Install |
|-------|---------|---------|---------|
| **Kernel** | [Agent OS](https://github.com/microsoft/agent-governance-toolkit) | Policy enforcement, action interception | `pip install agent-os-kernel` |
| **Network** | [AgentMesh](https://github.com/microsoft/agent-governance-toolkit) | Identity, trust, delegation | `pip install agentmesh-platform` |
| **Reliability** | [Agent SRE](https://github.com/microsoft/agent-governance-toolkit) | SLOs, chaos testing, circuit breakers | `pip install agent-sre` |
| **Runtime** | [Agent Hypervisor](https://github.com/microsoft/agent-governance-toolkit) | Execution rings, resource limits, saga | `pip install agent-hypervisor` |
| **Full Stack** | [ai-agent-governance](https://pypi.org/project/ai-agent-governance/) | All of the above | `pip install ai-agent-governance[full]` |

---

## ⚡ Quick Start in 30 Seconds

```bash
pip install agent-os-kernel
```

```python
from agent_os import StatelessKernel, ExecutionContext

# Create a governed agent in 3 lines
kernel = StatelessKernel()

# Define execution context with governance policies
ctx = ExecutionContext(agent_id="demo-agent", policies=["read_only"])

# Your agent runs with policy enforcement
result = await kernel.execute(
    action="database_query",
    params={"query": "SELECT * FROM users"},
    context=ctx
)

# ✅ Safe queries execute
# ❌ "DROP TABLE users" → Blocked by kernel
```

That's it! Your agent now has deterministic policy enforcement. [Learn more →](#what-is-agent-os)

**🎬 See all features in action:**
```bash
git clone https://github.com/microsoft/agent-governance-toolkit && python agent-os/demo.py
```

<details>
<summary><b>📋 More examples (click to expand)</b></summary>

### Policy enforcement with custom rules

```python
from agent_os import StatelessKernel

kernel = StatelessKernel()
kernel.load_policy_yaml("""
version: "1.0"
name: api-safety
rules:
  - name: block-destructive-sql
    condition: "action == 'database_query'"
    action: deny
    pattern: "DROP|TRUNCATE|DELETE FROM .* WHERE 1=1"
  - name: rate-limit-api
    condition: "action == 'api_call'"
    limit: "100/hour"
""")

result = await kernel.execute(action="database_query", params={"query": "DROP TABLE users"})
# ❌ Blocked: Matched rule 'block-destructive-sql'
```

### Audit logging

```python
from agent_os import KernelSpace

kernel = KernelSpace()

# Every kernel action is automatically recorded
result = await kernel.execute(action="read_file", params={"path": "/data/report.csv"})

# Query the flight recorder
entries = kernel.flight_recorder.query(agent_id="agent-001", limit=10)
for entry in entries:
    print(f"{entry.timestamp} | {entry.action} | {entry.outcome}")
```

### Governed chatbot with memory

```python
from agent_os import KernelSpace
from agent_os.emk import EpisodicMemory

kernel = KernelSpace(policy_file="policies.yaml")
memory = EpisodicMemory(max_turns=50)

@kernel.register
async def chat(message: str, conversation_id: str = "default") -> str:
    history = memory.get_history(conversation_id)
    response = await call_llm(history + [{"role": "user", "content": message}])
    memory.add_turn(conversation_id, message, response)
    return response
# Outputs are checked against content policies; violations trigger SIGSTOP
```

See [examples/](examples/) for 20+ runnable demos including SQL agents, GitHub reviewers, and compliance bots.
</details>

---

<p align="center">
  <img src="assets/demo-terminal.svg" alt="Agent OS Terminal Demo" width="700"/>
</p>

---

## 🎯 What You'll Build in 5 Minutes

```python
from agent_os import stateless_execute

# 1. Define safety policies (not prompts — actual enforcement)

# 2. Actions are checked against policies before execution
result = await stateless_execute(
    action="database_query",
    params={"query": "SELECT revenue FROM sales"},
    agent_id="analyst-001",
    policies=["read_only"]
)
# ✅ Safe queries execute
# ❌ "DROP TABLE users" → BLOCKED (not by prompt, by kernel)
```

**Result:** Defined policies are deterministically enforced by the kernel—not by hoping the LLM follows instructions.

For the full kernel with signals, VFS, and protection rings:

```python
from agent_os import KernelSpace, AgentSignal, AgentVFS

# Requires: pip install agent-os-kernel[full]
kernel = KernelSpace()
ctx = kernel.create_agent_context("agent-001")
await ctx.write("/mem/working/task.txt", "Hello World")
```

> **Note:** `KernelSpace`, `AgentSignal`, and `AgentVFS` require installing the control-plane module: `pip install agent-os-kernel[full]`

---

## What is Agent OS?

Agent OS applies operating system concepts to AI agent governance. Instead of relying on prompts to enforce safety ("please don't do dangerous things"), it provides application-level middleware that intercepts and validates agent actions before execution.

> **Note:** This is application-level enforcement (Python middleware), not OS kernel-level isolation. Agents run in the same process. For true isolation, run agents in containers.

```
┌─────────────────────────────────────────────────────────┐
│              USER SPACE (Agent Code)                    │
│   Your agent code runs here. The kernel intercepts      │
│   actions before they execute.                          │
├─────────────────────────────────────────────────────────┤
│              KERNEL SPACE                               │
│   Policy Engine │ Flight Recorder │ Signal Dispatch     │
│   Actions are checked against policies before execution │
└─────────────────────────────────────────────────────────┘
```

## The Idea

**Prompt-based safety** asks the LLM to follow rules. The LLM decides whether to comply.

**Kernel-based safety** intercepts actions before execution. The policy engine decides, not the LLM.

This is the same principle operating systems use: applications request resources, the kernel grants or denies access based on permissions.

---

## Architecture

```mermaid
graph TB
    subgraph Frameworks["External Frameworks"]
        LC[LangChain]
        CA[CrewAI]
        AG[AutoGen]
        OA[OpenAI]
        AN[Anthropic]
        GE[Gemini]
    end

    ADAPT[[Adapters]]

    subgraph L4["Layer 4: Intelligence"]
        SC[Self-Correction]
        SA[Semantic Analysis]
    end

    subgraph L3["Layer 3: Control Plane"]
        PE[Policy Engine]
        AL[Audit Logging]
    end

    subgraph L2["Layer 2: Infrastructure"]
        NM[Nexus Marketplace]
        OB[Observability]
    end

    subgraph L1["Layer 1: Primitives"]
        VE[Verification Engine]
        CS[Context Service]
        MS[Memory Store]
    end

    LC & CA & AG & OA & AN & GE --> ADAPT
    ADAPT --> L4
    SC & SA --> PE
    SC & SA --> AL
    PE & AL --> NM
    PE & AL --> OB
    NM & OB --> VE
    NM & OB --> CS
    NM & OB --> MS
```

### Directory Structure

```
agent-os/
├── src/agent_os/             # Core Python package
│   ├── __init__.py           # Public API (re-exports from all layers)
│   ├── stateless.py          # StatelessKernel (zero-dependency core)
│   ├── base_agent.py         # BaseAgent, ToolUsingAgent classes
│   ├── agents_compat.py      # AGENTS.md parser (OpenAI/Anthropic standard)
│   ├── cli.py                # CLI (agent-os check, review, init, etc.)
│   └── integrations/         # Framework adapters (LangChain, OpenAI, etc.)
├── modules/                  # Kernel Modules (4-layer architecture)
│   ├── primitives/           # Layer 1: Base types and failures
│   ├── cmvk/                 # Layer 1: Verification
│   ├── emk/                  # Layer 1: Episodic memory kernel
│   ├── caas/                 # Layer 1: Context-as-a-Service
│   ├── amb/                  # Layer 2: Agent message bus
│   ├── iatp/                 # Layer 2: Inter-agent trust protocol
│   ├── atr/                  # Layer 2: Agent tool registry
│   ├── observability/        # Layer 3: Prometheus + OpenTelemetry
│   ├── control-plane/        # Layer 3: THE KERNEL (policies, signals)
│   ├── scak/                 # Layer 4: Self-correcting agent kernel
│   ├── mute-agent/           # Layer 4: Face/Hands architecture
│   ├── nexus/                # Experimental: Trust exchange network
│   └── mcp-kernel-server/    # Integration: MCP protocol support
├── extensions/               # IDE & AI Assistant Extensions
│   ├── mcp-server/           # ⭐ MCP Server (Copilot, Claude, Cursor)
│   ├── vscode/               # VS Code extension
│   ├── copilot/              # GitHub Copilot extension
│   ├── jetbrains/            # IntelliJ/PyCharm plugin
│   ├── cursor/               # Cursor IDE extension
│   ├── chrome/               # Chrome extension
│   └── github-cli/           # gh CLI extension
├── examples/                 # Working examples
├── docs/                     # Documentation
├── tests/                    # Test suite (organized by layer)
├── notebooks/                # Jupyter tutorials
├── papers/                   # Research papers
└── templates/                # Policy templates
```

---

## Core Modules

| Module | Layer | PyPI Package | Description | Status |
|--------|-------|-------------|-------------|--------|
| [`primitives`](modules/primitives/) | 1 | `agent-primitives` | Base failure types, severity levels | ✅ Stable |
| [`cmvk`](modules/cmvk/) | 1 | `cmvk` | Verification, drift detection | ✅ Stable |
| [`emk`](modules/emk/) | 1 | `emk` | Episodic memory kernel (append-only ledger) | ✅ Stable |
| [`caas`](modules/caas/) | 1 | `caas-core` | Context-as-a-Service, RAG pipeline | ✅ Stable |
| [`amb`](modules/amb/) | 2 | `amb-core` | Agent message bus (async pub/sub) | ✅ Stable |
| [`iatp`](modules/iatp/) | 2 | `inter-agent-trust-protocol` | Sidecar trust protocol, typed IPC pipes | ✅ Stable |
| [`atr`](modules/atr/) | 2 | `agent-tool-registry` | Tool registry with LLM schema generation | ✅ Stable |
| [`control-plane`](modules/control-plane/) | 3 | `agent-control-plane` | **THE KERNEL** — Policy engine, signals, VFS | ✅ Stable |
| [`observability`](modules/observability/) | 3 | `agent-os-observability` | Prometheus metrics + OpenTelemetry tracing | ⚠️ No tests |
| [`scak`](modules/scak/) | 4 | `scak` | Self-correcting agent kernel | ✅ Stable |
| [`mute-agent`](modules/mute-agent/) | 4 | `mute-agent` | Decoupled reasoning/execution architecture | ⚠️ No tests |
| [`nexus`](modules/nexus/) | — | *Not published* | Trust exchange network | 🔬 Prototype |
| [`mcp-kernel-server`](modules/mcp-kernel-server/) | Int | `mcp-kernel-server` | MCP server for Claude Desktop | ⚠️ No tests |
| [**`hypervisor`**](https://github.com/microsoft/agent-governance-toolkit) | **⭐** | `agent-hypervisor` | **Runtime supervisor — Execution Rings, Joint Liability, Saga Orchestrator** ([own repo](https://github.com/microsoft/agent-governance-toolkit)) | **✅ 184 tests** |

---

## ⭐ Star Feature: Agent Hypervisor

> **Runtime supervisor for multi-agent collaboration** — think "VMware for AI agents."
> 
> **Now its own repo: [`agent-hypervisor`](https://github.com/microsoft/agent-governance-toolkit)** — 184 tests, 268μs full pipeline, zero dependencies beyond pydantic.

Just as OS hypervisors isolate virtual machines and enforce resource boundaries, the Agent Hypervisor isolates AI agent sessions and enforces **governance boundaries** at sub-millisecond latency.

```
┌────────────────────────────────────────────────────────────┐
│                    AGENT HYPERVISOR                         │
│                                                            │
│   Ring 0 (Root)      ← SRE Witness required                │
│   Ring 1 (Privileged)← σ_eff > 0.95 + consensus           │
│   Ring 2 (Standard)  ← σ_eff > 0.60                        │
│   Ring 3 (Sandbox)   ← Default for unknown agents          │
│                                                            │
│   ┌──────────┐  ┌───────────┐  ┌────────────────────────┐  │
│   │  Joint    │  │  Semantic  │  │  Hash-Chained          │  │
│   │ Liability │  │   Saga     │  │  Delta Audit Trail     │  │
│   │  Engine   │  │ Orchestr.  │  │  (Tamper-Evident)      │  │
│   └──────────┘  └───────────┘  └────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### Key Capabilities

| Feature | Description | Latency |
|---------|-------------|---------|
| **Execution Rings** | 4-level privilege model (Ring 0–3) based on trust score | **0.3μs** |
| **Joint Liability** | High-trust agents vouch for low-trust agents with bonded reputation | **7μs** |
| **Saga Orchestrator** | Multi-step transactions with timeout, retry, and auto-compensation | **151μs** |
| **Delta Audit** | Hash-chained semantic diffs with blockchain commitment | **27μs** |
| **Full Pipeline** | Session + join + audit + saga + terminate | **268μs** |

### Quick Start

```bash
pip install agent-hypervisor
```

```python
from hypervisor import Hypervisor, SessionConfig, ConsistencyMode

hv = Hypervisor()

# Create a governed multi-agent session
session = await hv.create_session(
    config=SessionConfig(consistency_mode=ConsistencyMode.EVENTUAL, max_participants=5),
    creator_did="did:mesh:admin",
)

# Agents are automatically assigned privilege rings based on trust score
ring = await hv.join_session(session.sso.session_id, "did:mesh:agent-alpha", sigma_raw=0.85)
# → Ring 2 (Standard) — can execute reversible actions

# Multi-step saga with automatic timeout and compensation
saga = session.saga.create_saga(session.sso.session_id)
step = session.saga.add_step(
    saga.saga_id, "draft_email", "did:mesh:agent-alpha",
    execute_api="/api/draft", undo_api="/api/undo-draft",
    timeout_seconds=30, max_retries=2,
)

# Terminate — returns tamper-evident summary hash
summary_hash = await hv.terminate_session(session.sso.session_id)
```

📖 **[Full Hypervisor documentation →](https://github.com/microsoft/agent-governance-toolkit)**

---

## IDE & CLI Extensions

| Extension | Description | Status |
|-----------|-------------|--------|
| [`mcp-server`](extensions/mcp-server/) | ⭐ **MCP Server** — Works with Claude, Copilot, Cursor (`npx agentos-mcp-server`) | ✅ Published (v1.0.1) |
| [`vscode`](extensions/vscode/) | VS Code extension with real-time policy checks, enterprise features | ✅ Published (v1.0.1) |
| [`copilot`](extensions/copilot/) | GitHub Copilot extension (Vercel/Docker deployment) | ✅ Published (v1.0.0) |
| [`jetbrains`](extensions/jetbrains/) | IntelliJ, PyCharm, WebStorm plugin (Kotlin) | ✅ Built (v1.0.0) |
| [`cursor`](extensions/cursor/) | Cursor IDE extension (Composer integration) | ✅ Built (v0.1.0) |
| [`chrome`](extensions/chrome/) | Chrome extension for GitHub, Jira, AWS, GitLab | ✅ Built (v1.0.0) |
| [`github-cli`](extensions/github-cli/) | `gh agent-os` CLI extension | ⚠️ Basic |

---

## Install

```bash
pip install agent-os-kernel
```

Or with optional components:

```bash
pip install agent-os-kernel[cmvk]           # + verification
pip install agent-os-kernel[iatp]           # + inter-agent trust
pip install agent-os-kernel[observability]  # + Prometheus/OpenTelemetry
pip install agent-os-kernel[nexus]          # + trust exchange network
pip install agent-os-kernel[full]           # Everything
```

### One-Command Quickstart

**macOS/Linux:**
```bash
curl -sSL https://raw.githubusercontent.com/microsoft/agent-governance-toolkit/main/scripts/quickstart.sh | bash
```

**Windows (PowerShell):**
```powershell
iwr -useb https://raw.githubusercontent.com/microsoft/agent-governance-toolkit/main/scripts/quickstart.ps1 | iex
```

---

## Quick Example

### Stateless API (Always Available — Zero Dependencies Beyond Pydantic)

```python
from agent_os import stateless_execute

# Execute with policy enforcement
result = await stateless_execute(
    action="database_query",
    params={"query": "SELECT * FROM users"},
    agent_id="analyst-001",
    policies=["read_only"]
)
```

### Full Kernel API (Requires `pip install agent-os-kernel[full]`)

```python
from agent_os import KernelSpace, AgentSignal, PolicyRule

kernel = KernelSpace()

# Create agent context with VFS
ctx = kernel.create_agent_context("agent-001")
await ctx.write("/mem/working/task.txt", "analyze this data")

# Policy enforcement
from agent_os import PolicyEngine
engine = PolicyEngine()
engine.add_rule(PolicyRule(name="no_sql_injection", pattern="DROP|DELETE|TRUNCATE"))
```

---

## POSIX-Inspired Primitives

Agent OS borrows concepts from POSIX operating systems:

| Concept | POSIX | Agent OS |
|---------|-------|----------|
| Process control | `SIGKILL`, `SIGSTOP` | `AgentSignal.SIGKILL`, `AgentSignal.SIGSTOP` |
| Filesystem | `/proc`, `/tmp` | VFS with `/mem/working`, `/mem/episodic` |
| IPC | Pipes (`\|`) | Typed IPC pipes between agents |
| Syscalls | `open()`, `read()` | `kernel.execute()` |

### Signals

```python
# Requires: pip install agent-os-kernel[full]
from agent_os import SignalDispatcher, AgentSignal

dispatcher = SignalDispatcher()
dispatcher.signal(agent_id, AgentSignal.SIGSTOP)  # Pause
dispatcher.signal(agent_id, AgentSignal.SIGCONT)  # Resume
dispatcher.signal(agent_id, AgentSignal.SIGKILL)  # Terminate
```

### VFS (Virtual File System)

```python
# Requires: pip install agent-os-kernel[full]
from agent_os import AgentVFS

vfs = AgentVFS(agent_id="agent-001")
vfs.write("/mem/working/task.txt", "Current task")
vfs.read("/policy/rules.yaml")  # Read-only from user space
```

---

## Framework Integrations

Wrap existing frameworks with Agent OS governance:

```python
# LangChain
from agent_os.integrations import LangChainKernel
governed = LangChainKernel().wrap(my_chain)

# OpenAI Assistants
from agent_os.integrations import OpenAIKernel
governed = OpenAIKernel().wrap_assistant(assistant, client)

# Semantic Kernel
from agent_os.integrations import SemanticKernelWrapper
governed = SemanticKernelWrapper().wrap(sk_kernel)

# CrewAI
from agent_os.integrations import CrewAIKernel
governed = CrewAIKernel().wrap(my_crew)

# AutoGen
from agent_os.integrations import AutoGenKernel
governed = AutoGenKernel().wrap(autogen_agent)

# OpenAI Agents SDK
from agent_os.integrations import OpenAIAgentsSDKKernel
governed = OpenAIAgentsSDKKernel().wrap(agent)
```

> **Note:** These adapters use lazy interception — they don't require the target framework to be installed until you call `.wrap()`.

See [integrations documentation](docs/integrations.md) for full details.

### Integration Comparison

| Framework | Governance Level | Async Support | Status | Adapter File |
|-----------|-----------------|---------------|--------|-------------|
| **LangChain** | Chain/Agent/Runnable | ✅ `ainvoke` | ✅ Stable | `integrations/langchain_adapter.py` |
| **OpenAI Assistants** | Run/Thread/Tool Call | ✅ Streaming | ✅ Stable | `integrations/openai_adapter.py` |
| **AutoGen** | Multi-Agent Orchestration | ❌ Sync only | ✅ Stable | `integrations/autogen_adapter.py` |
| **Semantic Kernel** | Function/Plugin/Memory | ✅ Native async | ✅ Stable | `integrations/semantic_kernel_adapter.py` |
| **CrewAI** | Crew/Agent/Task | ❌ Sync only | ✅ Stable | `integrations/crewai_adapter.py` |
| **OpenAI Agents SDK** | Agent/Tool/Handoff | ✅ Native async | ✅ Stable | `integrations/openai_agents_sdk_adapter.py` |

---

## Examples

The `examples/` directory contains demos at various levels:

### Getting Started

| Demo | Description | Command |
|------|-------------|---------|
| [demo-app](examples/demo-app/) | Uses the stateless API (most reliable) | `cd examples/demo-app && python demo.py` |
| [hello-world](examples/hello-world/) | Minimal example | `cd examples/hello-world && python agent.py` |
| [quickstart](examples/quickstart/) | Quick intro | `cd examples/quickstart && python my_first_agent.py` |

### Domain Examples (Self-Contained)

These examples are self-contained and don't require external Agent OS imports:

| Demo | Description |
|------|-------------|
| [healthcare-hipaa](examples/healthcare-hipaa/) | HIPAA-compliant agent |
| [customer-service](examples/customer-service/) | Customer support agent |
| [legal-review](examples/legal-review/) | Legal document analysis |
| [crewai-safe-mode](examples/crewai-safe-mode/) | CrewAI with safety wrappers |

### Production Demos (with Docker + Observability)

| Demo | Description | Command |
|------|-------------|---------|
| [carbon-auditor](examples/carbon-auditor/) | Multi-model verification | `cd examples/carbon-auditor && docker-compose up` |
| [grid-balancing](examples/grid-balancing/) | Multi-agent coordination | `cd examples/grid-balancing && docker-compose up` |
| [defi-sentinel](examples/defi-sentinel/) | Real-time attack detection | `cd examples/defi-sentinel && docker-compose up` |
| [pharma-compliance](examples/pharma-compliance/) | Document analysis | `cd examples/pharma-compliance && docker-compose up` |

Each production demo includes:
- **Grafana dashboard** on port 300X
- **Prometheus metrics** on port 909X
- **Jaeger tracing** on port 1668X

```bash
# Run carbon auditor with full observability
cd examples/carbon-auditor
cp .env.example .env  # Optional: add API keys
docker-compose up

# Open dashboards
open http://localhost:3000  # Grafana (admin/admin)
open http://localhost:16686 # Jaeger traces
```

---

## Safe Tool Plugins

Agent OS includes pre-built safe tools via the Agent Tool Registry:

```python
# Requires: pip install agent-os-kernel[full]
from atr import ToolRegistry, tool

@tool(name="safe_http", description="Rate-limited HTTP requests")
async def safe_http(url: str) -> dict:
    # Tool is automatically registered and sandboxed
    ...

registry = ToolRegistry()
registry.register(safe_http)

# Generate schemas for any LLM
openai_tools = registry.to_openai_schema()
anthropic_tools = registry.to_anthropic_schema()
```

---

## Message Bus

Connect agents using the async message bus:

```python
# Requires: pip install agent-os-kernel[full]
from amb_core import MessageBus, Message

bus = MessageBus()
await bus.subscribe("tasks", handler)
await bus.publish("tasks", Message(payload={"task": "analyze"}))
```

Broker adapters available for Redis, Kafka, and NATS (requires optional dependencies).

---

## CLI Tool

Agent OS includes a CLI for terminal workflows:

```bash
# Check files for safety violations
agentos check src/app.py
# ✓ src/app.py: No violations
# OR
# ⚠️  2 violation(s) found in src/app.py:
#   Line 12: DROP TABLE users;
#     Violation: Destructive SQL: DROP operation detected
#     Policy: block-destructive-sql

# Check staged git files (ideal for pre-commit hooks)
agentos check --staged
# ✓ No violations in staged files

# Machine-readable JSON output (for CI pipelines)
agentos check src/app.py --format json

# CI mode (no colors, strict exit codes)
agentos check --staged --ci
```

```bash
# Initialize Agent OS in a project
agentos init
# Initialized Agent OS in .agents/
#   - agents.md: Agent instructions (OpenAI/Anthropic standard)
#   - security.md: Kernel policies (Agent OS extension)
#   - Template: strict

# Choose a permissive or audit-only template
agentos init --template permissive
agentos init --template audit

# Overwrite an existing .agents/ directory
agentos init --force
```

```bash
# Enable kernel governance and verify the configuration
agentos secure
# Securing agents in .
#   [PASS] kernel version
#   [PASS] signals defined
#   [PASS] policies defined
# Security configuration valid.
```

```bash
# Audit agent security configuration
agentos audit
# Auditing .
#   [OK] agents.md
#   [OK] security.md
# No issues found.

# JSON output for CI
agentos audit --format json
```

```bash
# Show kernel status (version, installed packages)
agentos status
# Agent OS Kernel Status
# ========================================
#   Version: 1.2.0
#   Status: Installed
#   Project: /home/user/myproject
#   Agents: Configured (.agents/ found)
```

```bash
# Multi-model code review with CMVK consensus
agentos review src/app.py --cmvk
# 🔍 Reviewing src/app.py with CMVK...
# Multi-Model Review (3 models):
#   ✅ gpt-4: No issues
#   ⚠️  claude-sonnet-4: 1 potential issue(s)
#   ✅ gemini-pro: No issues
# Consensus: 67%

# Specify models
agentos review src/app.py --cmvk --models "gpt-4,claude-sonnet-4"
```

```bash
# Validate policy YAML files
agentos validate
#   Checking .agents/policy.yaml... OK
# ✓ All 1 policy file(s) valid.

# Validate specific files in strict mode
agentos validate policies/*.yaml --strict
```

```bash
# Install git pre-commit hook
agentos install-hooks
# ✓ Installed pre-commit hook: .git/hooks/pre-commit
# Agent OS will now check staged files before each commit.

# Append to an existing hook
agentos install-hooks --append
```

```bash
# Start the HTTP API server
agentos serve --port 8080
# Agent OS API server starting on 0.0.0.0:8080
# Endpoints:
#   GET  /health              Health check
#   GET  /status              Kernel status
#   GET  /agents              List agents
#   POST /agents/{id}/execute  Execute agent action
```

```bash
# Output Prometheus-style metrics
agentos metrics
# # HELP agentos_policy_violations_total Total policy violations.
# # TYPE agentos_policy_violations_total counter
# agentos_policy_violations_total 0
# ...
```

---

## MCP Integration (Claude Desktop, GitHub Copilot, Cursor)

Agent OS provides an MCP server that works with any MCP-compatible AI assistant:

```bash
# Quick install via npx
npx agentos-mcp-server
```

**npm:** [`agentos-mcp-server`](https://www.npmjs.com/package/agentos-mcp-server)  
**MCP Registry:** `io.github.microsoft/agentos`

Add to your config file:

**Claude Desktop** (`%APPDATA%\Claude\claude_desktop_config.json` on Windows):
```json
{
  "mcpServers": {
    "agentos": {
      "command": "npx",
      "args": ["-y", "agentos-mcp-server"]
    }
  }
}
```

**Features:** 10 tools for agent creation, policy enforcement, compliance checking (SOC 2, GDPR, HIPAA), human-in-the-loop approvals, and audit logging.

See [MCP server documentation](extensions/mcp-server/README.md) for full details.

---

## Documentation

### Tutorials
- [5-Minute Quickstart](docs/tutorials/5-minute-quickstart.md) — Get running fast
- [30-Minute Deep Dive](docs/tutorials/30-minute-deep-dive.md) — Comprehensive walkthrough
- [Building Your First Governed Agent](docs/tutorials/first-governed-agent.md) — Complete tutorial
- [Using Message Bus Adapters](docs/tutorials/message-bus-adapters.md) — Connect agents
- [Creating Custom Tools](docs/tutorials/custom-tools.md) — Build safe tools
- [Cheatsheet](docs/cheatsheet.md) — Quick reference

### Interactive Notebooks

| Notebook | Description | Time |
|----------|-------------|------|
| [Hello Agent OS](notebooks/01-hello-agent-os.ipynb) | Your first governed agent | 5 min |
| [Episodic Memory](notebooks/02-episodic-memory-demo.ipynb) | Agent memory that persists | 15 min |
| [Time-Travel Debugging](notebooks/03-time-travel-debugging.ipynb) | Replay and debug decisions | 20 min |
| [Verification](notebooks/04-verification.ipynb) | Detect hallucinations | 15 min |
| [Multi-Agent Coordination](notebooks/05-multi-agent-coordination.ipynb) | Trust between agents | 20 min |
| [Policy Engine](notebooks/06-policy-engine.ipynb) | Deep dive into policies | 15 min |

### Reference
- [Quickstart Guide](docs/quickstart.md) — 60 seconds to first agent
- [Framework Integrations](docs/integrations.md) — LangChain, OpenAI, etc.
- [Kernel Internals](docs/kernel-internals.md) — How the kernel works
- [Architecture Overview](docs/quickstart.md) — Getting started
- [Kernel Internals](docs/kernel-internals.md) — How the kernel works
- [RFC-003: Agent Signals](docs/rfcs/RFC-003-Agent-Signals.md) — POSIX-style signals
- [RFC-004: Agent Primitives](docs/rfcs/RFC-004-Agent-Primitives.md) — Core primitives

---

## Status & Maturity

This is a research project exploring kernel concepts for AI agent governance.

### ✅ Production-Ready

These components are fully implemented and tested:

| Component | Tests |
|-----------|-------|
| **StatelessKernel** — Zero-dependency policy enforcement (`src/agent_os/`) | ✅ Full coverage |
| **Policy Engine** — Deterministic rule enforcement | ✅ Tested |
| **Flight Recorder** — SQLite-based audit logging | ✅ Tested |
| **CLI** — `agent-os check`, `init`, `secure`, `validate` | ✅ Tested |
| **Framework Adapters** — LangChain, OpenAI, Semantic Kernel, CrewAI, AutoGen, OpenAI Agents SDK | ✅ Implemented |
| **AGENTS.md Parser** — OpenAI/Anthropic standard agent config | ✅ Full coverage |
| **Primitives** (`agent-primitives`) — Failure types, severity levels | ✅ Tested |
| **CMVK** (`cmvk`) — Drift detection, distance metrics (955+ lines) | ✅ Tested |
| **EMK** (`emk`) — Episodic memory with JSONL storage | ✅ 8 test files |
| **AMB** (`amb-core`) — Async message bus, DLQ, tracing | ✅ 6 test files |
| **IATP** (`inter-agent-trust-protocol`) — Sidecar trust, typed IPC | ✅ 9 test files |
| **ATR** (`agent-tool-registry`) — Multi-LLM schema generation | ✅ 6 test files |
| **Control Plane** (`agent-control-plane`) — Signals, VFS, protection rings | ✅ 18 test files |
| **SCAK** (`scak`) — Self-correcting agent kernel | ✅ 23 test files |

### ⚠️ Experimental (Code Exists, Tests Missing or Incomplete)

| Component | What's Missing |
|-----------|----------------|
| **Mute Agent** (`mute-agent`) | No tests; all layer dependencies use mock adapters |
| **Observability** (`agent-os-observability`) | No tests; Prometheus metrics, Grafana dashboards, OTel tracing implemented |
| **MCP Kernel Server** (`mcp-kernel-server`) | No tests; 1173-line implementation |
| **GitHub CLI Extension** | Single bash script with simulated output |
| **Control Plane MCP Adapter** | Placeholder — returns canned responses |
| **Control Plane A2A Adapter** | Placeholder — negotiation accepts all params |

### 🔬 Research Prototype

| Component | What's Missing |
|-----------|----------------|
| **Nexus Trust Exchange** | No `pyproject.toml`, no tests, placeholder cryptography (XOR — **not secure**), all signature verification stubbed, in-memory storage only |

### Known Architectural Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **Application-level only** | Direct stdlib calls (`subprocess`, `open`) bypass kernel | Pair with container isolation for production |
| **Blocklist-based policies** | Novel attack patterns not in rules will pass | Add AST-level parsing (#32), use defense in depth |
| **Shadow Mode single-step** | Multi-step agent simulations diverge from reality | Use for single-turn validation only |
| **No tamper-proof audit** | Flight Recorder SQLite can be modified by compromised agent | Write to external sink for critical audits |
| **Provider-coupled adapters** | Each SDK needs separate adapter | Abstract interface planned (#47) |

See [GitHub Issues](https://github.com/microsoft/agent-governance-toolkit/issues) for the full roadmap.

---

## FAQ

### How is this different from prompt-based safety?

Prompt-based safety relies on instructing the LLM to follow rules via system prompts. This approach is probabilistic — the model may still produce unsafe outputs under certain conditions.

Agent OS enforces policies at the middleware layer. Actions are intercepted and validated before execution, making enforcement deterministic rather than dependent on model compliance.

### What frameworks are supported?

Agent OS can wrap and govern agents built with popular frameworks including LangChain, CrewAI, AutoGen, Semantic Kernel, and the OpenAI SDK. It also supports MCP-based integrations.

### Can I use this in production?

Core components such as the **StatelessKernel** and **Policy Engine** are production-ready. However, Agent OS provides application-level enforcement. For high-security environments, it should be combined with infrastructure isolation (e.g., containers).

### How do I write custom policies?

Custom policies can be defined programmatically in Python or declaratively using YAML. Policies define rules that inspect and allow or deny agent actions before execution.

### What is the performance overhead?

Policy checks are lightweight and typically introduce only minimal latency per action. The overhead depends on the number and complexity of rules configured.

---

## Troubleshooting

### Common Issues

**ModuleNotFoundError: No module named 'agent_os'**
```bash
# Install from source
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-os
pip install -e .
```

**Optional modules not available**
```bash
# Check what's installed
python -c "from agent_os import check_installation; check_installation()"

# Install everything
pip install -e ".[full]"
```

**Permission errors on Windows**
```bash
# Run PowerShell as Administrator, or use --user flag
pip install --user -e .
```

**Docker not working**
```bash
# Build with Dockerfile (no Docker Compose needed for simple tests)
docker build -t agent-os .
docker run -it agent-os python examples/demo-app/demo.py
```

**Tests failing with API errors**
```bash
# Most tests work without API keys — mock mode is default
pytest tests/ -v

# For real LLM tests, set environment variables
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Frequently Asked Questions

**What is the difference between Agent OS and prompt-based guardrails?**
Prompt-based guardrails ask the LLM to self-police, which is probabilistic. Agent OS enforces governance at the middleware level using deterministic policy engines and POSIX-inspired access controls. It controls what agents *can* do (capability-based), not just what they *should not* do (filter-based).

**How does Agent OS work with other frameworks?**
Agent OS integrates with 14+ frameworks via adapters. Install the governance layer alongside your existing framework: use `langgraph-trust` for LangGraph, `openai-agents-trust` for OpenAI Agents, or the MCP server for any MCP-compatible client. Agent OS acts as a kernel layer underneath your agent framework.

**What is the Agent Governance Ecosystem?**
Agent OS is part of a suite of four projects: Agent OS (policy kernel), [AgentMesh](https://github.com/microsoft/agent-governance-toolkit) (trust network), [Agent Hypervisor](https://github.com/microsoft/agent-governance-toolkit) (runtime supervisor), and [Agent SRE](https://github.com/microsoft/agent-governance-toolkit) (reliability platform). Together they provide 4,310+ tests across 17 modules.

**Can I use Agent OS in production?**
Yes. Agent OS has 1,500+ tests, a VS Code extension, PyPI package (`pip install agent-os-kernel`), and is integrated into production frameworks like Dify (65K stars) and LlamaIndex (47K stars). It supports Python 3.9+ and runs on any platform.

---

## Contributing

```bash
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-os
pip install -e ".[dev]"
pytest
```

---

## License

MIT — See [LICENSE](LICENSE)

---

<div align="center">

**Exploring kernel concepts for AI agent safety.**

[GitHub](https://github.com/microsoft/agent-governance-toolkit) · [Docs](docs/)

</div>
