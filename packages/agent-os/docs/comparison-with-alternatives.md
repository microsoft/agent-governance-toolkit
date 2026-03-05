# Agent Governance & Safety Tools: Comprehensive Comparison

> **Last updated:** July 2025 · **Audience:** Developers, architects, and security teams evaluating AI agent governance solutions
>
> Searching for "agent governance comparison", "NeMo Guardrails vs alternatives", or "AI agent safety tools"? This guide compares every major open-source option.

---

## Table of Contents

- [Feature Matrix](#feature-matrix)
- [How to Read This Guide](#how-to-read-this-guide)
- [Detailed Comparisons](#detailed-comparisons)
  - [Agent OS vs NVIDIA NeMo Guardrails](#1-nvidia-nemo-guardrails-4k)
  - [Agent OS vs Meta LlamaGuard](#2-meta-llamaguard)
  - [Agent OS vs Guardrails AI](#3-guardrails-ai-5k)
  - [Agent OS vs IBM mcp-context-forge](#4-ibm-mcp-context-forge-33k)
  - [Agent OS vs Invariant Labs Guardrails](#5-invariant-labs-guardrails)
  - [Agent OS vs Cordum](#6-cordum-cordum-io-462)
  - [Agent OS vs gate22](#7-gate22-aipotheosis-labs-163)
  - [Agent OS vs TrinityGuard](#8-trinityguard-ai45lab-194)
- [OWASP Agentic Top 10 Coverage Matrix](#owasp-agentic-top-10-coverage-matrix)
- [Performance Comparison](#performance-comparison)
- [Using Multiple Tools Together](#using-multiple-tools-together)
- [Decision Guide](#decision-guide)

---

## Feature Matrix

| Feature | Agent OS | NeMo Guardrails | LlamaGuard | Guardrails AI | IBM MCF | Invariant Labs | Cordum | gate22 | TrinityGuard |
|---------|:--------:|:---------------:|:----------:|:-------------:|:-------:|:--------------:|:------:|:------:|:------------:|
| **Architecture** | Kernel | Dialog rails | Classifier | Validators | Gateway | Proxy/Library | Control plane | MCP Gateway | Safety wrapper |
| **Tool call interception** | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **Kernel-level governance** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Input/output filtering** | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Content safety classification** | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ | ✅ |
| **MCP protocol support** | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Framework integrations** | 12+ | 3–4 | 1 | 3 | 1 | 2–3 | 2 | Any MCP | 2 |
| **Human-in-the-loop** | ✅ | ⚠️ | ❌ | ❌ | ⚠️ | ❌ | ✅ | ❌ | ❌ |
| **Audit logging** | ✅ | ⚠️ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **Multi-agent governance** | ✅ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ✅ | ❌ | ✅ |
| **Rate limiting** | ✅ | ⚠️ | ❌ | ❌ | ✅ | ❌ | ✅ | ⚠️ | ❌ |
| **Policy-as-code** | ✅ | ✅ | ❌ | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| **Circuit breakers** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ⚠️ |
| **Schema validation** | ⚠️ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Topical/dialog rails** | ❌ | ✅ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **GPU required** | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Primary language** | Python | Python | Python | Python | Python | Python | Go | TypeScript | Python |
| **License** | MIT | Apache 2.0 | Llama License | Apache 2.0 | Apache 2.0 | Apache 2.0 | BUSL-1.1 | Apache 2.0 | MIT |
| **GitHub stars** | Growing | ~4K | N/A (model) | ~5K | ~3.3K | ~1K | ~462 | ~163 | ~194 |

**Legend:** ✅ = Core capability · ⚠️ = Partial/indirect support · ❌ = Not supported

---

## How to Read This Guide

These tools are **not direct competitors** — they operate at different layers of the AI stack:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Content Safety        LlamaGuard, TrinityGuard│
│  (Is the content safe?)                                 │
├─────────────────────────────────────────────────────────┤
│  Layer 2: I/O Validation        NeMo Guardrails,        │
│  (Are inputs/outputs correct?)  Guardrails AI            │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Tool/Action Gateway   IBM MCF, gate22,         │
│  (Can this tool be called?)     Invariant Labs           │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Agent Governance      Agent OS, Cordum         │
│  (Full lifecycle control)                                │
└─────────────────────────────────────────────────────────┘
```

Agent OS operates primarily at **Layer 4** with reach into Layer 3 via its MCP Gateway. The best production deployments combine tools from multiple layers.

---

## Detailed Comparisons

### 1. NVIDIA NeMo Guardrails (~4K★)

> **Repository:** [NVIDIA/NeMo-Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)

#### Approach

NeMo Guardrails uses a domain-specific language called **Colang** to define conversational "rails" — rules that guide what an LLM can say and how dialog flows. It operates as an **input/output filter** that wraps LLM calls, inspecting prompts and responses before they reach the user.

```colang
define user ask about competitors
  "What can you tell me about [competitor]?"

define flow
  user ask about competitors
  bot refuse to discuss competitors
```

#### Comparison

| Dimension | Agent OS | NeMo Guardrails |
|-----------|----------|-----------------|
| **Enforcement point** | During execution (tool calls) | Before/after LLM calls |
| **Policy language** | YAML + Python | Colang DSL + YAML |
| **What it protects** | Agent actions, tool calls, API access | LLM inputs, outputs, dialog flow |
| **Topical rails** | ❌ Not built-in | ✅ Core strength |
| **Hallucination control** | ❌ | ✅ RAG grounding, fact-checking |
| **Tool call governance** | ✅ Core capability | ❌ Indirect (gates LLM output) |
| **Multi-agent** | ✅ Per-agent policies | ❌ Single-agent focused |
| **Latency** | <0.1ms p99 | 10–50ms+ (depends on GPU) |
| **Jailbreak prevention** | ✅ Pattern-based blocking | ✅ Dedicated rails + NIM models |
| **Enterprise integrations** | Cisco, Palo Alto (via partners) | ✅ Cisco AI Defense, Palo Alto |
| **Learning curve** | Low (YAML + Python) | Medium (Colang DSL) |

#### Where NeMo Guardrails is better

- **Topical rails and dialog flow control** — NeMo excels at keeping conversations on-topic with its Colang DSL, something Agent OS does not attempt
- **Content safety classification** — NeMo's NIM microservices provide GPU-accelerated safety classification with higher accuracy than pattern matching
- **Hallucination/RAG grounding** — Built-in fact-checking rails for RAG applications
- **Enterprise partnerships** — Deep integrations with Cisco AI Defense and Palo Alto Networks

#### Where Agent OS is better

- **Tool call interception** — Agent OS intercepts the actual action, not just the LLM output that might trigger it
- **Multi-framework support** — 12+ framework integrations vs NeMo's primary LangChain focus
- **Performance** — Sub-0.1ms overhead vs NeMo's 10–50ms+ per rail evaluation
- **Multi-agent governance** — Per-agent policies, inter-agent trust, fleet management

#### Complementary?

**Yes — strongly recommended together.** NeMo Guardrails wraps the LLM (what agents *say*), Agent OS wraps the actions (what agents *do*). Use NeMo for dialog safety and topical control, Agent OS for tool call governance and audit trails.

```python
# Example: NeMo for dialog + Agent OS for actions
from nemoguardrails import LLMRails
from agent_os import StatelessKernel

rails = LLMRails(config)          # Layer 2: Dialog safety
kernel = StatelessKernel()         # Layer 4: Action governance

# NeMo filters what the LLM says
# Agent OS intercepts what the agent does
```

---

### 2. Meta LlamaGuard

> **Model:** [meta-llama/Llama-Guard](https://huggingface.co/meta-llama/Llama-Guard-3-8B) (multiple versions available)

#### Approach

LlamaGuard is a **fine-tuned classification model** that evaluates whether prompts or responses are safe according to a predefined safety taxonomy. It runs as a separate model that classifies text as safe or unsafe across categories like violence, sexual content, criminal planning, etc.

```python
from transformers import pipeline

classifier = pipeline("text-classification", model="meta-llama/LlamaGuard-7b")
result = classifier("Is this content safe?")
# Returns: safe / unsafe with category
```

#### Comparison

| Dimension | Agent OS | LlamaGuard |
|-----------|----------|------------|
| **Enforcement point** | During execution | Before/after LLM calls |
| **Detection method** | Deterministic rules | Neural classification |
| **What it protects** | Tool calls, agent actions | Prompt/response content |
| **Infrastructure** | CPU only (Python library) | GPU required (model inference) |
| **False positives** | Near zero (deterministic) | 3–8% (probabilistic) |
| **Latency** | <0.1ms p99 | 50–200ms (model inference) |
| **Customization** | YAML policies, any rule | Fine-tuning or prompt engineering |
| **Categories** | Action-based (tools, APIs) | Content-based (violence, PII, etc.) |
| **Audit trail** | ✅ Full structured logs | ❌ Classification result only |

#### Where LlamaGuard is better

- **Nuanced content safety** — Neural classifiers catch subtle unsafe content that regex patterns miss (sarcasm, coded language, implicit threats)
- **Multi-category taxonomy** — Pre-trained across 13+ safety categories with strong accuracy
- **Language coverage** — Handles multilingual content natively
- **Zero-config safety** — Works out of the box without writing any rules

#### Where Agent OS is better

- **Action-level governance** — LlamaGuard classifies text; Agent OS blocks dangerous tool calls regardless of what the text says
- **No GPU required** — Agent OS runs on any Python environment
- **Deterministic** — No false positives; if the policy says "block," it blocks
- **Audit and compliance** — Full audit trail vs. a binary safe/unsafe classification

#### Complementary?

**Yes — excellent pairing.** Use LlamaGuard to screen inputs/outputs for content safety, and Agent OS to govern what tools the agent can execute. LlamaGuard catches harmful content; Agent OS catches harmful actions.

---

### 3. Guardrails AI (~5K★)

> **Repository:** [guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails)

#### Approach

Guardrails AI validates LLM **outputs** against schemas and validators. It focuses on ensuring structured, correct, and safe responses — detecting PII, toxic language, competitor mentions, off-topic content, and enforcing JSON/XML schemas. Validators are composable and come from a community hub.

```python
from guardrails import Guard, OnFailAction
from guardrails.hub import DetectPII, ToxicLanguage

guard = Guard().use(
    DetectPII(on_fail=OnFailAction.FIX),
    ToxicLanguage(threshold=0.5, on_fail=OnFailAction.REASK),
)
result = guard(llm.complete, prompt="Summarize the report")
```

#### Comparison

| Dimension | Agent OS | Guardrails AI |
|-----------|----------|---------------|
| **Enforcement point** | During execution (tool calls) | After LLM generation (output) |
| **Primary focus** | Action governance | Output quality & safety |
| **Validator ecosystem** | N/A | ✅ 100+ validators on Hub |
| **Schema enforcement** | ❌ | ✅ Pydantic/JSON Schema |
| **Auto-retry on failure** | ❌ | ✅ Corrective re-prompting |
| **Tool call governance** | ✅ Core capability | ❌ Not applicable |
| **Multi-framework** | ✅ 12+ frameworks | ⚠️ OpenAI, Anthropic, Cohere |
| **PII detection** | ⚠️ Pattern-based | ✅ Multiple detector validators |
| **Latency** | <0.1ms p99 | <50ms (async validators) |

#### Where Guardrails AI is better

- **Output validation** — Rich ecosystem of 100+ validators for structured output, PII detection, toxicity, and more
- **Schema enforcement** — Guarantees LLM output matches Pydantic models or JSON schemas
- **Auto-retry** — Automatically re-prompts the LLM with corrective instructions on validation failure
- **Community Hub** — Large, active validator marketplace

#### Where Agent OS is better

- **Action governance** — Agent OS governs what agents *do*, not just what they *say*
- **Framework coverage** — 12+ framework integrations vs. 3 primary LLM providers
- **Deterministic enforcement** — Policies block actions regardless of LLM output
- **Multi-agent support** — Per-agent policies, inter-agent trust protocols

#### Complementary?

**Yes — they solve different problems.** Use Guardrails AI to validate LLM output quality and format, then Agent OS to govern the actions taken based on that output.

```python
from agent_os import StatelessKernel
from guardrails import Guard
from guardrails.hub import DetectPII

kernel = StatelessKernel()            # Governs actions
guard = Guard().use(DetectPII())      # Validates output

@kernel.govern
async def my_agent(task):
    result = guard(llm.complete, prompt=task)  # Guardrails: clean output
    return result                               # Agent OS: safe actions
```

---

### 4. IBM mcp-context-forge (~3.3K★)

> **Repository:** [IBM/mcp-context-forge](https://github.com/IBM/mcp-context-forge)

#### Approach

IBM's ContextForge is an **MCP gateway and registry** — a centralized proxy that sits in front of MCP servers, REST APIs, and A2A endpoints. It provides zero-trust security, RBAC, 30+ built-in guardrails, credential management, and a unified admin UI. It's designed for enterprise-scale AI agent infrastructure.

#### Comparison

| Dimension | Agent OS | IBM mcp-context-forge |
|-----------|----------|-----------------------|
| **Architecture** | Embedded kernel (library) | Standalone gateway (proxy) |
| **Deployment** | `pip install` in your app | Docker/Kubernetes service |
| **MCP support** | ✅ MCP kernel server | ✅ Core architecture |
| **Built-in guardrails** | Custom policies | 30+ pre-built guardrails |
| **Credential management** | ❌ | ✅ Encrypted, never exposed |
| **Admin UI** | ❌ (CLI/code) | ✅ Web dashboard |
| **RBAC** | ⚠️ Policy-based | ✅ Fine-grained, default-on |
| **Federation** | ❌ | ✅ Redis-backed multi-instance |
| **REST-to-MCP conversion** | ❌ | ✅ Automatic |
| **SSRF prevention** | ⚠️ | ✅ Built-in |
| **Framework integrations** | 12+ | 1 (MCP protocol) |
| **Non-MCP agents** | ✅ LangChain, CrewAI, etc. | ❌ MCP-only |
| **Latency** | <0.1ms p99 | Network hop + gateway processing |
| **Policy engine** | Built-in YAML | Cedar/OPA integration |

#### Where IBM MCF is better

- **Enterprise readiness** — Admin UI, RBAC, credential management, federation, and 30+ built-in guardrails out of the box
- **MCP ecosystem** — Purpose-built for MCP with REST-to-MCP conversion, multi-transport support, and tool registry
- **Zero-trust architecture** — Every component independently authenticated and authorized
- **Observability** — OpenTelemetry integration, real-time dashboard, distributed tracing
- **IBM backing** — Used in IBM Consulting Advantage for 160K+ users

#### Where Agent OS is better

- **Framework diversity** — Works with any agent framework (LangChain, CrewAI, AutoGen, OpenAI, etc.), not just MCP
- **Embedded governance** — No network hop; policies enforced in-process at sub-millisecond latency
- **Multi-agent lifecycle** — Full agent lifecycle management, not just tool call proxying
- **Lightweight** — `pip install` vs. Docker/Kubernetes deployment

#### Complementary?

**Yes — excellent architecture pairing.** Use IBM MCF as your MCP gateway for centralized tool management, and Agent OS inside each agent for framework-level governance. MCF governs the *infrastructure*; Agent OS governs the *agent behavior*.

---

### 5. Invariant Labs Guardrails

> **Repository:** [invariantlabs-ai/invariant](https://github.com/invariantlabs-ai/invariant)

#### Approach

Invariant Labs Guardrails is a **rule-based security framework** specifically for agentic AI systems. It uses a Python-inspired policy language to define contextual security rules that can match complex tool call chains. It can operate as a transparent proxy/gateway for LLM and MCP traffic, or as an embedded library.

```python
from invariant.analyzer import LocalPolicy

policy = LocalPolicy.from_string("""
raise "Don't send email after reading website" if:
  (output: ToolOutput) -> (call2: ToolCall)
  output is tool:get_website
  prompt_injection(output.content, threshold=0.7)
  call2 is tool:send_email
""")
```

#### Comparison

| Dimension | Agent OS | Invariant Labs |
|-----------|----------|----------------|
| **Policy language** | YAML + Python | Custom Python-inspired DSL |
| **Tool call interception** | ✅ Middleware wrapping | ✅ Transparent proxy |
| **Chain detection** | ⚠️ Per-call policies | ✅ Multi-step chain rules |
| **Built-in detectors** | Pattern matching | PII, secrets, copyright, prompt injection |
| **Trace visualization** | ⚠️ Audit logs | ✅ Invariant Explorer |
| **Framework support** | 12+ integrations | 2–3 (LLM/MCP proxy) |
| **Deployment** | Embedded library | Library or proxy |
| **Multi-agent** | ✅ | ❌ Single-agent |
| **Human-in-the-loop** | ✅ | ❌ |

#### Where Invariant Labs is better

- **Chain-of-tool detection** — Can express rules about *sequences* of tool calls (e.g., "block email after reading inbox from unknown source"), which Agent OS handles per-call
- **Transparent proxy** — Can sit as an invisible MCP/LLM proxy without code changes
- **Built-in detectors** — Prompt injection, PII, secrets, and copyright detectors out of the box
- **Trace visualization** — Invariant Explorer provides rich visual debugging of agent traces

#### Where Agent OS is better

- **Framework coverage** — 12+ framework integrations vs. proxy-only approach
- **Multi-agent governance** — Per-agent policies, inter-agent trust, fleet management
- **Human-in-the-loop** — Native human approval workflows
- **Ecosystem** — Part of a broader governance stack (AgentMesh, Agent SRE, Agent Hypervisor)

#### Complementary?

**Yes.** Invariant's chain-of-tool rules complement Agent OS's per-action governance. Use Invariant for complex multi-step attack detection and Agent OS for framework-level policy enforcement.

---

### 6. Cordum (cordum-io) (462★)

> **Repository:** [cordum-io/cordum](https://github.com/cordum-io/cordum)

#### Approach

Cordum is a **standalone Agent Control Plane** built in Go. It provides a Before/During/Across governance framework with a safety kernel, scheduler, workflow engine, and web dashboard. It defines its own open protocol (CAP — Cordum Agent Protocol) for agent governance at the network level.

#### Comparison

| Dimension | Agent OS | Cordum |
|-----------|----------|--------|
| **Architecture** | Embedded Python kernel | Standalone Go service |
| **Deployment** | `pip install` in your app | Docker Compose + Go services |
| **Governance model** | Per-action policy enforcement | Job-level safety gating |
| **Protocol** | Framework adapters | CAP (custom protocol) |
| **Admin UI** | ❌ | ✅ Web dashboard |
| **Safety kernel** | ✅ In-process | ✅ Separate service |
| **Agent pools** | ❌ | ✅ Pool segmentation |
| **Human-in-the-loop** | ✅ | ✅ |
| **MCP support** | ✅ | ✅ stdio + HTTP/SSE |
| **Language** | Python | Go |
| **License** | MIT | BUSL-1.1 |
| **Framework integrations** | 12+ | CAP SDK (Go, Python, Node) |

#### Where Cordum is better

- **Standalone control plane** — Full infrastructure with dashboard, scheduler, and safety kernel as separate services
- **Agent fleet management** — Pool segmentation, capability-based routing, fleet health monitoring
- **Production ops** — TLS, HA, backup runbooks, incident response built in
- **Web UI** — Visual dashboard for governance monitoring and policy management
- **Output quarantine** — Automatically blocks PII/secrets from reaching clients

#### Where Agent OS is better

- **Lightweight integration** — `pip install` vs. Docker Compose infrastructure
- **Framework diversity** — 12+ framework adapters vs. CAP protocol adoption
- **Action-level granularity** — Per-tool-call policies vs. job-level gating
- **Open license** — MIT vs. BUSL-1.1 (commercial restrictions)
- **Ecosystem maturity** — Merged into Dify (65K★), LlamaIndex (47K★), Agent-Lightning (15K★)

#### Complementary?

**Partially.** Cordum operates at the infrastructure level (fleet management, job scheduling), while Agent OS operates at the code level (per-action governance). They could coexist if using Cordum for fleet orchestration and Agent OS inside individual agents for granular policy enforcement. The protocol mismatch (CAP vs. framework adapters) may require bridging.

---

### 7. gate22 (aipotheosis-labs) (163★)

> **Repository:** [aipotheosis-labs/gate22](https://github.com/aipotheosis-labs/gate22)

#### Approach

gate22 is an **MCP gateway and control plane** focused on governing which tools agents can access. Admins onboard MCP servers, set credential modes (org-shared or per-user), and define function-level allow lists. Developers compose "bundles" from permitted MCP configurations exposed through a single unified endpoint with just two functions: `search` and `execute`.

#### Comparison

| Dimension | Agent OS | gate22 |
|-----------|----------|--------|
| **Architecture** | Embedded kernel | MCP gateway service |
| **Primary focus** | Action governance | Tool access governance |
| **Deployment** | `pip install` | Docker (backend + frontend) |
| **Admin UI** | ❌ | ✅ Web portal |
| **MCP support** | ✅ MCP server | ✅ Core architecture |
| **Function allow-lists** | ✅ (policy rules) | ✅ Per-config granular |
| **Bundle system** | ❌ | ✅ User-composed bundles |
| **Context window optimization** | ❌ | ✅ 2-function surface |
| **Credential management** | ❌ | ✅ Org-shared or per-user |
| **Non-MCP frameworks** | ✅ 12+ | ❌ MCP-only |
| **Policy-as-code** | ✅ | Roadmap (OPA/Cedar planned) |

#### Where gate22 is better

- **MCP-native governance** — Purpose-built for MCP tool access management with a unified endpoint
- **Context window efficiency** — Bundles condense hundreds of tools into 2 functions (search + execute), keeping IDE context lean
- **Credential management** — Admin-controlled credential modes with separation of duties
- **Tool change auditing** — Tracks MCP server tool diffs to detect tool poisoning
- **Admin UI** — Web portal for visual management of MCP configurations

#### Where Agent OS is better

- **Framework diversity** — Works with any framework, not just MCP
- **In-process governance** — No network hop; sub-millisecond enforcement
- **Policy depth** — Rich policy rules with pattern matching, rate limiting, and human approval
- **Multi-agent** — Per-agent policies and inter-agent governance
- **Maturity** — 1,680+ tests, benchmarked performance, adopted by major frameworks

#### Complementary?

**Yes.** gate22 governs *which MCP tools are accessible* at the infrastructure level, while Agent OS governs *how those tools are used* at the agent level. Use gate22 for centralized MCP tool management and Agent OS for per-agent behavioral policies.

---

### 8. TrinityGuard (AI45Lab) (194★)

> **Repository:** [AI45Lab/TrinityGuard](https://github.com/AI45Lab/TrinityGuard)

#### Approach

TrinityGuard is a **multi-agent safety testing and monitoring framework** that covers 20 risk types across three levels: single-agent (L1), inter-agent communication (L2), and system-level (L3). It uses an LLM-powered "Judge" system for risk assessment and supports both pre-deployment testing and runtime monitoring.

#### Comparison

| Dimension | Agent OS | TrinityGuard |
|-----------|----------|-------------|
| **Primary mode** | Runtime enforcement | Testing + monitoring |
| **Enforcement** | ✅ Blocks actions | ⚠️ Detects and alerts |
| **Risk coverage** | 10 OWASP categories | 20 risk types (3 levels) |
| **Pre-deployment testing** | ❌ | ✅ Core capability |
| **Runtime monitoring** | ⚠️ Audit logs | ✅ Progressive monitoring |
| **Detection method** | Deterministic rules | LLM-powered Judge |
| **Framework support** | 12+ | AG2, AutoGen |
| **Plugin system** | Provider discovery | ✅ Extensible plugins |
| **Multi-agent** | ✅ | ✅ Core focus |
| **Risk taxonomy** | OWASP-based | Custom 3-level taxonomy |

#### Where TrinityGuard is better

- **Pre-deployment testing** — Designed to find vulnerabilities *before* agents go live, something Agent OS doesn't do
- **Risk taxonomy breadth** — 20 risk types across 3 levels with specialized detectors for each
- **LLM-powered analysis** — Uses LLMs to detect nuanced risks (group hallucination, malicious emergence) that rules can't catch
- **Progressive monitoring** — Dynamic sub-monitor activation adapts safety coverage to runtime conditions

#### Where Agent OS is better

- **Runtime enforcement** — Agent OS *blocks* dangerous actions; TrinityGuard primarily *detects* them
- **Framework coverage** — 12+ integrations vs. AG2/AutoGen focus
- **Performance** — <0.1ms deterministic checks vs. LLM inference latency
- **Production readiness** — 1,680+ tests, benchmark suite, enterprise adoption

#### Complementary?

**Yes — strong pairing.** Use TrinityGuard for pre-deployment safety testing and runtime risk detection, then Agent OS for deterministic runtime enforcement. TrinityGuard finds the risks; Agent OS blocks them.

---

## OWASP Agentic Top 10 Coverage Matrix

How each tool addresses the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-agentic-ai/):

| OWASP Risk | Agent OS | NeMo | LlamaGuard | Guardrails AI | IBM MCF | Invariant | Cordum | gate22 | TrinityGuard |
|------------|:--------:|:----:|:----------:|:-------------:|:-------:|:---------:|:------:|:------:|:------------:|
| **ASI01** Goal Hijack | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ | ⚠️ | ❌ | ✅ |
| **ASI02** Tool Misuse | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **ASI03** Identity & Privilege | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ |
| **ASI04** Supply Chain | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ | ❌ | ⚠️ | ❌ |
| **ASI05** Code Execution | ✅ | ⚠️ | ❌ | ❌ | ⚠️ | ✅ | ⚠️ | ❌ | ✅ |
| **ASI06** Memory Poisoning | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **ASI07** Inter-Agent Comms | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ✅ |
| **ASI08** Cascading Failures | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **ASI09** Human-Agent Trust | ✅ | ⚠️ | ❌ | ❌ | ⚠️ | ❌ | ✅ | ❌ | ❌ |
| **ASI10** Rogue Agents | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ✅ |
| **Coverage** | **8/10** | **2/10** | **1/10** | **0/10** | **4/10** | **3/10** | **4/10** | **2/10** | **6/10** |

> **Note:** OWASP Agentic Top 10 is designed for *agent* governance. Tools focused on I/O filtering (NeMo, LlamaGuard, Guardrails AI) address these risks indirectly or not at all — they were designed for different threat models.

---

## Performance Comparison

| Tool | Governance Latency (p99) | Deployment Overhead | GPU Required |
|------|--------------------------|---------------------|--------------|
| **Agent OS** | <0.1ms | None (in-process library) | ❌ |
| **NeMo Guardrails** | 10–50ms+ | Moderate (NIM microservices for best performance) | Optional (recommended) |
| **LlamaGuard** | 50–200ms | High (model inference) | ✅ |
| **Guardrails AI** | <50ms (async) | Low | ❌ |
| **IBM MCF** | 1–10ms (network hop) | High (Docker/K8s) | ❌ |
| **Invariant Labs** | 1–5ms (proxy mode) | Low–Moderate | ❌ |
| **Cordum** | 1–10ms (service calls) | High (Docker Compose) | ❌ |
| **gate22** | 1–10ms (gateway) | Moderate (Docker) | ❌ |
| **TrinityGuard** | 100ms+ (LLM judge) | Moderate | Optional |

Agent OS is the lowest-latency option because it operates in-process with no network hops or model inference. Tools that use network proxies (IBM MCF, gate22, Cordum) add 1–10ms. Tools that use LLM inference (LlamaGuard, TrinityGuard) add 50–200ms+.

---

## Using Multiple Tools Together

The strongest production setup combines tools from multiple layers. Here's a recommended architecture:

```
┌──────────────────────────────────────────────────────────┐
│                    User / Application                    │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│  LlamaGuard — Content Safety Screen (input)              │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│  NeMo Guardrails — Dialog Rails & Topic Control          │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│  LLM (GPT-4, Claude, Llama, etc.)                        │
└──────────────────────┬───────────────────────────────────┘
                       │ Tool Call Request
┌──────────────────────▼───────────────────────────────────┐
│  Agent OS Kernel — Action Governance                     │
│  ├── Policy evaluation (<0.1ms)                          │
│  ├── Human approval (if required)                        │
│  └── Audit logging                                       │
└──────────────────────┬───────────────────────────────────┘
                       │ Approved Call
┌──────────────────────▼───────────────────────────────────┐
│  IBM MCF / gate22 — MCP Gateway (if using MCP tools)     │
│  ├── Credential injection                                │
│  ├── Rate limiting                                       │
│  └── Tool registry                                       │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│  External Tools & APIs                                   │
└──────────────────────────────────────────────────────────┘
```

---

## Decision Guide

### Choose Agent OS when you need:
- Runtime governance for agent *actions* (tool calls, API access, file operations)
- Multi-framework support (LangChain, CrewAI, AutoGen, Dify, LlamaIndex, etc.)
- Sub-millisecond policy enforcement with zero infrastructure overhead
- OWASP Agentic Top 10 coverage across 8/10 risk categories
- Human-in-the-loop approval workflows
- Full audit trails for compliance

### Choose NeMo Guardrails when you need:
- Dialog flow control and topical rails for chatbots
- LLM input/output filtering with a domain-specific language
- Enterprise partnerships (Cisco, Palo Alto integrations)
- Advanced content moderation with GPU-accelerated NIM microservices

### Choose LlamaGuard when you need:
- High-accuracy content safety classification
- Nuanced detection of harmful content across 13+ categories
- Self-hosted, open-weight safety model
- Multilingual content moderation

### Choose Guardrails AI when you need:
- Structured output validation (JSON schema, Pydantic)
- Output quality enforcement with auto-retry
- Rich validator ecosystem from Guardrails Hub
- PII detection and removal in LLM responses

### Choose IBM MCF when you need:
- Enterprise MCP gateway with admin UI and RBAC
- Centralized tool registry with credential management
- Zero-trust architecture with 30+ built-in guardrails
- Production infrastructure with federation and HA

### Choose Invariant Labs when you need:
- Multi-step tool chain attack detection
- Transparent MCP/LLM proxy deployment
- Rich trace visualization and debugging
- Python-inspired security policy language

### Choose Cordum when you need:
- Standalone agent control plane with web dashboard
- Agent fleet management and pool segmentation
- Job-level safety gating with scheduler
- CAP protocol for distributed agent governance

### Choose gate22 when you need:
- MCP tool access governance with function allow-lists
- Context window optimization (2-function surface)
- Admin-controlled credential modes
- Visual MCP configuration management

### Choose TrinityGuard when you need:
- Pre-deployment multi-agent safety testing
- 20-type risk taxonomy across 3 levels
- LLM-powered risk analysis with progressive monitoring
- AG2/AutoGen multi-agent system safety

---

## Summary

| What you want | Best tool(s) |
|---------------|-------------|
| Block dangerous tool calls | **Agent OS**, Invariant Labs, IBM MCF |
| Filter LLM inputs/outputs | **NeMo Guardrails**, LlamaGuard |
| Validate output quality | **Guardrails AI** |
| Centralized MCP management | **IBM MCF**, gate22 |
| Agent fleet orchestration | **Cordum** |
| Pre-deployment safety testing | **TrinityGuard** |
| Multi-agent lifecycle governance | **Agent OS** + Cordum |
| Maximum OWASP coverage | **Agent OS** (8/10) + TrinityGuard (6/10) |
| Lowest latency | **Agent OS** (<0.1ms p99) |
| Best content safety | **LlamaGuard** + NeMo Guardrails |

**The bottom line:** These tools are complementary, not competing. The best production deployments layer multiple tools — content safety (LlamaGuard), dialog control (NeMo), output validation (Guardrails AI), action governance (Agent OS), and infrastructure management (IBM MCF/gate22) — to create defense in depth across the entire AI agent stack.

---

*Have a correction or addition? [Open an issue](https://github.com/microsoft/agent-governance-toolkit/issues) or [submit a PR](https://github.com/microsoft/agent-governance-toolkit/pulls).*
