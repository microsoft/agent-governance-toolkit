🌍 [English](/README.md) | [日本語](./README.ja.md) | [简体中文](./README.zh-CN.md)

![Agent Governance Toolkit](../../docs/assets/readme-banner.svg)

# 欢迎使用代理治理工具包 !

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-npm_%40agentmesh%2Fsdk-blue?logo=typescript)](../../packages/agent-mesh/sdks/typescript/)
[![.NET 8.0+](https://img.shields.io/badge/.NET_8.0+-NuGet-blue?logo=dotnet)](https://www.nuget.org/packages/Microsoft.AgentGovernance)
[![Rust](https://img.shields.io/badge/Rust-crates.io-orange?logo=rust)](../../packages/agent-mesh/sdks/rust/agentmesh/)
[![Go](https://img.shields.io/badge/Go-module-00ADD8?logo=go)](../../packages/agent-mesh/sdks/go/)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](../../docs/OWASP-COMPLIANCE.md)
[![OpenSSF Best Practices](https://img.shields.io/cii/percentage/12085?label=OpenSSF%20Best%20Practices&logo=opensourcesecurity)](https://www.bestpractices.dev/projects/12085)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/microsoft/agent-governance-toolkit)

> [!IMPORTANT]
> **公开预览版** — 此仓库中发布的所有软件包均为 **经 Microsoft 签名的公开预览版**。它们达到
> 生产级别的质量，但在正式发布(GA)之前可能存在重大变更。如有任何反馈，请在[GitHub上提交issue](https://github.com/microsoft/agent-governance-toolkit/issues)。
>
> **这个工具包是什么:** 运行时治理基础设施 — 位于你的代理框架与代理执行操作之间的确定性
> 策略执行、零信任身份验证、执行沙箱，以及可靠性工程。
>
> **这个工具包不是什么:** 这不是一个用于模型安全或提示词防护的工具。它不会过滤大语言模型
> (LLM)的输入/输出，也不执行内容审核。它是在应用层对 *代理的行为* (工具调用、资源访问、
> 代理间通信)进行治理。对于模型层面的安全，请参考[Azure AI Content Safety](https://learn.microsoft.com/azure/ai-services/content-safety/)。

面向 AI 代理的运行时治理 — 唯一一个覆盖全部 **10 项 OWASP Agentic 风险** 并提供 **9,500+ 测试** 的工具包。 它治理的是代理 *做什么*, 而不仅仅是说什么 — 包括确定性策略执行、零信任身份认证、执行沙箱，以及站点可靠性工程(SRE) — 支持 **Python · TypeScript · .NET · Rust · Go**

> **适用于任何技术栈** — 支持 AWS Bedrock, Google ADK, Azure AI, LangChain, CrewAI, AutoGen, OpenAI Agents, LlamaIndex 等。 只需通过 `pip install` 即可使用，无厂商锁定。

## 📋 入门指南

### 📦 安装

**Python** (PyPI)
```bash
pip install agent-governance-toolkit[full]
```

**TypeScript / Node.js** (npm)
```bash
npm install @microsoft/agentmesh-sdk
```

**.NET** (NuGet)
```bash
dotnet add package Microsoft.AgentGovernance
```

<details>
<summary>安装单独的 Python 软件包</summary>

```bash
pip install agent-os-kernel        # 策略引擎
pip install agentmesh-platform     # 信任网格
pip install agentmesh-runtime       # 运行时监督器
pip install agent-sre              # SRE 工具包
pip install agent-governance-toolkit    # 合规与认证
pip install agentmesh-marketplace      # 插件市场
pip install agentmesh-lightning        # 强化学习训练治理
```
</details>

### 📚 文档

- **[快速入门](../../QUICKSTART.md)** — 在 10 分钟内从零开始构建受治理的代理 (Python · TypeScript · .NET · Rust · Go)
- **[TypeScript SDK](../../packages/agent-mesh/sdks/typescript/README.md)** — 提供身份、信任、策略与审计功能的 npm 包
- **[.NET SDK](../../packages/agent-governance-dotnet/README.md)** — 提供完整 OWASP 覆盖的 NuGet 包
- **[Rust SDK](../../packages/agent-mesh/sdks/rust/agentmesh/README.md)** — crates.io 上的库，包含策略、信任、审计及 Ed25519 身份
- **[Go SDK](../../packages/agent-mesh/sdks/go/README.md)** — 提供策略、信任、审计与身份功能的 Go 模块
- **[教程](../../docs/tutorials/)** — 涵盖策略、身份、集成、合规、SRE 与沙箱的分步指南
- **[Azure 部署](../../docs/deployment/README.md)** — 支持 AKS, Azure AI Foundry, Container Apps, OpenClaw 边车
- **[NVIDIA OpenShell 集成](../../docs/integrations/openshell.md)** — 将沙箱隔离与治理智能相结合
- **[OWASP 合规](../../docs/OWASP-COMPLIANCE.md)** — 完整覆盖 ASI-01 至 ASI-10 的映射
- **[威胁模型](../../docs/THREAT_MODEL.md)** — 包含信任边界、攻击面与 STRIDE 分析
- **[架构](../../docs/ARCHITECTURE.md)** — 系统设计、安全模型与信任评分
- **[架构决策](../../docs/adr/README.md)** — 关键身份、运行时与策略选择的 ADR 记录
- **[NIST RFI 映射](../../docs/compliance/nist-rfi-2026-00206.md)** — 对应 NIST AI Agent 安全 RFI 的映射 (2026-00206)

还有问题吗？请提交一个 [GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues) 或查看我们的 [社区页面](../../COMMUNITY.md).

### ✨ **亮点**

- **确定性策略执行**: 每个代理行为在执行 *前* 都会根据策略进行评估，延迟低于毫秒级 (<0.1 ms)
  - [策略引擎](../../packages/agent-os/) | [性能基准](../../BENCHMARKS.md)
- **零信任代理身份**: 基于 Ed25519 的加密凭证，支持 SPIFFE/SVID，信任评分范围为 0–1000 
  - [AgentMesh](../../packages/agent-mesh/) | [信任评分](../../packages/agent-mesh/)
- **执行沙箱**: 4 层权限环、Saga 编排、终止控制与紧急停止(kill switch)
  - [Agent Runtime](../../packages/agent-runtime/) | [代理虚拟化管理器](../../packages/agent-hypervisor/)
- **代理 SRE**: 包含 SLO、错误预算、回放调试、混沌工程、熔断机制与渐进式发布
  - [Agent SRE](../../packages/agent-sre/) | [可观测性集成](../../packages/agent-hypervisor/src/hypervisor/observability/)
- **MCP 安全扫描器**: 检测 MCP 工具定义中的工具投毒、拼写劫持(typosquatting)、隐藏指令与rug-pull攻击
  - [MCP 扫描器](../../packages/agent-os/src/agentos/mcp_security.py) | [CLI](../../packages/agent-os/src/agentos/cli/mcp_scan.py)
- **信任报告 CLI**: `agentmesh trust report` — 可视化信任评分、任务成功/失败情况及代理活动
  - [信任 CLI](../../packages/agent-mesh/src/agentmesh/cli/trust_cli.py)
- **密钥扫描与模糊测试**: 基于 Gitleaks 的工作流，包含 7 个模糊测试目标，覆盖策略、注入、沙箱、信任及 MCP
  - [安全工作流](../../.github/workflows/)
- **12+ 框架集成**: 支持 Microsoft Agent Framework, LangChain, CrewAI, AutoGen, Dify, LlamaIndex, OpenAI Agents, Google ADK 等
  - [框架快速入门](../../examples/quickstart/) | [集成方案](../../docs/proposals/)
- **完整 OWASP 覆盖**: 针对 Agentic Top 10 风险实现 10/10 覆盖，每个 ASI 类别均有专属控制措施
  - [OWASP 合规](../../docs/OWASP-COMPLIANCE.md) | [竞品对比](../../docs/COMPARISON.md)
- **GitHub Actions 支持 CI/CD**: 为 PR 工作流提供自动化安全扫描与治理证明
  - [安全扫描 Action](../../action/security-scan/) | [治理证明 Action](../../action/governance-attestation/)

### 💬 **我们期待你的反馈!**

- 如发现 Bug，请提交 [GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues).

## 快速入门

### 执行策略 — Python

```python
from agent_os import PolicyEngine, CapabilityModel

# 定义此代理允许执行的操作
capabilities = CapabilityModel(
    allowed_tools=["web_search", "file_read"],
    denied_tools=["file_write", "shell_exec"],
    max_tokens_per_call=4096
)

# 在每次操作前强制执行策略
engine = PolicyEngine(capabilities=capabilities)
decision = engine.evaluate(agent_id="researcher-1", action="tool_call", tool="web_search")

if decision.allowed:
    # 继续进行工具调用
    ...
```

### 执行策略 — TypeScript

```typescript
import { PolicyEngine } from "@microsoft/agentmesh-sdk";

const engine = new PolicyEngine([
  { action: "web_search", effect: "allow" },
  { action: "shell_exec", effect: "deny" },
]);

const decision = engine.evaluate("web_search"); // "allow"
```

### 执行策略 — .NET

```csharp
using AgentGovernance;
using AgentGovernance.Policy;

var kernel = new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = new() { "policies/default.yaml" },
});

var result = kernel.EvaluateToolCall(
    agentId: "did:mesh:researcher-1",
    toolName: "web_search",
    args: new() { ["query"] = "latest AI news" }
);

if (result.Allowed) { /* 继续执行 */ }
```

### 执行策略 — Rust

```rust
use agentmesh::{AgentMeshClient, ClientOptions};

let client = AgentMeshClient::new("my-agent").unwrap();
let result = client.execute_with_governance("data.read", None);
assert!(result.allowed);
```

### 执行策略 — Go

```go
import agentmesh "github.com/microsoft/agent-governance-toolkit/sdks/go"

client, _ := agentmesh.NewClient("my-agent",
    agentmesh.WithPolicyRules([]agentmesh.PolicyRule{
        {Action: "data.read", Effect: agentmesh.Allow},
        {Action: "*", Effect: agentmesh.Deny},
    }),
)
result := client.ExecuteWithGovernance("data.read", nil)
// result.Allowed == true
```

### 运行治理演示

```bash
# 完整治理演示 (policy enforcement, audit, trust, cost, reliability)
python demo/maf_governance_demo.py

# 使用对抗性攻击场景运行
python demo/maf_governance_demo.py --include-attacks
```

## 更多示例与样本

- **[框架快速入门](../../examples/quickstart/)** — 单文件受治理代理适用于 LangChain, CrewAI, AutoGen, OpenAI Agents, Google ADK
- **[教程 1: Policy Engine](../../docs/tutorials/01-policy-engine.md)** — 定义并执行治理策略
- **[教程 2: Trust & Identity](../../docs/tutorials/02-trust-and-identity.md)** — 零信任代理凭证
- **[教程 3: Framework Integrations](../../docs/tutorials/03-framework-integrations.md)** — 为任何框架添加治理
- **[教程 4: Audit & Compliance](../../docs/tutorials/04-audit-and-compliance.md)** — OWASP 合规与证明
- **[教程 5: Agent Reliability](../../docs/tutorials/05-agent-reliability.md)** — SLOs, 错误预算, 混沌测试
- **[教程 6: Execution Sandboxing](../../docs/tutorials/06-execution-sandboxing.md)** — 权限环与终止机制

## OPA/Rego 与 Cedar 策略支持

将您现有的基础设施策略引入代理治理 — 无需新的策略 DSL。

### OPA/Rego (Agent OS)

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_rego(rego_content="""
package agentos
default allow = false
allow { input.tool_name == "web_search" }
allow { input.role == "admin" }
""")

decision = evaluator.evaluate({"tool_name": "web_search", "role": "analyst"})
# decision.allowed == True
```

### Cedar (Agent OS)

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_cedar(policy_content="""
permit(principal, action == Action::"ReadData", resource);
forbid(principal, action == Action::"DeleteFile", resource);
""")

decision = evaluator.evaluate({"tool_name": "read_data", "agent_id": "agent-1"})
# decision.allowed == True
```

### AgentMesh OPA/Cedar

```python
from agentmesh.governance import PolicyEngine

engine = PolicyEngine()
engine.load_rego("policies/mesh.rego", package="agentmesh")
engine.load_cedar(cedar_content='permit(principal, action == Action::"Analyze", resource);')

decision = engine.evaluate("did:mesh:agent-1", {"tool_name": "analyze"})
```

每个后端支持三种评估模式: **内嵌引擎** (cedarpy/opa CLI), **远程服务器**, 或 **内置回退** (零外部依赖).

## SDKs & 软件包

### 多语言 SDKs

| 语言 | Package | Install |
|----------|---------|---------|
| **Python** | [`agent-governance-toolkit[full]`](https://pypi.org/project/agent-governance-toolkit/) | `pip install agent-governance-toolkit[full]` |
| **TypeScript** | [`@microsoft/agentmesh-sdk`](../../packages/agent-mesh/sdks/typescript/) | `npm install @microsoft/agentmesh-sdk` |
| **.NET** | [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) | `dotnet add package Microsoft.AgentGovernance` |
| **Rust** | [`agentmesh`](https://crates.io/crates/agentmesh) | `cargo add agentmesh` |
| **Go** | [`agentmesh`](../../packages/agent-mesh/sdks/go/) | `go get github.com/microsoft/agent-governance-toolkit/sdks/go` |

### Python 软件包 (PyPI)

| 软件包 | PyPI | 描述 |
|---------|------|-------------|
| **Agent OS** | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | 策略引擎 — 确定性动作评估、能力模型、审计日志、动作拦截、MCP 网关 |
| **AgentMesh** | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | 代理间信任 — Ed25519 身份、SPIFFE/SVID 凭证、信任评分、A2A/MCP/IATP 协议桥接 |
| **Agent Runtime** | [`agentmesh-runtime`](../../packages/agent-runtime/) | 执行监督器 — 四层权限环、 saga 编排 、终止控制、联合责任、仅追加审计日志 |
| **Agent SRE** | [`agent-sre`](https://pypi.org/project/agent-sre/) | 可靠性工程 — SLOs、错误预算、重放调试、混沌工程、渐进式发布 |
| **Agent Compliance** | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | 运行时策略执行 — OWASP ASI 2026 控制、治理证明、完整性验证 |
| **Agent Marketplace** | [`agentmesh-marketplace`](../../packages/agent-marketplace/) | 插件生命周期 — 发现、安装、验证和签名插件 |
| **Agent Lightning** | [`agentmesh-lightning`](../../packages/agent-lightning/) | RL 训练治理 — 受治理运行器、策略奖励 |

## 框架集成

适用于 **20+ 代理框架** ，包括:

| 框架 | Stars | 集成 |
|-----------|-------|-------------|
| [**Microsoft Agent Framework**](https://github.com/microsoft/agent-framework) | 8K+ ⭐ | **Native Middleware** |
| [**Semantic Kernel**](https://github.com/microsoft/semantic-kernel) | 27K+ ⭐ | **Native (.NET + Python)** |
| [Dify](https://github.com/langgenius/dify) | 133K+ ⭐ | Plugin |
| [Microsoft AutoGen](https://github.com/microsoft/autogen) | 55K+ ⭐ | Adapter |
| [LlamaIndex](https://github.com/run-llama/llama_index) | 47K+ ⭐ | Middleware |
| [CrewAI](https://github.com/crewAIInc/crewAI) | 46K+ ⭐ | Adapter |
| [LangGraph](https://github.com/langchain-ai/langgraph) | 27K+ ⭐ | Adapter |
| [Haystack](https://github.com/deepset-ai/haystack) | 24K+ ⭐ | Pipeline |
| [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) | 20K+ ⭐ | Middleware |
| [Google ADK](https://github.com/google/adk-python) | 18K+ ⭐ | Adapter |
| [Azure AI Foundry](https://learn.microsoft.com/azure/ai-studio/) | — | Deployment Guide |

## OWASP Agentic Top 10 Coverage

| 风险 | ID | 状态 |
|------|----|--------|
| 代理目标劫持 | ASI-01 | ✅ 策略引擎阻止未授权的目标更改 |
| 过度能力 | ASI-02 | ✅ 能力模型强制最小权限原则 |
| 身份与权限滥用 | ASI-03 | ✅ 基于 Ed25519 证书的零信任身份 |
| 不受控代码执行 | ASI-04 | ✅ Agent Runtime 执行环 + 沙箱 |
| 不安全输出处理 | ASI-05 | ✅ 内容策略验证所有输出 |
| 内存投毒 | ASI-06 | ✅ 带完整性检查的情节记忆 |
| 不安全的代理间通信 | ASI-07 | ✅ AgentMesh 加密通道 + 信任门控 |
| 级联故障 | ASI-08 | ✅ 断路器 + SLO 执行 |
| 人机信任缺失 | ASI-09 | ✅ 完整审计轨迹 + 飞行记录器 |
| 恶意代理 | ASI-10 | ✅ 终止开关 + 权限环隔离 + 行为异常检测 |

完整映射包含实现细节和测试证据: **[OWASP-COMPLIANCE.md](../../docs/OWASP-COMPLIANCE.md)**

### 监管对齐

| 法规 | 截止日期 | AGT 覆盖 |
|------------|----------|-------------|
| 欧盟 AI 法案 — 高风险 AI (Annex III) | 2026 年 8 月 2 日 | 审计轨迹 (Art. 12), 风险管理 (Art. 9), 人工监督 (Art. 14) |
| Colorado AI 法案 (SB 24-205) | 2026 年 6 月 30 日 | 风险评估、人工监督机制、消费者披露 |
| 欧盟 AI 法案 — GPAI 义务 | 生效中 | 透明性, 版权策略, 系统性风险评估 |

AGT 提供 **运行时治理** — 规定代理允许执行的操作。对于 **数据治理**和面向监管机构的证据导出，可参考 [Microsoft Purview DSPM for AI](https://learn.microsoft.com/purview/ai-microsoft-purview) 作为补充层。

## 性能

治理开销为 **每次操作 < 0.1 ms** — 大约比一次 LLM API 调用快 10,000 倍。

| 指标 | 延迟 (p50) | 吞吐量 |
|---|---|---|
| 策略评估（1 条规则） | 0.012 ms | 72K ops/sec |
| 策略评估（100 条规则） | 0.029 ms | 31K ops/sec |
| 内核级执行 | 0.091 ms | 9.3K ops/sec |
| 适配器开销 | 0.004–0.006 ms | 130K–230K ops/sec |
| 并发吞吐量（50 个 agents） | — | 35,481 ops/sec |

完整方法论及各适配器细分: **[BENCHMARKS.md](../../BENCHMARKS.md)**

## 安全模型与限制

该工具包提供 **应用层 (Python middleware) 治理**，而非操作系统内核级隔离。策略引擎与其治理的代理运行在 **同一个 Python 进程中**. 这与所有基于 Python 的代理框架 (如 LangChain, CrewAI, AutoGen 等)使用相同的信任边界。

| 层 | 提供能力 | 不提供 |
|-------|-----------------|------------------------|
| 策略引擎 | 确定性动作拦截、拒绝列表执行 | 硬件级内存隔离 |
| 身份 (IATP) | 基于 Ed25519 的加密代理凭证、信任评分 | 操作系统级进程隔离 |
| 执行环 | 具资源限制的逻辑权限层级 | CPU 环级强制执行 |
| 启动完整性 | 启动时对治理模块进行 SHA-256 篡改检测 | 硬件信任根 (如TPM/Secure Boot) |

**生产环境建议:**
- 将每个代理运行在 **独立容器中** ，以实现操作系统级隔离
- 所有安全策略规则以 **可配置示例配置** 形式提供 — 请根据你的环境进行审查和自定义 (参见 `examples/policies/`)
- 不应将任何内置规则集视为完整
- 详细信息参见 [Architecture — Security Model & Boundaries](../../docs/ARCHITECTURE.md)

### 安全工具

| 工具 | 覆盖范围 |
|------|----------|
| CodeQL | Python + TypeScript 静态应用安全测试 |
| Gitleaks | 在 PR/push/每周执行密钥扫描 |
| ClusterFuzzLite | 7 个模糊测试目标 (policy, injection, MCP, sandbox, trust) |
| Dependabot | 13 个生态系统 (pip, npm, nuget, cargo, gomod, docker, actions) |
| OpenSSF Scorecard | 每周评分 + SARIF 上传 |
| SBOM | SPDX + CycloneDX 生成与证明 |
| Dependency Review | PR 阶段 CVE 和许可证检查 |

## 贡献者资源

- [贡献指南](../../CONTRIBUTING.md)
- [社区](../../COMMUNITY.md)
- [安全策略](../../SECURITY.md)
- [架构](../../docs/ARCHITECTURE.md)
- [Changelog](../../CHANGELOG.md)
- [Support](../../SUPPORT.md)

## 重要说明

如果你使用 Agent Governance Toolkit 建与第三方代理框架或服务协作的应用程序，则需自行承担风险。我们建议你审查所有与第三方服务共享的数据，并了解第三方在数据保留和数据存储位置方面的实践。你有责任管理你的数据是否会流出组织的合规范围和地理边界，以及相关影响。

## 许可证

本项目基于 [MIT License](../../LICENSE) 进行授权。

## 商标

本项目可能包含项目、产品或服务的商标或标志。Microsoft 商标或标志的授权使用需遵循[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).在本项目的修改版本中使用 Microsoft 商标或标志，不得造成混淆或暗示 Microsoft 的赞助。任何第三方商标或标志的使用，均需遵循该第三方的相关政策。