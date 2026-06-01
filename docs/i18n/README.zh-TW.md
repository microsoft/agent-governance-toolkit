🌍 [English](/README.md) | [日本語](./README.ja.md) | [简体中文](./README.zh-CN.md) | [繁體中文](./README.zh-TW.md)

![Agent Governance Toolkit](../../docs/assets/readme-banner.svg)

# 歡迎使用代理治理工具包 !

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-npm_%40agentmesh%2Fsdk-blue?logo=typescript)](../../agent-governance-typescript/)
[![.NET 8.0+](https://img.shields.io/badge/.NET_8.0+-NuGet-blue?logo=dotnet)](https://www.nuget.org/packages/Microsoft.AgentGovernance)
[![Rust](https://img.shields.io/badge/Rust-crates.io-orange?logo=rust)](../../agent-governance-rust/agentmesh/)
[![Go](https://img.shields.io/badge/Go-module-00ADD8?logo=go)](../../agent-governance-golang/)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](../../docs/compliance/owasp-agentic-top10-architecture.md)
[![OpenSSF Best Practices](https://img.shields.io/cii/percentage/12085?label=OpenSSF%20Best%20Practices&logo=opensourcesecurity)](https://www.bestpractices.dev/projects/12085)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/microsoft/agent-governance-toolkit)

> [!IMPORTANT]
> **公開預覽版** — 此儲存庫中發布的所有套件均為 **經 Microsoft 簽署的公開預覽版**。它們達到
> 正式版的品質，但在正式發布 (GA) 之前可能存在重大變更。如有任何意見回饋，請在 [GitHub 上提交 Issue](https://github.com/microsoft/agent-governance-toolkit/issues)。
>
> **這個工具包是什麼：** 執行期治理基礎架構 — 位於您的代理框架與代理執行操作之間的確定性
> 策略執行、零信任身份驗證、執行沙箱，以及可靠性工程。
>
> **這個工具包不是什麼：** 這不是一個用於模型安全或提示詞防護的工具。它不會過濾大型語言模型
> (LLM) 的輸入/輸出，也不執行內容審核。它是在應用層對 *代理的行為* (工具呼叫、資源存取、
> 代理間通訊) 進行治理。對於模型層面的安全，請參閱 [Azure AI Content Safety](https://learn.microsoft.com/azure/ai-services/content-safety/)。

面向 AI 代理的執行期治理 — 唯一一個涵蓋全部 **10 項 OWASP Agentic 風險** 並提供 **13,000+ 測試** 的工具包。它治理的是代理 *做什麼*，而不僅僅是說什麼 — 包括確定性策略執行、零信任身份認證、執行沙箱，以及網站可靠性工程 (SRE) — 支援 **Python · TypeScript · .NET · Rust · Go**

> **適用於任何技術棧** — 支援 AWS Bedrock、Google ADK、Azure AI、LangChain、CrewAI、AutoGen、OpenAI Agents、LlamaIndex 等。只需透過 `pip install` 即可使用，無廠商鎖定。

## 📋 入門指南

### 📦 安裝

**Python** (PyPI)
```bash
pip install agent-governance-toolkit[full]
```

**TypeScript / Node.js** (npm)
```bash
npm install @microsoft/agent-governance-sdk
```

**.NET** (NuGet)
```bash
dotnet add package Microsoft.AgentGovernance
```

<details>
<summary>安裝單獨的 Python 套件</summary>

```bash
pip install agent-os-kernel        # 策略引擎
pip install agentmesh-platform     # 信任網格
pip install agentmesh-runtime       # 執行期監督器
pip install agent-sre              # SRE 工具包
pip install agent-governance-toolkit    # 合規與認證
pip install agentmesh-marketplace      # 外掛市場
pip install agentmesh-lightning        # 強化學習訓練治理
```
</details>

### 📚 文件

- **[快速入門](../../docs/quickstart.md)** — 在 10 分鐘內從零開始構建受治理的代理 (Python · TypeScript · .NET · Rust · Go)
- **[TypeScript 套件](../../agent-governance-typescript/README.md)** — 提供身份、信任、策略與稽核功能的 npm 套件
- **[.NET 套件](../../agent-governance-dotnet/README.md)** — 提供完整 OWASP 覆蓋的 NuGet 套件
- **[Rust crate](../../agent-governance-rust/agentmesh/README.md)** — crates.io 上的函式庫，包含策略、信任、稽核及 Ed25519 身份
- **[Go 模組](../../agent-governance-golang/README.md)** — 提供策略、信任、稽核與身份功能的 Go 模組
- **[教學](../../docs/tutorials/)** — 涵蓋策略、身份、整合、合規、SRE 與沙箱的逐步指南
- **[Azure 部署](../../docs/deployment/README.md)** — 支援 AKS、Azure AI Foundry、Container Apps、OpenClaw Sidecar
- **[NVIDIA OpenShell 整合](../../docs/integrations/openshell.md)** — 將沙箱隔離與治理智能相結合
- **[OWASP 合規](../../docs/compliance/owasp-agentic-top10-architecture.md)** — 完整覆蓋 ASI-01 至 ASI-10 的對應
- **[威脅模型](../../docs/security/threat-model.md)** — 包含信任邊界、攻擊面與 STRIDE 分析
- **[架構](../../docs/ARCHITECTURE.md)** — 系統設計、安全模型與信任評分
- **[架構決策](../../docs/adr/README.md)** — 關鍵身份、執行期與策略選擇的 ADR 記錄
- **[NIST RFI 對應](../../docs/compliance/nist-rfi-2026-00206.md)** — 對應 NIST AI Agent 安全 RFI 的對應 (2026-00206)

還有問題嗎？請提交一個 [GitHub Issue](https://github.com/microsoft/agent-governance-toolkit/issues) 或查看我們的 [社群頁面](../../docs/COMMUNITY.md)。

### ✨ **亮點**

- **確定性策略執行**：每個代理行為在執行 *前* 都會根據策略進行評估，延遲低於毫秒 (<0.1 ms)
  - [策略引擎](../../agent-governance-python/agent-os/) | [效能基準](../../docs/BENCHMARKS.md)
- **零信任代理身份**：基於 Ed25519 的加密憑證，支援 SPIFFE/SVID，信任評分範圍為 0–1000
  - [AgentMesh](../../agent-governance-python/agent-mesh/) | [信任評分](../../agent-governance-python/agent-mesh/)
- **執行沙箱**：4 層權限環、Saga 編排、終止控制與緊急停止 (kill switch)
  - [Agent Runtime](../../agent-governance-python/agent-runtime/) | [代理虛擬化管理器](../../agent-governance-python/agent-hypervisor/)
- **代理 SRE**：包含 SLO、錯誤預算、重播除錯、混沌工程、熔斷機制與漸進式發布
  - [Agent SRE](../../agent-governance-python/agent-sre/) | [可觀測性整合](../../agent-governance-python/agent-hypervisor/src/hypervisor/observability/)
- **MCP 安全掃描器**：偵測 MCP 工具定義中的工具投毒、拼寫劫持 (typosquatting)、隱藏指令與 rug-pull 攻擊
  - [MCP 掃描器](../../agent-governance-python/agent-os/src/agent_os/mcp_security.py) | [CLI](../../agent-governance-python/agent-os/src/agent_os/cli/mcp_scan.py)
- **信任報告 CLI**：`agentmesh trust report` — 視覺化信任評分、任務成功/失敗情況及代理活動
  - [信任 CLI](../../agent-governance-python/agent-mesh/src/agentmesh/cli/trust_cli.py)
- **金鑰掃描與模糊測試**：基於 Gitleaks 的工作流，包含 7 個模糊測試目標，涵蓋策略、注入、沙箱、信任及 MCP
  - [安全工作流](../../.github/workflows/)
- **12+ 框架整合**：支援 Microsoft Agent Framework、LangChain、CrewAI、AutoGen、Dify、LlamaIndex、OpenAI Agents、Google ADK 等
  - [框架快速入門](../../examples/quickstart/) | [整合方案](../../docs/proposals/)
- **完整 OWASP 覆蓋**：針對 Agentic Top 10 風險實現 10/10 覆蓋，每個 ASI 類別均有專屬控制措施
  - [OWASP 合規](../../docs/compliance/owasp-agentic-top10-architecture.md) | [競品比較](../../docs/COMPARISON.md)
- **GitHub Actions 支援 CI/CD**：為 PR 工作流提供自動化安全掃描與治理證明
  - [安全掃描 Action](../../action/security-scan/) | [治理證明 Action](../../action/governance-attestation/)

### 💬 **我們期待您的意見回饋！**

- 如發現 Bug，請提交 [GitHub Issue](https://github.com/microsoft/agent-governance-toolkit/issues)。

## 快速入門

### 執行策略 — Python

```python
from agent_os import PolicyEngine, CapabilityModel

# 定義此代理允許執行的操作
capabilities = CapabilityModel(
    allowed_tools=["web_search", "file_read"],
    denied_tools=["file_write", "shell_exec"],
    max_tokens_per_call=4096
)

# 在每次操作前強制執行策略
engine = PolicyEngine(capabilities=capabilities)
decision = engine.evaluate(agent_id="researcher-1", action="tool_call", tool="web_search")

if decision.allowed:
    # 繼續進行工具呼叫
    ...
```

### 執行策略 — TypeScript

```typescript
import { PolicyEngine } from "@microsoft/agent-governance-sdk";

const engine = new PolicyEngine([
  { action: "web_search", effect: "allow" },
  { action: "shell_exec", effect: "deny" },
]);

const decision = engine.evaluate("web_search"); // "allow"
```

### 執行策略 — .NET

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

if (result.Allowed) { /* 繼續執行 */ }
```

### 執行策略 — Rust

```rust
use agentmesh::{AgentMeshClient, ClientOptions};

let client = AgentMeshClient::new("my-agent").unwrap();
let result = client.execute_with_governance("data.read", None);
assert!(result.allowed);
```

### 執行策略 — Go

```go
import agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang"

client, _ := agentmesh.NewClient("my-agent",
    agentmesh.WithPolicyRules([]agentmesh.PolicyRule{
        {Action: "data.read", Effect: agentmesh.Allow},
        {Action: "*", Effect: agentmesh.Deny},
    }),
)
result := client.ExecuteWithGovernance("data.read", nil)
// result.Allowed == true
```

### 執行治理示範

```bash
# 完整治理示範 (policy enforcement, audit, trust, cost, reliability)
python examples/demos/maf_governance_demo.py

# 使用對抗性攻擊場景執行
python examples/demos/maf_governance_demo.py --include-attacks
```

## 更多範例與樣本

- **[框架快速入門](../../examples/quickstart/)** — 單檔案受治理代理適用於 LangChain、CrewAI、AutoGen、OpenAI Agents、Google ADK
- **[教學 1: Policy Engine](../../docs/tutorials/01-policy-engine.md)** — 定義並執行治理策略
- **[教學 2: Trust & Identity](../../docs/tutorials/02-trust-and-identity.md)** — 零信任代理憑證
- **[教學 3: Framework Integrations](../../docs/tutorials/03-framework-integrations.md)** — 為任何框架新增治理
- **[教學 4: Audit & Compliance](../../docs/tutorials/04-audit-and-compliance.md)** — OWASP 合規與證明
- **[教學 5: Agent Reliability](../../docs/tutorials/05-agent-reliability.md)** — SLO、錯誤預算、混沌測試
- **[教學 6: Execution Sandboxing](../../docs/tutorials/06-execution-sandboxing.md)** — 權限環與終止機制

## OPA/Rego 與 Cedar 策略支援

將您現有的基礎架構策略引入代理治理 — 無需新的策略 DSL。

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

每個後端支援三種評估模式：**內嵌引擎** (cedarpy/opa CLI)、**遠端伺服器**，或 **內建回退** (零外部相依性)。

## SDK 與套件

### 多語言 SDK

| 語言 | Package | Install |
|----------|---------|---------|
| **Python** | [`agent-governance-toolkit[full]`](https://pypi.org/project/agent-governance-toolkit/) | `pip install agent-governance-toolkit[full]` |
| **TypeScript** | [`@microsoft/agent-governance-sdk`](../../agent-governance-typescript/) | `npm install @microsoft/agent-governance-sdk` |
| **.NET** | [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) | `dotnet add package Microsoft.AgentGovernance` |
| **Rust** | [`agentmesh`](https://crates.io/crates/agentmesh) | `cargo add agentmesh` |
| **Go** | [`agentmesh`](../../agent-governance-golang/) | `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang` |

### Python 套件 (PyPI)

| 套件 | PyPI | 說明 |
|---------|------|-------------|
| **Agent OS** | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | 策略引擎 — 確定性動作評估、能力模型、稽核日誌、動作攔截、MCP 閘道 |
| **AgentMesh** | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | 代理間信任 — Ed25519 身份、SPIFFE/SVID 憑證、信任評分、A2A/MCP/IATP 協定橋接 |
| **Agent Runtime** | [`agentmesh-runtime`](../../agent-governance-python/agent-runtime/) | 執行期監督器 — 四層權限環、Saga 編排、終止控制、聯合責任、僅附加稽核日誌 |
| **Agent SRE** | [`agent-sre`](https://pypi.org/project/agent-governance-python/agent-sre/) | 可靠性工程 — SLO、錯誤預算、重播除錯、混沌工程、漸進式發布 |
| **Agent Compliance** | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | 執行期策略執行 — OWASP ASI 2026 控制、治理證明、完整性驗證 |
| **Agent Marketplace** | [`agentmesh-marketplace`](../../agent-governance-python/agent-marketplace/) | 外掛生命週期 — 探索、安裝、驗證和簽署外掛 |
| **Agent Lightning** | [`agentmesh-lightning`](../../agent-governance-python/agent-lightning/) | RL 訓練治理 — 受治理執行器、策略獎勵 |

## 框架整合

適用於 **20+ 代理框架**，包括：

| 框架 | Stars | 整合方式 |
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

## OWASP Agentic Top 10 覆蓋

| 風險 | ID | 狀態 |
|------|----|--------|
| 代理目標劫持 | ASI-01 | ✅ 策略引擎阻止未授權的目標變更 |
| 過度能力 | ASI-02 | ✅ 能力模型強制最小權限原則 |
| 身份與權限濫用 | ASI-03 | ✅ 基於 Ed25519 憑證的零信任身份 |
| 代理供應鏈攻擊 | ASI-04 | ✅ 相依混淆掃描 + 工具驗證 |
| 意外程式碼執行 | ASI-05 | ✅ Agent Runtime 執行環 + 沙箱 |
| 記憶體投毒 | ASI-06 | ✅ 帶完整性檢查的情節記憶 |
| 不安全的代理間通訊 | ASI-07 | ✅ AgentMesh 加密通道 + 信任閘控 |
| 級聯故障 | ASI-08 | ✅ 熔斷器 + SLO 執行 |
| 人機信任缺失 | ASI-09 | ✅ 完整稽核軌跡 + 飛行記錄器 |
| 惡意代理 | ASI-10 | ✅ 終止開關 + 權限環隔離 + 行為異常偵測 |

完整對應包含實作細節和測試證據：**[OWASP-COMPLIANCE.md](../../docs/compliance/owasp-agentic-top10-architecture.md)**

### 法規對應

| 法規 | 截止日期 | AGT 覆蓋 |
|------------|----------|-------------|
| 歐盟 AI 法案 — 高風險 AI (Annex III) | 2026 年 8 月 2 日 | 稽核軌跡 (Art. 12)、風險管理 (Art. 9)、人工監督 (Art. 14) |
| Colorado AI 法案 (SB 24-205) | 2026 年 6 月 30 日 | 風險評估、人工監督機制、消費者揭露 |
| 歐盟 AI 法案 — GPAI 義務 | 生效中 | 透明性、著作權策略、系統性風險評估 |

AGT 提供 **執行期治理** — 規定代理允許執行的操作。對於 **資料治理** 和面向監管機構的證據匯出，可參考 [Microsoft Purview DSPM for AI](https://learn.microsoft.com/purview/ai-microsoft-purview) 作為補充層。

## 效能

治理額外負荷為 **每次操作 < 0.1 ms** — 大約比一次 LLM API 呼叫快 10,000 倍。

| 指標 | 延遲 (p50) | 吞吐量 |
|---|---|---|
| 策略評估（1 條規則） | 0.012 ms | 72K ops/sec |
| 策略評估（100 條規則） | 0.029 ms | 31K ops/sec |
| 核心層級執行 | 0.091 ms | 9.3K ops/sec |
| 轉接器額外負荷 | 0.004–0.006 ms | 130K–230K ops/sec |
| 並行吞吐量（50 個 agents） | — | 35,481 ops/sec |

完整方法論及各轉接器細分：**[BENCHMARKS.md](../../docs/BENCHMARKS.md)**

## 安全模型與限制

此工具包提供 **應用層 (Python middleware) 治理**，而非作業系統核心層隔離。策略引擎與其治理的代理執行在 **同一個 Python 程序中**。這與所有基於 Python 的代理框架 (如 LangChain、CrewAI、AutoGen 等) 使用相同的信任邊界。

| 層 | 提供能力 | 不提供 |
|-------|-----------------|------------------------|
| 策略引擎 | 確定性動作攔截、拒絕清單執行 | 硬體層級記憶體隔離 |
| 身份 (IATP) | 基於 Ed25519 的加密代理憑證、信任評分 | 作業系統層級程序隔離 |
| 執行環 | 具資源限制的邏輯權限層級 | CPU 環層級強制執行 |
| 啟動完整性 | 啟動時對治理模組進行 SHA-256 竄改偵測 | 硬體信任根 (如 TPM/Secure Boot) |

**正式環境建議：**
- 將每個代理執行在 **獨立容器中**，以實現作業系統層級隔離
- 所有安全策略規則以 **可設定範例設定** 形式提供 — 請根據您的環境進行審查和自訂 (參見 `examples/policies/`)
- 不應將任何內建規則集視為完整
- 詳細資訊參見 [Architecture — Security Model & Boundaries](../../docs/ARCHITECTURE.md)

### 安全工具

| 工具 | 覆蓋範圍 |
|------|----------|
| CodeQL | Python + TypeScript 靜態應用安全測試 |
| Gitleaks | 在 PR/push/每週執行金鑰掃描 |
| ClusterFuzzLite | 7 個模糊測試目標 (policy, injection, MCP, sandbox, trust) |
| Dependabot | 13 個生態系統 (pip, npm, nuget, cargo, gomod, docker, actions) |
| OpenSSF Scorecard | 每週評分 + SARIF 上傳 |
| SBOM | SPDX + CycloneDX 產生與證明 |
| Dependency Review | PR 階段 CVE 和授權檢查 |

## 貢獻者資源

- [貢獻指南](../../CONTRIBUTING.md)
- [社群](../../docs/COMMUNITY.md)
- [安全政策](../../SECURITY.md)
- [架構](../../docs/ARCHITECTURE.md)
- [Changelog](../../CHANGELOG.md)
- [Support](../../SUPPORT.md)

## 重要聲明

如果您使用 Agent Governance Toolkit 建立與第三方代理框架或服務協作的應用程式，則需自行承擔風險。我們建議您審查所有與第三方服務共享的資料，並了解第三方在資料保留和資料存放位置方面的做法。您有責任管理您的資料是否會流出組織的合規範圍和地理邊界，以及相關影響。

## 授權條款

本專案基於 [MIT License](../../LICENSE) 進行授權。

## 商標

本專案可能包含專案、產品或服務的商標或標誌。Microsoft 商標或標誌的授權使用需遵循 [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general)。在本專案的修改版本中使用 Microsoft 商標或標誌，不得造成混淆或暗示 Microsoft 的贊助。任何第三方商標或標誌的使用，均需遵循該第三方的相關政策。
