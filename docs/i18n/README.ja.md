> この文書は [README.md](/README.md) の日本語訳です。最新の情報は英語版をご確認ください。

🌍 [English](/README.md) | [日本語](./README.ja.md) | [简体中文](./README.zh-CN.md)

![Agent Governance Toolkit](../../docs/assets/readme-banner.svg)

# Agent Governance Toolkit へようこそ！

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
> **パブリックプレビュー** — このリポジトリから公開されるすべてのパッケージは
> **Microsoft 署名済みのパブリックプレビューリリース**です。プロダクション品質ですが、
> GA（一般提供）前に破壊的変更が行われる可能性があります。フィードバックは
> [GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues) からお寄せください。
>
> **このツールキットとは：** ランタイムガバナンスインフラストラクチャ — エージェントフレームワークと
> エージェントが実行するアクションの間に位置する、決定論的ポリシー適用、ゼロトラストID、
> 実行サンドボックス、および信頼性エンジニアリング。
>
> **このツールキットではないもの：** モデルの安全性やプロンプトガードレールのツールではありません。
> LLM の入出力フィルタリングやコンテンツモデレーションは行いません。アプリケーション層で
> *エージェントのアクション*（ツール呼び出し、リソースアクセス、エージェント間通信）を
> ガバナンスします。モデルレベルの安全性については、
> [Azure AI Content Safety](https://learn.microsoft.com/azure/ai-services/content-safety/) をご参照ください。

AI エージェントのためのランタイムガバナンス — **OWASP Agentic リスク全10項目**を **9,500 以上のテスト**でカバーする唯一のツールキット。エージェントが*何を言うか*ではなく、*何をするか*をガバナンス — 決定論的ポリシー適用、ゼロトラストID、実行サンドボックス、SRE — **Python · TypeScript · .NET · Rust · Go**

> **あらゆるスタックに対応** — AWS Bedrock、Google ADK、Azure AI、LangChain、CrewAI、AutoGen、OpenAI Agents、LlamaIndex など。`pip install` のみでベンダーロックインなし。

## 📋 はじめに

### 📦 インストール

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

**Rust** (フル SDK)
```bash
cargo add agentmesh
```

**Rust** (スタンドアロン MCP サーフェス)
```bash
cargo add agentmesh-mcp
```

<details>
<summary>個別の Python パッケージをインストール</summary>

```bash
pip install agent-os-kernel        # ポリシーエンジン
pip install agentmesh-platform     # トラストメッシュ
pip install agentmesh-runtime       # ランタイムスーパーバイザー
pip install agent-sre              # SRE ツールキット
pip install agent-governance-toolkit    # コンプライアンスとアテステーション
pip install agentmesh-marketplace      # プラグインマーケットプレイス
pip install agentmesh-lightning        # 強化学習トレーニングガバナンス
```
</details>

### 📚 ドキュメント

- **[クイックスタート](../../QUICKSTART.md)** — ゼロからガバナンス付きエージェントを10分で構築（Python · TypeScript · .NET · Rust · Go）
- **[TypeScript SDK](../../packages/agent-mesh/sdks/typescript/README.md)** — ID、トラスト、ポリシー、監査機能を備えた npm パッケージ
- **[.NET SDK](../../packages/agent-governance-dotnet/README.md)** — 完全な OWASP カバレッジを備えた NuGet パッケージ
- **[Rust SDK](../../packages/agent-mesh/sdks/rust/agentmesh/README.md)** — ポリシー、トラスト、監査、ID、MCP ガバナンスプリミティブを備えた crates.io クレート
- **[Rust MCP SDK](../../packages/agent-mesh/sdks/rust/agentmesh-mcp/README.md)** — MCP ガバナンスおよびセキュリティプリミティブのスタンドアロン crates.io クレート
- **[Go SDK](../../packages/agent-mesh/sdks/go/README.md)** — ポリシー、トラスト、監査、ID 機能を備えた Go モジュール
- **[チュートリアル](../../docs/tutorials/)** — ポリシー、ID、統合、コンプライアンス、SRE、サンドボックスのステップバイステップガイド
- **[Azure デプロイ](../../docs/deployment/README.md)** — AKS、Azure AI Foundry、Container Apps、OpenClaw サイドカー
- **[NVIDIA OpenShell 統合](../../docs/integrations/openshell.md)** — サンドボックス分離とガバナンスインテリジェンスの統合
- **[OWASP コンプライアンス](../../docs/OWASP-COMPLIANCE.md)** — ASI-01 から ASI-10 の完全マッピング
- **[脅威モデル](../../docs/THREAT_MODEL.md)** — 信頼境界、攻撃面、STRIDE 分析
- **[アーキテクチャ](../../docs/ARCHITECTURE.md)** — システム設計、セキュリティモデル、トラストスコアリング
- **[アーキテクチャ決定記録](../../docs/adr/README.md)** — ID、ランタイム、ポリシーに関する主要な ADR ログ
- **[NIST RFI マッピング](../../docs/compliance/nist-rfi-2026-00206.md)** — NIST AI Agent セキュリティ RFI（2026-00206）へのマッピング

ご質問がありましたら、[GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues) を作成するか、[コミュニティページ](../../COMMUNITY.md) をご覧ください。

### ✨ **ハイライト**

- **決定論的ポリシー適用**: すべてのエージェントアクションが実行*前*にポリシーに基づいて評価され、サブミリ秒のレイテンシ（<0.1 ms）で処理
  - [ポリシーエンジン](../../packages/agent-os/) | [ベンチマーク](../../BENCHMARKS.md)
- **ゼロトラストエージェントID**: Ed25519 暗号資格情報、SPIFFE/SVID サポート、0〜1000 スケールのトラストスコアリング
  - [AgentMesh](../../packages/agent-mesh/) | [トラストスコアリング](../../packages/agent-mesh/)
- **実行サンドボックス**: 4 階層の特権リング、Saga オーケストレーション、終了制御、キルスイッチ
  - [Agent Runtime](../../packages/agent-runtime/) | [Agent Hypervisor](../../packages/agent-hypervisor/)
- **エージェント SRE**: SLO、エラーバジェット、リプレイデバッグ、カオスエンジニアリング、サーキットブレーカー、プログレッシブデリバリー
  - [Agent SRE](../../packages/agent-sre/) | [オブザーバビリティ統合](../../packages/agent-hypervisor/src/hypervisor/observability/)
- **MCP セキュリティスキャナー**: MCP ツール定義におけるツールポイズニング、タイポスクワッティング、隠し命令、ラグプル攻撃を検出
  - [MCP スキャナー](../../packages/agent-os/src/agentos/mcp_security.py) | [CLI](../../packages/agent-os/src/agentos/cli/mcp_scan.py)
- **トラストレポート CLI**: `agentmesh trust report` — トラストスコア、タスクの成功/失敗、エージェントアクティビティを可視化
  - [トラスト CLI](../../packages/agent-mesh/src/agentmesh/cli/trust_cli.py)
- **シークレットスキャンとファジング**: Gitleaks ワークフロー、ポリシー・インジェクション・サンドボックス・トラスト・MCP をカバーする7つのファズターゲット
  - [セキュリティワークフロー](../../.github/workflows/)
- **12 以上のフレームワーク統合**: Microsoft Agent Framework、LangChain、CrewAI、AutoGen、Dify、LlamaIndex、OpenAI Agents、Google ADK など
  - [フレームワーククイックスタート](../../examples/quickstart/) | [統合提案](../../docs/proposals/)
- **完全な OWASP カバレッジ**: Agentic Top 10 リスクの 10/10 を対応済み、各 ASI カテゴリに専用のコントロールを提供
  - [OWASP コンプライアンス](../../docs/OWASP-COMPLIANCE.md) | [競合比較](../../docs/COMPARISON.md)
- **CI/CD 向け GitHub Actions**: PR ワークフローのための自動セキュリティスキャンとガバナンスアテステーション
  - [セキュリティスキャン Action](../../action/security-scan/) | [ガバナンスアテステーション Action](../../action/governance-attestation/)

### 💬 **フィードバックをお待ちしています！**

- バグを発見した場合は、[GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues) を作成してください。

## クイックスタート

### ポリシーの適用 — Python

```python
from agent_os import PolicyEngine, CapabilityModel

# このエージェントに許可される操作を定義
capabilities = CapabilityModel(
    allowed_tools=["web_search", "file_read"],
    denied_tools=["file_write", "shell_exec"],
    max_tokens_per_call=4096
)

# すべてのアクション前にポリシーを適用
engine = PolicyEngine(capabilities=capabilities)
decision = engine.evaluate(agent_id="researcher-1", action="tool_call", tool="web_search")

if decision.allowed:
    # ツール呼び出しを続行
    ...
```

### ポリシーの適用 — TypeScript

```typescript
import { PolicyEngine } from "@microsoft/agentmesh-sdk";

const engine = new PolicyEngine([
  { action: "web_search", effect: "allow" },
  { action: "shell_exec", effect: "deny" },
]);

const decision = engine.evaluate("web_search"); // "allow"
```

### ポリシーの適用 — .NET

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

if (result.Allowed) { /* 続行 */ }
```

### ポリシーの適用 — Rust

```rust
use agentmesh::{AgentMeshClient, ClientOptions};

let client = AgentMeshClient::new("my-agent").unwrap();
let result = client.execute_with_governance("data.read", None);
assert!(result.allowed);
```

### ポリシーの適用 — Go

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

### ガバナンスデモの実行

```bash
# フルガバナンスデモ（ポリシー適用、監査、トラスト、コスト、信頼性）
python demo/maf_governance_demo.py

# 敵対的攻撃シナリオを含めて実行
python demo/maf_governance_demo.py --include-attacks
```

## その他のサンプルと例

- **[フレームワーククイックスタート](../../examples/quickstart/)** — LangChain、CrewAI、AutoGen、OpenAI Agents、Google ADK 向けの単一ファイルガバナンス付きエージェント
- **[チュートリアル 1: Policy Engine](../../docs/tutorials/01-policy-engine.md)** — ガバナンスポリシーの定義と適用
- **[チュートリアル 2: Trust & Identity](../../docs/tutorials/02-trust-and-identity.md)** — ゼロトラストエージェント資格情報
- **[チュートリアル 3: Framework Integrations](../../docs/tutorials/03-framework-integrations.md)** — 任意のフレームワークにガバナンスを追加
- **[チュートリアル 4: Audit & Compliance](../../docs/tutorials/04-audit-and-compliance.md)** — OWASP コンプライアンスとアテステーション
- **[チュートリアル 5: Agent Reliability](../../docs/tutorials/05-agent-reliability.md)** — SLO、エラーバジェット、カオステスト
- **[チュートリアル 6: Execution Sandboxing](../../docs/tutorials/06-execution-sandboxing.md)** — 特権リングと終了制御

## OPA/Rego & Cedar ポリシーサポート

既存のインフラストラクチャポリシーをエージェントガバナンスに適用 — 新しいポリシー DSL は不要です。

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

バックエンドごとに3つの評価モード: **組み込みエンジン**（cedarpy/opa CLI）、**リモートサーバー**、または**ビルトインフォールバック**（外部依存関係ゼロ）。

## SDK とパッケージ

### マルチ言語 SDK

| 言語 | パッケージ | インストール |
|----------|---------|---------|
| **Python** | [`agent-governance-toolkit[full]`](https://pypi.org/project/agent-governance-toolkit/) | `pip install agent-governance-toolkit[full]` |
| **TypeScript** | [`@microsoft/agentmesh-sdk`](../../packages/agent-mesh/sdks/typescript/) | `npm install @microsoft/agentmesh-sdk` |
| **.NET** | [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) | `dotnet add package Microsoft.AgentGovernance` |
| **Rust** | [`agentmesh`](https://crates.io/crates/agentmesh) | `cargo add agentmesh` |
| **Rust MCP** | [`agentmesh-mcp`](https://crates.io/crates/agentmesh-mcp) | `cargo add agentmesh-mcp` |
| **Go** | [`agentmesh`](../../packages/agent-mesh/sdks/go/) | `go get github.com/microsoft/agent-governance-toolkit/sdks/go` |

### Python パッケージ (PyPI)

| パッケージ | PyPI | 説明 |
|---------|------|-------------|
| **Agent OS** | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | ポリシーエンジン — 決定論的アクション評価、ケイパビリティモデル、監査ログ、アクションインターセプション、MCP ゲートウェイ |
| **AgentMesh** | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | エージェント間トラスト — Ed25519 ID、SPIFFE/SVID 資格情報、トラストスコアリング、A2A/MCP/IATP プロトコルブリッジ |
| **Agent Runtime** | [`agentmesh-runtime`](../../packages/agent-runtime/) | 実行スーパーバイザー — 4 階層特権リング、Saga オーケストレーション、終了制御、連帯責任、追記専用監査ログ |
| **Agent SRE** | [`agent-sre`](https://pypi.org/project/agent-sre/) | 信頼性エンジニアリング — SLO、エラーバジェット、リプレイデバッグ、カオスエンジニアリング、プログレッシブデリバリー |
| **Agent Compliance** | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | ランタイムポリシー適用 — OWASP ASI 2026 コントロール、ガバナンスアテステーション、完全性検証 |
| **Agent Marketplace** | [`agentmesh-marketplace`](../../packages/agent-marketplace/) | プラグインライフサイクル — プラグインの検出、インストール、検証、署名 |
| **Agent Lightning** | [`agentmesh-lightning`](../../packages/agent-lightning/) | 強化学習トレーニングガバナンス — ガバナンス付きランナー、ポリシー報酬 |

## フレームワーク統合

**20 以上のエージェントフレームワーク**に対応:

| フレームワーク | Stars | 統合方式 |
|-----------|-------|-------------|
| [**Microsoft Agent Framework**](https://github.com/microsoft/agent-framework) | 8K+ ⭐ | **ネイティブミドルウェア** |
| [**Semantic Kernel**](https://github.com/microsoft/semantic-kernel) | 27K+ ⭐ | **ネイティブ（.NET + Python）** |
| [Dify](https://github.com/langgenius/dify) | 133K+ ⭐ | プラグイン |
| [Microsoft AutoGen](https://github.com/microsoft/autogen) | 55K+ ⭐ | アダプター |
| [LlamaIndex](https://github.com/run-llama/llama_index) | 47K+ ⭐ | ミドルウェア |
| [CrewAI](https://github.com/crewAIInc/crewAI) | 46K+ ⭐ | アダプター |
| [LangGraph](https://github.com/langchain-ai/langgraph) | 27K+ ⭐ | アダプター |
| [Haystack](https://github.com/deepset-ai/haystack) | 24K+ ⭐ | パイプライン |
| [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) | 20K+ ⭐ | ミドルウェア |
| [Google ADK](https://github.com/google/adk-python) | 18K+ ⭐ | アダプター |
| [Azure AI Foundry](https://learn.microsoft.com/azure/ai-studio/) | — | デプロイガイド |

## OWASP Agentic Top 10 カバレッジ

| リスク | ID | ステータス |
|------|----|--------|
| エージェント目標ハイジャック | ASI-01 | ✅ ポリシーエンジンが未承認の目標変更をブロック |
| 過剰なケイパビリティ | ASI-02 | ✅ ケイパビリティモデルが最小権限を適用 |
| ID と特権の悪用 | ASI-03 | ✅ Ed25519 証明書によるゼロトラスト ID |
| 制御されないコード実行 | ASI-04 | ✅ Agent Runtime 実行リング + サンドボックス |
| 安全でない出力処理 | ASI-05 | ✅ コンテンツポリシーがすべての出力を検証 |
| メモリポイズニング | ASI-06 | ✅ 完全性チェック付きエピソディックメモリ |
| 安全でないエージェント間通信 | ASI-07 | ✅ AgentMesh 暗号化チャネル + トラストゲート |
| カスケード障害 | ASI-08 | ✅ サーキットブレーカー + SLO 適用 |
| 人間-エージェント間の信頼不足 | ASI-09 | ✅ 完全な監査証跡 + フライトレコーダー |
| 不正エージェント | ASI-10 | ✅ キルスイッチ + リング分離 + 行動異常検知 |

実装の詳細とテストエビデンスを含む完全なマッピング: **[OWASP-COMPLIANCE.md](../../docs/OWASP-COMPLIANCE.md)**

### 規制への適合

| 規制 | 期限 | AGT カバレッジ |
|------------|----------|-------------|
| EU AI 法 — 高リスク AI（附属書 III） | 2026年8月2日 | 監査証跡（第12条）、リスク管理（第9条）、人間による監視（第14条） |
| Colorado AI 法（SB 24-205） | 2026年6月30日 | リスク評価、人間による監視メカニズム、消費者への開示 |
| EU AI 法 — GPAI 義務 | 施行中 | 透明性、著作権ポリシー、システミックリスク評価 |

AGT は**ランタイムガバナンス** — エージェントが実行を許可される操作 — を提供します。**データガバナンス**および規制当局向けのエビデンスエクスポートについては、補完レイヤーとして [Microsoft Purview DSPM for AI](https://learn.microsoft.com/purview/ai-microsoft-purview) をご参照ください。

## パフォーマンス

ガバナンスのオーバーヘッドは**アクションあたり 0.1 ms 未満** — LLM API 呼び出しの約 10,000 倍高速です。

| メトリクス | レイテンシ (p50) | スループット |
|---|---|---|
| ポリシー評価（ルール1件） | 0.012 ms | 72K ops/sec |
| ポリシー評価（ルール100件） | 0.029 ms | 31K ops/sec |
| カーネル適用 | 0.091 ms | 9.3K ops/sec |
| アダプターオーバーヘッド | 0.004–0.006 ms | 130K–230K ops/sec |
| 並行スループット（50エージェント） | — | 35,481 ops/sec |

完全な方法論とアダプターごとの詳細: **[BENCHMARKS.md](../../BENCHMARKS.md)**

## セキュリティモデルと制限事項

このツールキットは**アプリケーションレベル（Python ミドルウェア）のガバナンス**を提供し、OS カーネルレベルの分離ではありません。ポリシーエンジンとガバナンス対象のエージェントは**同一の Python プロセス**内で動作します。これは、すべての Python ベースのエージェントフレームワーク（LangChain、CrewAI、AutoGen など）と同じ信頼境界です。

| レイヤー | 提供する機能 | 提供しない機能 |
|-------|-----------------|------------------------|
| ポリシーエンジン | 決定論的アクションインターセプション、拒否リスト適用 | ハードウェアレベルのメモリ分離 |
| ID（IATP） | Ed25519 暗号エージェント資格情報、トラストスコアリング | OS レベルのプロセス分離 |
| 実行リング | リソース制限付きの論理的特権階層 | CPU リングレベルの適用 |
| ブートストラップ完全性 | 起動時のガバナンスモジュールに対する SHA-256 改ざん検出 | ハードウェア信頼のルート（TPM/Secure Boot） |

**本番環境での推奨事項:**
- 各エージェントを**個別のコンテナ**で実行し、OS レベルの分離を実現
- すべてのセキュリティポリシールールは**設定可能なサンプル構成**として提供 — お使いの環境に合わせてレビューおよびカスタマイズしてください（`examples/policies/` 参照）
- 組み込みのルールセットを網羅的と見なすべきではありません
- 詳細は [Architecture — Security Model & Boundaries](../../docs/ARCHITECTURE.md) を参照

### セキュリティツール

| ツール | カバレッジ |
|------|----------|
| CodeQL | Python + TypeScript SAST |
| Gitleaks | PR/push/週次でのシークレットスキャン |
| ClusterFuzzLite | 7つのファズターゲット（ポリシー、インジェクション、MCP、サンドボックス、トラスト） |
| Dependabot | 13のエコシステム（pip、npm、nuget、cargo、gomod、docker、actions） |
| OpenSSF Scorecard | 週次スコアリング + SARIF アップロード |
| SBOM | SPDX + CycloneDX 生成とアテステーション |
| Dependency Review | PR 時の CVE およびライセンスチェック |

## コントリビューターリソース

- [コントリビューションガイド](../../CONTRIBUTING.md)
- [コミュニティ](../../COMMUNITY.md)
- [セキュリティポリシー](../../SECURITY.md)
- [アーキテクチャ](../../docs/ARCHITECTURE.md)
- [変更履歴](../../CHANGELOG.md)
- [サポート](../../SUPPORT.md)

## 重要事項

Agent Governance Toolkit を使用してサードパーティのエージェントフレームワークやサービスと連携するアプリケーションを構築する場合、自己の責任において行ってください。サードパーティサービスと共有されるすべてのデータを確認し、データの保持および保管場所に関するサードパーティの慣行を把握することを推奨します。データが組織のコンプライアンスおよび地理的境界の外に流出するかどうか、およびそれに関連する影響を管理する責任はお客様にあります。

## ライセンス

このプロジェクトは [MIT License](../../LICENSE) に基づいてライセンスされています。

## 商標

このプロジェクトには、プロジェクト、製品、またはサービスの商標やロゴが含まれている場合があります。Microsoft の商標やロゴの使用は、[Microsoft の商標およびブランドガイドライン](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general)に従い、承認を受ける必要があります。このプロジェクトの改変版における Microsoft の商標やロゴの使用は、混乱を招いたり Microsoft のスポンサーシップを示唆したりしてはなりません。サードパーティの商標やロゴの使用は、それぞれのサードパーティのポリシーに従います。
