🌍 [English](/README.md) | [日本語](./README.ja.md) | [简体中文](./README.zh-CN.md) | [한국어](./README.ko.md)

![Agent Governance Toolkit](../../docs/assets/readme-banner.svg)

# Agent Governance Toolkit

### 에이전트를 프로덕션에 안심하고 배포하세요

<p align="center">
  <a href="https://microsoft.github.io/agent-governance-toolkit">
    <img src="https://img.shields.io/badge/%F0%9F%93%96_전체_문서-microsoft.github.io%2Fagent--governance--toolkit-0078D4?style=for-the-badge&logoColor=white" alt="전체 문서" height="40">
  </a>
</p>

<p align="center">
  <strong>
    🚀 <a href="#빠른-시작">빠른 시작</a> ·
    📋 <a href="#명세-specifications">명세</a> ·
    📦 <a href="https://pypi.org/project/agent-governance-toolkit/">PyPI</a> ·
    📝 <a href="../../CHANGELOG.md">변경 이력</a>
  </strong>
</p>

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![Discord](https://dcbadge.limes.pink/api/server/7aVPCcVh?style=flat)](https://discord.gg/7aVPCcVh)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/agent-governance-toolkit?label=PyPI)](https://pypi.org/project/agent-governance-toolkit/)
[![npm](https://img.shields.io/npm/v/%40microsoft/agent-governance-sdk?label=npm)](https://www.npmjs.com/package/@microsoft/agent-governance-sdk)
[![NuGet](https://img.shields.io/nuget/v/Microsoft.AgentGovernance?label=NuGet)](https://www.nuget.org/packages/Microsoft.AgentGovernance)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12085/badge)](https://www.bestpractices.dev/projects/12085)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](../../docs/compliance/owasp-agentic-top10-architecture.md)

> [!IMPORTANT]
> **공개 프리뷰(Public Preview)** — 프로덕션 품질의 Microsoft 서명 릴리즈입니다. GA 이전에 주요 변경이 발생할 수 있습니다.

자율형 AI 에이전트를 위한 정책 적용, 신원증명, 샌드박싱, SRE. `pip install` 하나로 어떤 프레임워크에서도 사용 가능합니다.

---

## 문제 상황

여러분의 AI 에이전트는 도구를 호출하고, 웹을 탐색하며, 데이터베이스를 조회하고, 다른 에이전트에게 작업을 위임합니다. 배포 후에는 자율적으로 의사결정을 내립니다. 세 가지 질문에 답할 수 있어야 합니다:

**1. 이 동작이 허용되는가?** `send_email`과 `query_database`에 접근할 수 있는 에이전트가 `drop_table`을 실행하지 못하도록 해야 합니다. OAuth 스코프와 IAM 역할은 에이전트가 어떤 서비스에 접근할 수 있는지를 제어하지만, 연결된 후 무엇을 하는지는 제어하지 못합니다.

**2. 어떤 에이전트가 이 작업을 했는가?** 다중 에이전트 시스템에서 다섯 개의 에이전트가 하나의 API 키를 공유할 수 있습니다. 문제가 발생했을 때 "어떤 에이전트가 했다"는 대응은 사고 처리 방식이 될 수 없습니다.

**3. 무슨 일이 있었는지 증명할 수 있는가?** 감사자와 규제 기관은 모든 의사결정에 대한 변조 불가 기록이 필요합니다: 어떤 정책이 활성화되어 있었는지, 에이전트가 무엇을 요청했는지, 허용 또는 거부된 이유가 무엇인지.

프롬프트 수준의 안전성("규칙을 따르세요")은 통제 수단이 아닙니다. 확률론적 시스템에 대한 공손한 요청일 뿐입니다. [OWASP LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)는 이를 명시적으로 밝힙니다: *"프롬프트 인젝션을 완벽하게 방지하는 방법이 존재하는지 불분명하다."* 공개된 수치가 이를 뒷받침합니다. [Andriushchenko et al. (ICLR 2025)](https://arxiv.org/abs/2404.02151)는 logprob 접근과 suffix 최적화를 활용한 적응형 공격을 사용하여, [JailbreakBench](https://arxiv.org/abs/2404.01318) 벤치마크(Chao et al., NeurIPS 2024) 기준으로 GPT-4o, GPT-3.5, Claude 3, Llama-3에 대해 **공격 성공률 100%**를 보고했습니다. Microsoft의 [AI Red Teaming Agent](https://learn.microsoft.com/azure/ai-foundry/concepts/ai-red-teaming-agent)는 적대적 입력 하에서의 정책 위반 비율인 **공격 성공률(ASR, Attack Success Rate)**을 이 유형의 실패에 대한 표준 지표로 공식화합니다. [*100개 생성형 AI 제품 레드팀 테스트에서 얻은 교훈*](https://www.microsoft.com/en-us/security/blog/2025/01/13/3-takeaways-from-red-teaming-100-generative-ai-products/)은 이 점을 재확인합니다: *"완화 조치가 위험을 완전히 제거하지는 않는다"* 며 모델 레이어 방어는 본질적으로 확률론적이기 때문에 레드팀 테스트는 지속적인 프로세스여야 한다고 강조합니다.

AGT는 프롬프트 내부에서 이 싸움을 이기려 하지 않습니다. 모든 도구 호출, 메시지 전송, 위임 작업은 모델의 의도가 실행되기 전에 결정론적 애플리케이션 코드에서 **가로채어집니다**. AGT 커널이 거부한 동작은 "가능성이 낮은" 것이 아닙니다. **구조적으로 불가능합니다**. 이것이 에이전트에게 올바르게 행동하도록 요청하는 것과 잘못된 행동 자체를 불가능하게 만드는 것의 차이입니다.

---

## 빠른 시작

**사전 요구 사항:** Python 3.10+

```bash
pip install agent-governance-toolkit[full]
```

Claude Code의 경우, AGT를 플러그인 마켓플레이스에 추가하고 거버넌스 플러그인을 설치하세요:

```text
/plugin marketplace add microsoft/agent-governance-toolkit
/plugin install agt-governance@agent-governance-toolkit
```

두 줄로 어떤 도구 함수에도 거버넌스를 적용하세요:

```python
from agentmesh.governance import govern

safe_tool = govern(my_tool, policy="policy.yaml")   # 모든 호출 검사, 기록, 적용
```

이것으로 끝입니다. `safe_tool`은 모든 호출 시 YAML 정책을 평가하고, 의사결정을 기록하며, 동작이 차단되면 `GovernanceDenied`를 발생시킵니다.

```yaml
# policy.yaml
apiVersion: governance.toolkit/v1
name: production-policy
default_action: allow
rules:
  - name: block-destructive
    condition: "action.type in ['drop', 'delete', 'truncate']"
    action: deny
    description: "파괴적인 작업은 사람의 승인이 필요합니다"

  - name: require-approval-for-send
    condition: "action.type == 'send_email'"
    action: require_approval
    approvers: ["security-team"]
```

```python
>>> safe_tool(action="read", table="users")
{'table': 'users', 'rows': 42}

>>> safe_tool(action="drop", table="users")
GovernanceDenied: Action denied by policy rule 'block-destructive':
  파괴적인 작업은 사람의 승인이 필요합니다
```

또는 프로그래밍 방식 제어를 위해 전체 `PolicyEvaluator` API를 사용하세요:

<details>
<summary><b>PolicyEvaluator 예제</b></summary>

```python
from agent_os.policies import (
    PolicyEvaluator, PolicyDocument, PolicyRule,
    PolicyCondition, PolicyAction, PolicyOperator, PolicyDefaults
)

evaluator = PolicyEvaluator(policies=[PolicyDocument(
    name="my-policy", version="1.0",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[PolicyRule(
        name="block-dangerous-tools",
        condition=PolicyCondition(
            field="tool_name",
            operator=PolicyOperator.IN,
            value=["execute_code", "delete_file"]
        ),
        action=PolicyAction.DENY, priority=100,
    )],
)])

result = evaluator.evaluate({"tool_name": "web_search"})    # 허용됩니다
result = evaluator.evaluate({"tool_name": "delete_file"})   # 차단됩니다
```

</details>

<details>
<summary><b>TypeScript / .NET / Rust / Go 예제</b></summary>

**TypeScript**
```typescript
import { PolicyEngine } from "@microsoft/agent-governance-sdk";

const engine = new PolicyEngine([
  { action: "web_search", effect: "allow" },
  { action: "shell_exec", effect: "deny" },
]);
engine.evaluate("web_search"); // "허용"
engine.evaluate("shell_exec"); // "차단"
```

**.NET**
```csharp
using AgentGovernance;
using AgentGovernance.Extensions.ModelContextProtocol;
using AgentGovernance.Policy;

var kernel = new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = new() { "policies/default.yaml" },
});
var result = kernel.EvaluateToolCall("did:mesh:agent-1", "web_search",
    new() { ["query"] = "latest AI news" });

// MCP 서버 연동
builder.Services.AddMcpServer()
    .WithGovernance(options => options.PolicyPaths.Add("policies/mcp.yaml"));
```

**Rust**
```rust
use agent_governance::{AgentMeshClient, ClientOptions};

let client = AgentMeshClient::new("my-agent").unwrap();
let result = client.execute_with_governance("data.read", None);
assert!(result.allowed);
```

**Go**
```go
import agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang"

client, _ := agentmesh.NewClient("my-agent",
    agentmesh.WithPolicyRules([]agentmesh.PolicyRule{
        {Action: "data.read", Effect: agentmesh.Allow},
        {Action: "*", Effect: agentmesh.Deny},
    }),
)
result := client.ExecuteWithGovernance("data.read", nil)
```

</details>

CLI 도구:

```bash
agt doctor                                        # 설치 상태 확인
agt verify                                        # OWASP 컴플라이언스 확인
agt verify --evidence ./agt-evidence.json --strict # 증거 부족 시 CI 실패 처리
agt red-team scan ./prompts/ --min-grade B         # 프롬프트 인젝션 감사
agt lint-policy policies/                          # 정책 파일 검증
```

전체 과정: [quickstart.md](../../docs/i18n/quickstart.ko.md) — 5분 만에 거버넌스가 적용된 에이전트 완성.
🌍 다음 언어로도 제공됩니다: [日本語](./quickstart.ja.md) | [简体中文](./quickstart.zh-CN.md) | [English](../../docs/quickstart.md)

---

## 동작 원리

```
Agent ──► Policy Engine ──► Identity ──► Audit Log
            (YAML/OPA/Cedar)  (SPIFFE/DID/mTLS)  (변조 불가)
                 │                                      │
                 ├── Allowed ──► 도구 실행               │
                 └── Denied  ──► GovernanceDenied        │
                                                        ▼
                                                 Decision Record
```

모든 레이어는 선택 사항입니다. `govern()`으로 시작하고 리스크 프로파일에 따라 레이어를 추가하세요. 대부분의 팀은 정책 적용과 감사 로깅만으로도 충분합니다.

---

## 패키지

| 패키지 | 설명 |
|---------|-------------|
| [**Agent OS**](../../agent-governance-python/agent-os/) | 정책 엔진, 에이전트 라이프사이클, 거버넌스 게이트 |
| [**Agent Mesh**](../../agent-governance-python/agent-mesh/) | 에이전트 검색, 라우팅, 신뢰 메시 |
| [**Agent Runtime**](../../agent-governance-python/agent-runtime/) | 4단계 권한 격리 링을 통한 실행 샌드박싱 |
| [**Agent SRE**](../../agent-governance-python/agent-sre/) | 킬 스위치, SLO 모니터링, 카오스 테스트 |
| [**Agent Compliance**](../../agent-governance-python/agent-compliance/) | OWASP 검증, 정책 린팅, 무결성 체크 |
| [**Agent Marketplace**](../../agent-governance-python/agent-marketplace/) | 플러그인 거버넌스 및 신뢰 점수화 |
| [**Agent Lightning**](../../agent-governance-python/agent-lightning/) | 위반 패널티가 적용된 강화학습(RL) 훈련 거버넌스 |
| [**Agent Hypervisor**](../../agent-governance-python/agent-hypervisor/) | 실행 감사, 델타 엔진, 커밋먼트 앵커링 |

### 추가 기능

| 기능 | 설명 |
|---|---|
| **MCP Security Gateway** | 도구 오염(tool poisoning) 탐지, 드리프트 모니터링, 유사 도구명 공격(typosquatting), 숨겨진 지시문 스캔 ([명세](../../docs/specs/MCP-SECURITY-GATEWAY-1.0.md)) |
| **Shadow AI Discovery** | 프로세스, 환경 설정, 리포지터리에서 미등록 에이전트 감지 ([Discovery](../../agent-governance-python/agent-discovery/)) |
| **Governance Dashboard** | 상태, 신뢰, 컴플라이언스에 대한 실시간 에이전트 현황 ([Dashboard](../../examples/demos/governance-dashboard/)) |
| **PromptDefense Evaluator** | 12-vector 프롬프트 인젝션 감사 ([Evaluator](../../agent-governance-python/agent-compliance/src/agent_compliance/prompt_defense.py)) |
| **Contributor Reputation** | 사회공학 공격에 대한 PR/이슈 등록자 검증. 재사용 가능한 GitHub Action ([Action](../../.github/actions/contributor-check/)) |

---

## 설치 방법

| 언어 | 패키지 | 명령어 |
|----------|---------|---------|
| **Python** | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | `pip install agent-governance-toolkit[full]` |
| **TypeScript** | [`@microsoft/agent-governance-sdk`](../../agent-governance-typescript/) | `npm install @microsoft/agent-governance-sdk` |
| **Copilot CLI** | [`@microsoft/agent-governance-copilot-cli`](../../agent-governance-copilot-cli/) | `npx @microsoft/agent-governance-copilot-cli install` |
| **Claude Code** | [`@microsoft/agent-governance-claude-code`](../../agent-governance-claude-code/) | `claude --plugin-dir ./agent-governance-claude-code` |
| **OpenCode** | [`@microsoft/agent-governance-opencode`](../../agent-governance-opencode/) | `npm install @microsoft/agent-governance-opencode` |
| **.NET** | [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) | `dotnet add package Microsoft.AgentGovernance` |
| **.NET MCP** | `Microsoft.AgentGovernance.Extensions.ModelContextProtocol` | `dotnet add package Microsoft.AgentGovernance.Extensions.ModelContextProtocol` |
| **Rust** | [`agent-governance`](https://crates.io/crates/agent-governance) | `cargo add agent-governance` |
| **Go** | [`agent-governance-toolkit`](../../agent-governance-golang/) | `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang` |

5개 언어 SDK 모두 핵심 거버넌스(정책, 신원, 신뢰, 감사)를 구현합니다. Python은 풀 스택을 지원합니다. Copilot CLI와 Claude Code는 TypeScript SDK 위에 구축된 1st-party 개발자 인터페이스입니다.
**[언어 패키지 매트릭스](../../docs/PACKAGE-FEATURE-MATRIX.md)**에서 언어별 상세 지원 현황을 확인하세요.

<details>
<summary><b>Python 배포판 (v4.0.0 — 통합)</b></summary>

v4.0.0부터 45개 패키지가 5개 최상위 배포판으로 통합되었습니다:

| 배포판 | PyPI | 포함 내용 |
|--------------|------|-----------------|
| `agent-governance-toolkit-core` | [`agent-governance-toolkit-core`](https://pypi.org/project/agent-governance-toolkit-core/) | 정책 엔진, 역량 모델, 감사, MCP 게이트웨이, 제로 트러스트 신원증명, 신뢰 점수화, A2A/MCP/IATP 브릿지 |
| `agent-governance-toolkit-runtime` | [`agent-governance-toolkit-runtime`](https://pypi.org/project/agent-governance-toolkit-runtime/) | 권한 격리 링, 사가 오케스트레이션, 종료 제어, 실행 계획 검증 |
| `agent-governance-toolkit-sre` | [`agent-governance-toolkit-sre`](https://pypi.org/project/agent-governance-toolkit-sre/) | SLO, 에러 버짓, 카오스 공학, 서킷 브레이커 |
| `agent-governance-toolkit-cli` | [`agent-governance-toolkit-cli`](https://pypi.org/project/agent-governance-toolkit-cli/) | `agt` CLI, OWASP 검증, 무결성 체크, 정책 린팅 |
| `agent-governance-toolkit[full]` | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | 위 모든 패키지를 설치하는 메타 패키지 |

이전 패키지 이름(`agent-os-kernel`, `agentmesh-platform`, `agentmesh-runtime`, `agent-sre`, `agent-discovery`, `agent-hypervisor`, `agentmesh-marketplace`, `agentmesh-lightning`)은 통합된 배포판으로 리다이렉트되는 스텁 패키지로 계속 설치 가능합니다.

</details>

### 사전 요구 사항

- **Python**: 3.10+
- **Node.js**: 18+ / npm 9+ (TypeScript SDK)
- **.NET**: 8+
- **Go**: 1.25+
- **Rust**: 1.70+
- **선택 사항**: Azure 연동 기능을 위한 `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`

---

## 프레임워크 지원

| 프레임워크 | 연동 방식 |
|-----------|-------------|
| [**Microsoft Agent Framework**](https://github.com/microsoft/agent-framework) | 네이티브 미들웨어 |
| [**Semantic Kernel**](https://github.com/microsoft/semantic-kernel) | 네이티브 (.NET + Python) |
| [AutoGen](https://github.com/microsoft/autogen) | 어댑터 |
| [LangGraph](https://github.com/langchain-ai/langgraph) / [LangChain](https://github.com/langchain-ai/langchain) | 어댑터 |
| [CrewAI](https://github.com/crewAIInc/crewAI) | 어댑터 |
| [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) | 미들웨어 |
| Claude Code | 거버넌스 플러그인 패키지 |
| [Google ADK](https://github.com/google/adk-python) | 어댑터 |
| [LlamaIndex](https://github.com/run-llama/llama_index) | 미들웨어 |
| [Haystack](https://github.com/deepset-ai/haystack) | 파이프라인 |
| [Mastra](https://github.com/mastra-ai/mastra) | 어댑터 |
| [Dify](https://github.com/langgenius/dify) | 플러그인 |
| [Azure AI Foundry](https://learn.microsoft.com/azure/ai-studio/) | 배포 가이드 |
| GitHub Copilot CLI | 거버넌스 인스톨러 |

전체 목록: [프레임워크 연동](../../agent-governance-python/agentmesh-integrations/) · [Quickstart 예제](../../examples/quickstart/)

---

## 예제

| 예제 | 프레임워크 | 시연 내용 |
|---------|-----------|----------------------|
| [openai-agents-governed](../../examples/openai-agents-governed) | OpenAI Agents SDK | 신뢰 티어를 통한 정책 게이트 도구 호출 |
| [crewai-governed](../../examples/crewai-governed) | CrewAI | 역할 기반 정책을 통한 다중 에이전트 거버넌스 |
| [smolagents-governed](../../examples/smolagents-governed) | HuggingFace smolagents | 경량 에이전트 거버넌스 |
| [maf-integration](../../examples/maf-integration) | MAF | Microsoft Agent Framework 연동 |
| [mcp-trust-verified-server](../../examples/mcp-trust-verified-server) | MCP | 신뢰 검증된 MCP 서버 구현 |
| [cedarling-governed](../../examples/cedarling-governed) | Cedar/Cedarling | Janssen Cedarling 정책 엔진 연동 |
| [governance-dashboard](../../examples/demos/governance-dashboard) | Streamlit | 실시간 에이전트 현황 대시보드 |

---

## 명세 (Specifications)

모든 주요 컴포넌트는 적합성 테스트가 포함된 공식 RFC 2119 명세를 가지고 있습니다. 이 명세들은 구현체가 MUST, SHOULD, MAY로 무엇을 해야 하는지 정의하는 동작 계약입니다.

| 명세 | 범위 | 테스트 수 |
|---|---|---|
| [Agent OS Policy Engine](../../docs/specs/AGENT-OS-POLICY-ENGINE-1.0.md) | 정책 평가, 규칙 병합, fail-closed 시맨틱 | 68 |
| [AgentMesh Identity and Trust](../../docs/specs/AGENTMESH-IDENTITY-TRUST-1.0.md) | 자격증명, 신뢰 점수화, 위임 체인 | 135 |
| [Agent Hypervisor Execution Control](../../docs/specs/AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md) | 권한 격리 링, 사가 오케스트레이션, 킬 스위치 | 80 |
| [AgentMesh Trust and Coordination](../../docs/specs/AGENTMESH-TRUST-COORDINATION-1.0.md) | 피어 신뢰 협상, 메시 전체 정책 | 62 |
| [Agent SRE Governance](../../docs/specs/AGENT-SRE-GOVERNANCE-1.0.md) | SLO, 에러 버짓, 카오스, 서킷 브레이커 | 111 |
| [MCP Security Gateway](../../docs/specs/MCP-SECURITY-GATEWAY-1.0.md) | 도구 오염, 드리프트 탐지, 숨겨진 지시문 | 127 |
| [Agent Lightning Fast-Path](../../docs/specs/AGENT-LIGHTNING-FAST-PATH-1.0.md) | 강화학습 훈련 거버넌스, 위반 패널티 | 100 |
| [Framework Adapter Contract](../../docs/specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md) | 10개 어댑터 연동, 인터셉터 체인 | 152 |
| [Audit and Compliance](../../docs/specs/AUDIT-COMPLIANCE-1.0.md) | Merkle 감사, 컴플라이언스 매핑, Decision BOM | 157 |
| [AgentMesh Wire Protocol](../../docs/specs/AGENTMESH-WIRE-1.0.md) | 메시지 형식, 라우팅, 직렬화 | -- |

**992개의 적합성 테스트**로 코드와 명세의 일치를 보장합니다. [25개 아키텍처 결정 기록](../../docs/adr/)이 그 이유를 문서화합니다.

---

## 표준 컴플라이언스

| 표준 | 커버리지 |
|----------|----------|
| [OWASP Agentic AI Top 10](../../docs/compliance/owasp-agentic-top10-architecture.md) | 결정론적 통제와 함께 모든 ASI 리스크 카테고리 매핑 |
| [NIST AI RMF 1.0](../../docs/compliance/nist-ai-rmf-alignment.md) | GOVERN, MAP, MEASURE, MANAGE 전체 정렬 |
| [EU AI Act](../../docs/compliance/) | 자동화된 증거를 통한 컴플라이언스 매핑 |
| [SOC 2](../../docs/compliance/soc2-mapping.md) | 감사 추적 내보내기를 통한 통제 매핑 |

---

## 보안 (Security)

AGT는 OS 커널 레벨이 아닌 애플리케이션 미들웨어 레이어에서 거버넌스를 적용합니다. 정책 엔진과 에이전트는 동일한 프로세스 경계를 공유합니다.

**운영 환경 권장 사항:** OS 레벨 격리를 위해 각 에이전트를 별도 컨테이너에서 실행하세요. [아키텍처: 보안 경계](../../docs/ARCHITECTURE.md)를 참고하세요.

| 도구 | 점검 범위 |
|------|----------|
| CodeQL | Python + TypeScript 정적 분석(SAST) |
| Gitleaks | PR/Push/주간 시크릿 스캐닝 |
| ClusterFuzzLite | 7개 퍼징 타겟 (정책, 인젝션, MCP, 샌드박스, 신뢰) |
| Dependabot | 13개 생태계 |
| OpenSSF Scorecard | 주간 점수 산출 + SARIF 업로드 |

정직한 설계 경계와 권장 계층 방어에 대해서는 [알려진 제약 사항](../../docs/LIMITATIONS.md)을 참고하세요.

---

## 문서 (Documentation)

| 카테고리 | 링크 |
|----------|-------|
| **시작하기** | [Quick Start](../../docs/i18n/quickstart.ko.md) · [Tutorials](../../docs/tutorials/) (60+) · [FAQ](../../docs/FAQ.md) |
| **아키텍처** | [시스템 설계](../../docs/ARCHITECTURE.md) · [위협 모델](../../docs/security/threat-model.md) · [ADR](../../docs/adr/) (25) |
| **명세** | [전체 명세](../../docs/specs/) (공식 명세 10개, 적합성 테스트 992개) |
| **API 레퍼런스** | [Agent OS](../../agent-governance-python/agent-os/README.md) · [AgentMesh](../../agent-governance-python/agent-mesh/README.md) · [Agent SRE](../../agent-governance-python/agent-sre/README.md) |
| **컴플라이언스** | [OWASP](../../docs/compliance/owasp-agentic-top10-architecture.md) · [EU AI Act](../../docs/compliance/) · [NIST AI RMF](../../docs/compliance/nist-ai-rmf-alignment.md) · [SOC 2](../../docs/compliance/soc2-mapping.md) |
| **배포** | [Azure](../../docs/deployment/README.md) · [AWS](../../docs/deployment/README.md) · [GCP](../../docs/deployment/README.md) · [Docker Compose](../../docs/deployment/README.md) |
| **확장** | [VS Code](../../agent-governance-typescript/agent-os-vscode/) · [프레임워크 연동](../../agent-governance-python/agentmesh-integrations/) |

---

## 기여하기 (Contributing)

[기여 가이드](../../CONTRIBUTING.md) · [커뮤니티](../../docs/COMMUNITY.md) · [Discord](https://discord.gg/7aVPCcVh) · [보안 정책](../../SECURITY.md) · [변경 이력](../../CHANGELOG.md)

**AGT를 사용 중이신가요?** [ADOPTERS.md](../../docs/ADOPTERS.md)에 귀하의 조직을 추가해 주세요.

## 거버넌스 (Governance)

| 문서 | 목적 |
|----------|---------|
| [GOVERNANCE.md](../../GOVERNANCE.md) | 의사결정, 역할, 기여자 사다리 |
| [CHARTER.md](../../docs/CHARTER.md) | 기술 헌장 (LF Projects 형식) |
| [MAINTAINERS.md](../../MAINTAINERS.md) | 메인테이너 및 조직 |
| [SECURITY.md](../../SECURITY.md) | 취약점 신고 및 대응 SLA |
| [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) | Microsoft 오픈소스 행동 강령 |
| [ANTITRUST.md](../../ANTITRUST.md) | 참여자를 위한 경쟁법 가이드라인 |
| [TRADEMARKS.md](../../TRADEMARKS.md) | 상표 사용 정책 |

## 중요 고지 사항

제3자 에이전트 프레임워크 또는 서비스와 연동되는 애플리케이션을 구축하기 위해 Agent Governance Toolkit을 사용하는 경우, 그에 따른 책임은 사용자 본인에게 있습니다. 제3자 서비스와 공유되는 모든 데이터를 검토하고, 해당 서비스의 데이터 보유 및 보관 위치에 대한 정책을 숙지할 것을 권장합니다.

## 공식 소스

Agent Governance Toolkit의 공식 소스는 다음과 같습니다:

| 리소스 | 위치 |
|----------|----------|
| **소스 코드** | [github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) |
| **문서** | [microsoft.github.io/agent-governance-toolkit](https://microsoft.github.io/agent-governance-toolkit/) |
| **Python 패키지** | [pypi.org/user/agentgovtoolkit](https://pypi.org/user/agentgovtoolkit/) |
| **npm 패키지** | [npmjs.com](https://www.npmjs.com/)의 `@microsoft/agent-governance-sdk` |
| **NuGet 패키지** | [nuget.org](https://www.nuget.org/)의 `Microsoft.AgentGovernance.*` |
| **Rust 크레이트** | [crates.io](https://crates.io/)의 `agent-governance`, `agent-governance-mcp` |

프로젝트 팀은 공식임을 주장하는 제3자 웹사이트, 패키지, 또는 문서 사이트를 유지 관리하거나 보증하지 않습니다. Agent Governance Toolkit 이름을 사용하는 의심스러운 사이트나 패키지를 발견하면 [SECURITY.md](../../SECURITY.md)에 설명된 채널을 통해 신고해 주세요.

## 라이선스 (License)

이 프로젝트는 [MIT 라이선스](../../LICENSE)에 따라 라이선스가 부여됩니다.

## 상표 (Trademarks)

본 프로젝트에는 프로젝트, 제품 또는 서비스에 대한 상표 또는 로고가 포함될 수 있습니다. Microsoft 상표 또는 로고의 허용된 사용은 [Microsoft의 상표 및 브랜드 가이드라인](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general)을 준수해야 합니다. 본 프로젝트의 수정된 버전에서 Microsoft 상표 또는 로고를 사용할 때 혼란을 야기하거나 Microsoft의 후원을 암시해서는 안 됩니다. 제3자 상표 또는 로고의 사용은 해당 제3자의 정책을 따릅니다.
