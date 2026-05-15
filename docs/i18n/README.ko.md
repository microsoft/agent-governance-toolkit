> 이 문서는[README.md](/README.md) 파일의 한국어 번역본입니다. 아직 갱신되지 않은 최신 정보는 영문판을 확인해 주세요. 

🌍 [English](/README.md) | [日本語](./README.ja.md) | [简体中文](./README.zh-CN.md) | [한국어](./README.ko.md)

![Agent Governance Toolkit](../../docs/assets/readme-banner.svg)

# Agent Governance Toolkit

<p align="center">
  <strong>
    📖 <a href="https://microsoft.github.io/agent-governance-toolkit">문서 사이트</a> ·
    🚀 <a href="#설치-개요-1분30초밖에-걸리지-않아요">빠른 시작</a> ·
    📦 <a href="https://pypi.org/project/agent-governance-toolkit/">PyPI</a> ·
    📝 <a href="../../CHANGELOG.md">변경 이력</a>
  </strong>
</p>

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-microsoft.github.io%2Fagent--governance--toolkit-blue?logo=github)](https://microsoft.github.io/agent-governance-toolkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/agent-governance-toolkit)](https://pypi.org/project/agent-governance-toolkit/)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](docs/OWASP-COMPLIANCE.md)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/microsoft/agent-governance-toolkit)

> [!IMPORTANT]
> ** 공개 프리뷰(Public Preview) ** — 이 리포지터리의 코드는 Microsoft에 의하여 서명된 프로덕션 적용 수준의 릴리즈이지만 GA(일반공개) 이전 단계이기 때문에 상당한 변경이 발생할 여지가 있습니다. 툴킷에 대한 의견이 있다면 [GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues)를 등록해 주십시오.

> [!TIP]
> **v3.4.0 출시!** 기여자 평판 조회(Contribute reputation check)의 오탐지 개선, CI 린팅 픽스, README 파일이 정리되었습니다. [변경 이력 →](../../CHANGELOG.md)

**AI 에이전트의 런타임 거버넌스** -- 결정론적 정책 적용(deterministic policy enforcement), 제로 트러스트 신원증명(zero-trust identity), 실행단계 샌드박싱(execution sandboxing), 자율형 에이전트를 위한 SRE까지 **OWASP의 10대 에이전트 리스크 쟁점(10 OWASP Agentic risks)**을 **1만3천개** 이상의 테스트로 검증해 볼 수 있습니다.

**다양한 스택에서 작동합니다** — AWS Bedrock, Google ADK, Azure AI, LangChain, CrewAI, AutoGen, OpenAI Agents 및 20개 이상의 스택, 그리고 Python · TypeScript · .NET · Rust · Go 언어를 지원합니다.

---
## AGT는 무엇을 할 수 있나요?(그리고 할 수 없는 것은?)

**이 툴킷이 할 수 있는 일:** 이 툴킷은 에이전트 프레임워크와 그 에이전트들의 실제 행동의 중간에 위치하여 모든 tool 호출, 리소스 액세스, 에이전트간 메시지 등이 **실행되기 전에** 정책에 따라 평가합니다. 아울러 확률론적이 아니라 결정론적(Deterministic)으로 판단을 내립니다.

**이 툴킷이 못하는 일:** 이 툴킷은 프롬프트의 가드레일 혹은 컨텐츠 안전성 점검을 하지 않습니다. 이 툴킷은 에이전트의 **행동(action)**을 통제하는 것이지 LLM 입출력은 관여하지 않습니다. 모델 레벨의 안전성에 대해선 [Azure AI Content Safety](https://learn.microsoft.com/azure/ai-services/content-safety/) 문서를 참고해 주십시오. 
 
```
Agent Action ──► Policy Check ──► Allow / Deny ──► Audit Log    (< 0.1 ms)
```

**이 툴킷의 중요성:** 프롬프트 기반의 안정성 강제(예를 들어 "다음 규칙을 준수하도록 해(please follow the rules)")는 red-team 테스팅에서 [26.67%의 정책 위반률](../../docs/BENCHMARKS.md)을 보였습니다. 반면 이 툴킷의 결정론적 애플리케이션 레이어 정책 적용은 **0.00%**의 위반률을 보여줍니다.

---

## 설치 개요 (1분30초밖에 걸리지 않아요)

```bash
# 1. 설치 커맨드
pip install agent-governance-toolkit[full]

# 2. 잘 설치되었는지 확인합니다
agt doctor

# 3. OWASP 컴플라이언스 확인
agt verify

# 4. 가능한 경우 보안증거 파일이 정책을 충족하는지 점검합니다
agt verify --evidence ./agt-evidence.json

# 5. 증거 데이터가 부족하거나 위반이 있다면 CI(Continuous Integration) 실행을 실패처리합니다
agt verify --evidence ./agt-evidence.json --strict

# 6. 에이전트에 대한 Red-team 보안점검 수행
agt red-team scan ./prompts/ --min-grade B --strict
```

설치가 완료되면 정책이 적용되는지 확인해 보겠습니다.

```python
from agent_os.policies import PolicyEvaluator, PolicyDocument, PolicyRule, PolicyCondition, PolicyAction, PolicyOperator, PolicyDefaults

evaluator = PolicyEvaluator(policies=[PolicyDocument(
    name="my-policy", version="1.0",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[PolicyRule(
        name="block-dangerous-tools",
        condition=PolicyCondition(field="tool_name", operator=PolicyOperator.IN, value=["execute_code", "delete_file"]),
        action=PolicyAction.DENY, priority=100,
    )],
)])

result = evaluator.evaluate({"tool_name": "web_search"})    # ✅ 허용됩니다
result = evaluator.evaluate({"tool_name": "delete_file"})   # ❌ 결정론적으로 차단됩니다
```
<details>
<summary><b>TypeScript</b></summary>

```typescript
import { PolicyEngine } from "@microsoft/agent-governance-sdk";

const engine = new PolicyEngine([
  { action: "web_search", effect: "allow" },
  { action: "shell_exec", effect: "deny" },
]);
engine.evaluate("web_search"); // "허용"
engine.evaluate("shell_exec"); // "차단"
```

</details>

<details>
<summary><b>.NET</b></summary>

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
// result.Allowed == true

builder.Services
    .AddMcpServer()
    .WithGovernance(options => options.PolicyPaths.Add("policies/mcp.yaml"));
```

</details>

<details>
<summary><b>Rust</b></summary>

```rust
use agent_governance::{AgentMeshClient, ClientOptions};

let client = AgentMeshClient::new("my-agent").unwrap();
let result = client.execute_with_governance("data.read", None);
assert!(result.allowed);
```

</details>

<details>
<summary><b>Go</b></summary>

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

</details>

> **전체 과정:** [QUICKSTART.md](../../docs/i18n/quickstart.ko.md) - 10분만 투자하시면 YAML 정책 파일, OPA/Rego, Cedar 지원을 통해 에이전트 거버넌스를 처음부터 끝까지 체험해 볼 수 있습니다.
> 🌍 다음 언어로도 제공됩니다: [English](../../docs/quickstart.md) | [日本語](./quickstart.ja.md) | [简体中文](./quickstart.zh-CN.md)

---

## 주요 기능

| 기능 | 상세 설명 | 관련 링크 |
|---|---|---|
| **Policy Engine(정책 엔진)** | 에이전트의 모든 동작을 밀리초 이내에 결정론적으로 사전 평가할 수 있습니다. YAML, OPA/Rego, Cedar가 지원됩니다. | [Agent OS](../../agent-governance-python/agent-os/) · [Benchmarks](../../docs/BENCHMARKS.md) |
| **Contributor Reputation(기여자 평판점검)** | PR 및 이슈 등록자에 대해 신원 세탁(credential laundering), 암호 스프레이 패턴 공격(spray pattern) 등의 사회공학(Social Engineering) 공격 문제가 있는지 점검하는 GitHub Action으로 다른 리포지터리에서 사용가능합니다. | [Action](../../.github/actions/contributor-check/) · [Scripts](../../scripts/) |
| **Zero-Trust Identity(제로트러스트 신원증명)** | Ed25519 + 양자내성(quantum-safe) ML-DSA-65 신분증(credential), 에이전트 신용점수 부여 (0–1000), SPIFFE/SVID 표준규격을 지원합니다 | [AgentMesh](../../agent-governance-python/agent-mesh/) |
| **Execution Sandboxing(실행 샌드박싱)** | 4단계 권한 격리 링(4-tier privilege rings), 사가 오케스트레이션(saga orchestration), 킬스위치(kill switch) | [Runtime](../../agent-governance-python/agent-runtime/) · [Hypervisor](../../agent-governance-python/agent-hypervisor/) |
| **Agent SRE(에이전트 SRE)** | SLO, 에러 버짓(error budgets), 리플레이 디버깅(replay debugging), 카오스 공학(chaos engineering), 써킷 브레이커(circuit breakers) | [Agent SRE](../../agent-governance-python/agent-sre/) |
| **MCP Security Scanner(MCP 보안 스캐너)** | MCP 정의 규격에 있을지 모르는 도구 오염(tool poisoning), 유사 도구명 공격(typosquatting), 숨겨진 지시문(hidden instructions) 등을 탐지합니다. | [MCP Scanner](../../agent-governance-python/agent-os/src/agent_os/mcp_security.py) |
| **Shadow AI Discovery(미등록 AI 감지)** | 프로세스, 환경 설정, 리포지터리 등에 있는 미등록 에이전트를 감지합니다. | [Agent Discovery](../../agent-governance-python/agent-discovery/) |
| **Agent Lifecycle(에이전트 라이프사이클)** | 에이전트 생성 → 신원증명 갱신(credential rotation) → 무사용 감지(orphan detection) → 퇴역(decommissioning) | [Lifecycle](../../agent-governance-python/agent-mesh/src/agentmesh/lifecycle/) |
| **Governance Dashboard(거버넌스 대시보드)** | 에이전트의 상태, 신뢰, 규제 준수, 감사 이벤트 등에 대해 실시간으로 모니터링할 수 있습니다. | [Dashboard](../../examples/demos/governance-dashboard/) |
| **Unified CLI(통합 CLI)** | `agt verify`, `agt red-team`, `agt doctor`, `agt lint-policy` — 명령어 하나로 모든 동작을 간편하게 실행합니다. | [CLI](../../agent-governance-python/agent-compliance/src/agent_compliance/cli/agt.py) |
| **PromptDefense Evaluator(프롬프트 방어 점검)** | 규제 준수 점검을 위해 12-vector의 프롬프트 주입 감사를 수행합니다. | [Evaluator](../../agent-governance-python/agent-compliance/src/agent_compliance/prompt_defense.py) |

---

## 다양한 스택에서 동작합니다.

| 프레임워크 | 연동 |
|-----------|-------------|
| [**Microsoft Agent Framework**](https://github.com/microsoft/agent-framework) | 네이티브 미들웨어 |
| [**Semantic Kernel**](https://github.com/microsoft/semantic-kernel) | 네이티브 (.NET + Python) |
| [Microsoft AutoGen](https://github.com/microsoft/autogen) | 어댑터 |
| [LangGraph](https://github.com/langchain-ai/langgraph) / [LangChain](https://github.com/langchain-ai/langchain) | 어댑터 |
| [CrewAI](https://github.com/crewAIInc/crewAI) | 어댑터 |
| [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) | 미들웨어 |
| [pi-mono](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) | TypeScript SDK 연동 |
| [Google ADK](https://github.com/google/adk-python) | 어댑터 |
| [LlamaIndex](https://github.com/run-llama/llama_index) | 미들웨어 |
| [Haystack](https://github.com/deepset-ai/haystack) | 파이프라인 |
| [Dify](https://github.com/langgenius/dify) | 파이프라인 |
| [Azure AI Foundry](https://learn.microsoft.com/azure/ai-studio/) | 배포 가이드 |

전체 목록: [프레임워크 연동](../../agent-governance-python/agentmesh-integrations/) · [Quickstart 예제](../../examples/quickstart/)

---

## OWASP Agentic Top 10 — 10대 리스크 모두를 커버합니다.

| Risk | ID | AGT 통제 |
|------|----|-------------|
| Agent Goal Hijacking | ASI-01 | 정책 엔진이 비인가된 에이전트 목표 변경을 차단 |
| Excessive Capabilities | ASI-02 | 최소권한 부여 강제 적용 |
| Identity & Privilege Abuse | ASI-03 | Ed25519와 ML-DSA-65에 의한 제로트러스트 신원증명 제공|
| Uncontrolled Code Execution | ASI-04 | 실행 격리 링(rings) 및 샌드박싱(sandboxing) |
| Insecure Output Handling | ASI-05 | 컨텐츠 정책이 모든 출력을 검증 |
| Memory Poisoning | ASI-06 | 무결성 체크를 통해 일화적(episodic) 메모리 구현 |
| Unsafe Inter-Agent Comms | ASI-07 | 채널 암호화 및 신뢰 게이트 구현 |
| Cascading Failures | ASI-08 | 써킷 브레이커 및 SLO 강제화 |
| Human-Agent Trust Deficit | ASI-09 | 전체 감사 추적(full audit trails) 및 비행기록계(flight recorder) |
| Rogue Agents | ASI-10 | 실행 격리, 킬스위치(kill switch), 이상 탐지(anomaly detection) |

전체 목록: [OWASP-COMPLIANCE.md](../../docs/OWASP-COMPLIANCE.md) · 주요 규제 대응: [EU AI Act](../../docs/compliance/), [NIST AI RMF](../../docs/compliance/nist-ai-rmf-alignment.md), [Colorado AI Act](../../docs/compliance/)

---

## 성능 평가

각 거버넌스 동작은 **0.1ms(밀리초)* 이내에 실행되어 통상적인 LLM API 호출보다 10배 이상 빠릅니다.

| 평가지표 | Latency (중위값 기준) | Throughput |
|---|---|---|
| 정책 평가 (단일 rule) | 0.012 ms | 72K ops/sec |
| 정책 평가 (100 rules) | 0.029 ms | 31K ops/sec |
| 정책 강제 | 0.091 ms | 9.3K ops/sec |
| 병렬 실행 (50 agents) | — | 35,481 ops/sec |

> **주의사항:** 위 수치는 정책 평가(policy evaluation)에 한정됩니다. 분산 다중-에이전트 환경에서는 에이전트간 암호화 검증 및 메시 핸드셰이크에 따른
> 5–50ms 정도의 추가 부하를 고려해야 합니다. 전체 내용에 대해서는 [성능 평가의 한계점](../../docs/LIMITATIONS.md#3-performance-policy-eval-vs-end-to-end) 문서를 참고하십시오.

전체 평가 방법론은 [BENCHMARKS.md](../../docs/BENCHMARKS.md)를 참고하시기 바랍니다.

---

## 설치 방법

| 언어 | 패키지 | 명령어 |
|----------|---------|---------|
| **Python** | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | `pip install agent-governance-toolkit[full]` |
| **TypeScript** | [`@microsoft/agent-governance-sdk`](../../agent-governance-typescript/) | `npm install @microsoft/agent-governance-sdk` |
| **.NET** | [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) | `dotnet add package Microsoft.AgentGovernance` |
| **.NET MCP** | `Microsoft.AgentGovernance.Extensions.ModelContextProtocol` | `dotnet add package Microsoft.AgentGovernance.Extensions.ModelContextProtocol` |
| **Rust** | [`agent-governance`](https://crates.io/crates/agent-governance) | `cargo add agent-governance` |
| **Go** | [`agent-governance-toolkit`](../../agent-governance-golang/) | `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang` |

위에 명시된 5개 언어 패키지 모두 정책, 신원, 신뢰, 감사 등의 핵심 거버넌스 기능이 구현되어 있습니다. Python은 풀 스택을 지원합니다. 
**[언어 패키지별 지원 현황](../../docs/PACKAGE-FEATURE-MATRIX.md)**을 참고하십시오. 

<details>
<summary><b>개별 Python 패키지</b></summary>

| 패키지 | PyPI | 설명 |
|---------|------|-------------|
| Agent OS | [`agent-os-kernel`]([https://pypi.org/project/agent-os-kernel/](https://pypi.org/project/agent-os-kernel/)) | 정책 엔진, 역량 모델, 감사 로그 기록, MCP 게이트웨이 |
| AgentMesh | [`agentmesh-platform`]([https://pypi.org/project/agentmesh-platform/](https://pypi.org/project/agentmesh-platform/)) | 제로 트러스트 신원증명, 신뢰 점수 부여, A2A/MCP/IATP 브릿지 |
| Agent Runtime | [`agentmesh-runtime`](../../agent-governance-python/agent-runtime/) | 권한 격리 링, 사가 오케스트레이션, 종료 제어 |
| Agent SRE | [`agent-sre`]([https://pypi.org/project/agent-sre/](https://pypi.org/project/agent-sre/)) | SLO, 에러 버젯, 카오스 공학, 서킷 브레이커 |
| Agent Compliance | [`agent-governance-toolkit`]([https://pypi.org/project/agent-governance-toolkit/](https://pypi.org/project/agent-governance-toolkit/)) | OWASP 검증, 무결성 체크, 정책 린팅(Linting) |
| Agent Discovery | [`agent-discovery`](../../agent-governance-python/agent-discovery/) | 미등록 AI(Shadow AI) 감지, 인벤토리 관리, 리스크 점수화 |
| Agent Hypervisor | [`agent-hypervisor`](../../agent-governance-python/agent-hypervisor/) | 가역성(Reversibility) 검증, 실행 계획 유효성 검사 |
| Agent Marketplace | [`agentmesh-marketplace`](../../agent-governance-python/agent-marketplace/) | 플러그인 라이프사이클 관리 |
| Agent Lightning | [`agentmesh-lightning`](../../agent-governance-python/agent-lightning/) | 강화학습(RL) 훈련 거버넌스 |

</details>

---

## 문서 (Documentation)

**시작하기**
- [Quick Start](./quickstart.ko.md) — 10분 만에 끝내는 에이전트 거버넌스 시작 가이드
- [Tutorials](../../docs/tutorials/) — 40개 이상의 튜토리얼 및 7장으로 구성된 'Policy-as-Code' 심층 학습
- [FAQ](../../docs/FAQ.md) — 고객, 파트너 및 평가자를 위한 기술 Q&A

**아키텍처 및 레퍼런스**
- [Language Package Matrix](../../docs/PACKAGE-FEATURE-MATRIX.md) — 언어별 지원 기능 비교표
- [Architecture](../../docs/ARCHITECTURE.md) — 시스템 설계, 보안 모델, 신뢰 점수 체계
- [Architecture Decisions](../../docs/adr/README.md) — 아키텍처 결정 기록(ADR) 로그
- [Threat Model](../../docs/THREAT_MODEL.md) — 신뢰 경계 및 STRIDE 분석
- [API: Agent OS](../../agent-governance-python/agent-os/README.md) · [AgentMesh](../../agent-governance-python/agent-mesh/README.md) · [Agent SRE](../../agent-governance-python/agent-sre/README.md)

**컴플라이언스 및 배포**
- [Known Limitations](../../docs/LIMITATIONS.md) — 설계상의 제약 사항 및 권장되는 계층 방어 전략
- [OWASP Compliance](../../docs/OWASP-COMPLIANCE.md) — ASI-01부터 ASI-10까지의 전체 매핑 가이드
- [Deployment Guides](../../docs/deployment/README.md) — Azure (AKS, Foundry, Container Apps), AWS (ECS/Fargate), GCP (GKE), Docker Compose 배포 가이드
- [NIST AI RMF Alignment]../../docs/compliance/nist-ai-rmf-alignment.md) · [EU AI Act](docs/compliance/) · [SOC 2 Mapping](../../docs/compliance/soc2-mapping.md)

**확장 기능**
- [VS Code Extension](../../agent-governance-typescript/agent-os-vscode/) · [Framework Integrations](../../agent-governance-python/agentmesh-integrations/)

---

## 보안 (Security)

이 툴킷은 OS 커널 레벨의 격리가 아닌 **애플리케이션 레벨의 거버넌스**(Python 미들웨어)를 제공합니다. 정책 엔진과 에이전트는 동일한 프로세스 내에서 실행되며, 이는 모든 Python 기반 에이전트 프레임워크와 동일한 신뢰 경계(Trust Boundary)를 공유함을 의미합니다.

**운영 환경 권장 사항:** OS 레벨의 격리를 위해 각 에이전트를 별도의 컨테이너에서 실행하십시오. 자세한 내용은 [아키텍처 — 보안 경계](../../docs/ARCHITECTURE.md) 문서를 참고해 주십시오.

> **📖 [알려진 제약 사항 및 설계 범위](../../docs/LIMITATIONS.md)** — AGT가 수행하지 않는 작업, 분산 배포 시의 투명한 성능 수치, 그리고 권장되는 계층 방어(Layered Defense) 아키텍처에 대해 설명합니다.

| 도구 (Tool) | 점검 범위 (Coverage) |
|------|----------|
| **CodeQL** | Python 및 TypeScript 정적 분석(SAST) |
| **Gitleaks** | PR/Push/주간 단위 시크릿 스캐닝 |
| **ClusterFuzzLite** | 7개 퍼징 타겟 (정책, 주입, MCP, 샌드박스, 신뢰) |
| **Dependabot** | 13개 생태계 의존성 관리 |
| **OpenSSF Scorecard** | 주간 단위 보안 점수 산출 및 SARIF 업로드 |

---

## 기여하기 (Contributing)

- [기여 가이드](../../CONTRIBUTING.md) · [커뮤니티](../../docs/COMMUNITY.md) · [보안 정책](../../SECURITY.md) · [변경 이력](../../CHANGELOG.md)

**AGT를 사용 중이신가요?** [ADOPTERS.md](../../docs/ADOPTERS.md)에 귀하의 조직을 추가해 주세요. 이 프로젝트가 지속적인 동력을 얻고 다른 사용자들이 실사용 사례를 발견하는 데 큰 도움이 됩니다.

## 중요 고지 사항

제3자 에이전트 프레임워크 또는 서비스와 연동되는 애플리케이션을 구축하기 위해 Agent Governance Toolkit을 사용하는 경우, 그에 따른 책임은 사용자 본인에게 있습니다. 제3자 서비스와 공유되는 모든 데이터를 검토하고, 해당 서비스의 데이터 보유 및 보관 위치에 대한 정책을 숙지할 것을 권장합니다.

## 라이선스 (License)

이 프로젝트는 [MIT 라이선스](../../LICENSE)에 따라 라이선스가 부여됩니다.

## 상표 (Trademarks)

본 프로젝트에는 프로젝트, 제품 또는 서비스에 대한 상표 또는 로고가 포함될 수 있습니다. Microsoft 상표 또는 로고의 허용된 사용은 [Microsoft의 상표 및 브랜드 가이드라인](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general)을 준수해야 합니다. 본 프로젝트의 수정된 버전에서 Microsoft 상표 또는 로고를 사용할 때 혼란을 야기하거나 Microsoft의 후원을 암시해서는 안 됩니다. 제3자 상표 또는 로고의 사용은 해당 제3자의 정책을 따릅니다.
