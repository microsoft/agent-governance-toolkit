---
title: "Agent Governance Toolkit"
last_reviewed: 2026-08-27
owner: agt-maintainers
---

> Bu belge [README.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/README.md) dosyasının Türkçe çevirisidir. En güncel bilgi için İngilizce sürümü kontrol edin.

🌍 [English](https://github.com/microsoft/agent-governance-toolkit/blob/main/README.md) | [日本語](./README.ja.md) | [简体中文](./README.zh-CN.md) | [한국어](./README.ko.md) | [Türkçe](./README.tr.md)

![Agent Governance Toolkit](../assets/readme-banner.svg)

# Agent Governance Toolkit

### Ajanlarınızı üretime alın, gece rahat uyuyun

<p align="center">
  <a href="https://microsoft.github.io/agent-governance-toolkit">
    <img src="https://img.shields.io/badge/%F0%9F%93%96_Full_Documentation-microsoft.github.io%2Fagent--governance--toolkit-0078D4?style=for-the-badge&logoColor=white" alt="Full Documentation" height="40">
  </a>
</p>

<p align="center">
  <strong>
    🚀 <a href="#hizli-baslangic">Hızlı Başlangıç</a> ·
    📋 <a href="#spesifikasyonlar">Spesifikasyonlar</a> ·
    📦 <a href="https://pypi.org/project/agent-governance-toolkit/">PyPI</a> ·
    📝 <a href="https://github.com/microsoft/agent-governance-toolkit/blob/main/CHANGELOG.md">Değişiklik Günlüğü</a>
  </strong>
</p>

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![Discord](https://dcbadge.limes.pink/api/server/TxMRqY3pFr?style=flat)](https://discord.gg/TxMRqY3pFr)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/microsoft/agent-governance-toolkit/blob/main/LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/agent-governance-toolkit?label=PyPI)](https://pypi.org/project/agent-governance-toolkit/)
[![npm](https://img.shields.io/npm/v/%40microsoft/agent-governance-sdk?label=npm)](https://www.npmjs.com/package/@microsoft/agent-governance-sdk)
[![NuGet](https://img.shields.io/nuget/v/Microsoft.AgentGovernance?label=NuGet)](https://www.nuget.org/packages/Microsoft.AgentGovernance)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12085/badge)](https://www.bestpractices.dev/projects/12085)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](../compliance/owasp-agentic-top10-architecture.md)
[![AARM Extended](https://img.shields.io/badge/AARM-Extended_(R1–R9)-brightgreen)](https://aarm.dev/builders/agent-governance-toolkit-microsoft)
[![ATF](https://img.shields.io/badge/ATF-All_5_Elements-brightgreen)](https://agentictrustframework.ai/ecosystem)

> [!IMPORTANT]
> **Public Preview** — üretim kalitesinde genel önizleme sürümleri. Genel kullanıma açılmadan (GA) önce geriye dönük uyumluluğu bozan değişiklikler olabilir.

Otonom yapay zeka ajanları için politika zorlama (policy enforcement), kimlik, yürütme yalıtımı (sandboxing) ve SRE. Tek bir `pip install`, her framework ile.

---

## Problem

Yapay zeka ajanlarınız araç çağırıyor, web'de geziniyor, veritabanı sorguluyor ve başka ajanlara görev devrediyor. Bir kez devreye alındıktan sonra kararlarını kendileri veriyor. Üç sorunun cevabına ihtiyacınız var:

**1. Bu eylem izinli mi?** `send_email` ve `query_database` erişimi olan bir ajanın `drop_table` çalıştırabilmesi gerekmez. OAuth kapsamları ve IAM rolleri bir ajanın hangi servislere erişebileceğini kontrol eder, bağlandıktan sonra ne yaptığını değil.

**2. Bunu hangi ajan yaptı?** Çok ajanlı bir sistemde beş ajan tek bir API anahtarını paylaşıyor olabilir. Bir şeyler ters gittiğinde "bir ajan yaptı" demek olay müdahalesi sayılmaz.

**3. Ne olduğunu kanıtlayabiliyor musunuz?** Denetçiler ve düzenleyiciler her kararın kurcalama kanıtı bırakan (tamper-evident) kaydını istiyor: hangi politika aktifti, ajan neyi talep etti, ve neden izin verildi veya reddedildi.

Prompt seviyesindeki güvenlik ("lütfen kurallara uy") bir kontrol yüzeyi değildir. Stokastik bir sisteme yapılmış nazik bir ricadır. [OWASP LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) bunu açıkça belirtiyor: prompt injection'ı önlemenin kusursuz bir yönteminin olup olmadığı belirsizdir. Yayınlanmış sayılar da bunu destekliyor. [Andriushchenko vd. (ICLR 2025)](https://arxiv.org/abs/2404.02151), logprob erişimi ve sonek optimizasyonu kullanan uyarlanabilir saldırılarla GPT-4o, GPT-3.5, Claude 3 ve Llama-3 üzerinde [JailbreakBench](https://arxiv.org/abs/2404.01318) kıyaslamasına (Chao vd., NeurIPS 2024) karşı **%100 saldırı başarı oranı** bildiriyor. Microsoft'un kendi [AI Red Teaming Agent](https://learn.microsoft.com/azure/ai-foundry/concepts/ai-red-teaming-agent) aracı, düşmanca girdi altındaki politika ihlali oranı olan **Attack Success Rate (ASR)** metriğini bu hata sınıfı için kanonik ölçüt olarak resmileştiriyor. [*Lessons from Red Teaming 100 Generative AI Products*](https://www.microsoft.com/en-us/security/blog/2025/01/13/3-takeaways-from-red-teaming-100-generative-ai-products/) aynı noktayı pekiştiriyor: azaltıcı önlemler riski tamamen ortadan kaldırmıyor ve model katmanındaki savunmalar yapısı gereği olasılıksal olduğu için red teaming sürekli bir süreç olmak zorunda.

AGT bu mücadeleyi prompt'un içinde kazanmaya çalışmaz. Her araç çağrısı, mesaj gönderimi ve görev devri, modelin niyeti hatta çıkmadan *önce*, deterministik uygulama kodunda araya girilerek yakalanır. AGT çekirdeğinin reddettiği eylemler "olası değil" demek yerine **yapısal olarak imkânsız** hâle gelir. Bir ajandan düzgün davranmasını istemekle onu kötü davranamaz kılmak arasındaki fark budur.

---

<a id="hizli-baslangic"></a>

## Hızlı Başlangıç

**Ön koşullar:** Python 3.11+

```bash
pip install "agent-governance-toolkit[full]"
```

Aşağıdaki hızlı başlangıç import'ları için `[full]` ekini kullanın. Temel
`agent-governance-toolkit` paketi yalnızca uyumluluk (compliance) CLI'ını kurar;
yönetişim modülleri birleştirilmiş core dağıtımında yer alır. `agentmesh` hızlı
başlangıç import'u güncel sarmalayıcı API olmaya devam ediyor. `agent_os` import
edildiğinde bir `DeprecationWarning` üretilir, çünkü eski `agent-os-kernel`
dağıtımı kullanımdan kaldırılmıştır. Onun yerine `agent-governance-toolkit-core`
dağıtımını (veya bunu içeren `[full]` ekini) kullanın. Politika motoru host kodu
ACS SDK'sını kullanır; `agt-policies`, v4'ten v5'e tek yönlü geçiş komutunu
sağlar. ACS öncesi `agent_os.policies` kural modeli kaldırıldı; yerine gelenler
`BREAKING_CHANGES.md` dosyasında listelenmiştir.

Claude Code için AGT'yi bir eklenti pazarı olarak ekleyip yönetişim eklentisini kurun:

```text
/plugin marketplace add microsoft/agent-governance-toolkit
/plugin install agt-governance@agent-governance-toolkit
```

Herhangi bir araç fonksiyonunu iki satırda yönetişim altına alın:

```python
from agentmesh.governance import govern

safe_tool = govern(my_tool, policy="policy.yaml")   # her çağrı denetlenir, loglanır, zorlanır
```

Her çağrıda `safe_tool` YAML politikasını değerlendirir, kararı bir denetim izine
loglar ve politika eylemi engellediğinde `GovernanceDenied` hatası üretir.

```yaml
# policy.yaml
apiVersion: governance.toolkit/v1
name: production-policy
default_action: allow
rules:
  - name: block-destructive
    condition: "action.type in ['drop', 'delete', 'truncate']"
    action: deny
    description: "Destructive operations require human approval"

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
  Destructive operations require human approval
```

Programatik kontrol için tam `AgentControl` API'sini de kullanabilirsiniz:

<details>
<summary><b>AgentControl örneği</b></summary>

```python
from agent_control_specification import AgentControl

runtime = AgentControl.from_path(str("manifest.yaml"))
result = runtime.evaluate(
    "input",
    {
        "envelope": {"agent_id": "example-agent"},
        "input": {"body": {"action": "web_search", "params": {}}},
    },
)
print(result.verdict)
runtime.close()
```

[Tam ACS e-posta aracı örneğini çalıştırın](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/acs-email-tool).

</details>

<details>
<summary><b>TypeScript / .NET / Rust / Go örnekleri</b></summary>

**TypeScript**
```typescript
import { PolicyEngine } from "@microsoft/agent-governance-sdk";

const engine = new PolicyEngine([
  { action: "web_search", effect: "allow" },
  { action: "shell_exec", effect: "deny" },
]);
engine.evaluate("web_search"); // "allow"
engine.evaluate("shell_exec"); // "deny"
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

// MCP sunucu entegrasyonu
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

CLI araçları:

```bash
agt doctor                                        # kurulumu kontrol eder
agt verify                                        # OWASP uyumluluk kontrolü
agt verify --evidence ./agt-evidence.json --strict # zayıf kanıtta CI'ı başarısız kılar
agt red-team scan ./prompts/ --min-grade B         # prompt injection denetimi
agt lint-policy policies/                          # politika dosyalarını doğrular
```

Tam anlatım: [quickstart.tr.md](./quickstart.tr.md) — sıfırdan yönetişimli ajanlara 5 dakikada.
🌍 Diğer diller: [English](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/quickstart.md) | [日本語](./quickstart.ja.md) | [简体中文](./quickstart.zh-CN.md) | [한국어](./quickstart.ko.md)

---

## Nasıl Çalışır

```
Agent ──► Policy Engine ──► Identity ──► Audit Log
            (YAML/OPA/Cedar)  (SPIFFE/DID/mTLS)  (Tamper-evident)
                 │                                      │
                 ├── Allowed ──► Tool executes           │
                 └── Denied  ──► GovernanceDenied        │
                                                        ▼
                                                 Decision Record
```

Her katman opsiyoneldir. `govern()` ile başlayın ve risk profiliniz büyüdükçe katman ekleyin. Ekiplerin çoğu politika zorlama + denetim loglaması ile çalışır ve tam yığına hiç ihtiyaç duymaz.

---

## Paketler

| Paket | Açıklama |
|---------|-------------|
| [**Agent OS**](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-os) | Politika motoru, ajan yaşam döngüsü, yönetişim geçidi |
| [**Agent Control Specification**](https://github.com/microsoft/agent-governance-toolkit/tree/main/policy-engine) ([README](https://github.com/microsoft/agent-governance-toolkit/blob/main/policy-engine/README.md)) | AGT politika katmanını destekleyen durumsuz, deterministik, hata durumunda kapalı (fail-closed) politika karar çalışma zamanı (Rust çekirdek) |
| [**Agent Mesh**](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-mesh) | Ajan keşfi, yönlendirme ve güven ağı |
| [**Agent Runtime**](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-runtime) | Dört yetki halkası ile yürütme yalıtımı |
| [**Agent SRE**](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-sre) | Acil durdurma anahtarı (kill switch), SLO izleme, kaos testi |
| [**Agent Compliance**](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-compliance) | OWASP doğrulaması, politika linting, bütünlük kontrolleri |
| [**Agent Marketplace**](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-marketplace) | Eklenti yönetişimi ve güven puanlaması |
| [**Agent Lightning**](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-lightning) | İhlal cezalarıyla RL eğitimi yönetişimi |
| [**Agent Hypervisor**](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-hypervisor) | Yürütme denetimi, delta motoru, bellek içi taahhüt takibi, komut reddetme listesi zorlaması |

### Ek Yetenekler

| Yetenek | Açıklama |
|---|---|
| **MCP Security Gateway** | Araç zehirlenmesi tespiti, sapma izleme, typosquatting, gizli talimat taraması ([Spesifikasyon](../specs/MCP-SECURITY-GATEWAY-1.0.md)) |
| **Shadow AI Discovery** | Süreçler, yapılandırmalar ve depolar arasında kayıtlı olmayan ajanları bulma ([Discovery](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-discovery)) |
| **Governance Dashboard** | Sağlık, güven ve uyumluluk için gerçek zamanlı filo görünürlüğü ([Dashboard](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/demos/governance-dashboard)) |
| **PromptDefense Evaluator** | 12 vektörlü prompt injection denetimi ([Evaluator](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-compliance/src/agent_compliance/prompt_defense.py)) |
| **Contributor Reputation** | Sosyal mühendisliğe karşı PR/issue yazarı taraması. Yeniden kullanılabilir GitHub Action ([Action](https://github.com/microsoft/agent-governance-toolkit/tree/main/.github/actions/contributor-check)) |

---

## Kurulum

| Dil | Paket | Komut |
|----------|---------|---------|
| **Python** | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | `pip install "agent-governance-toolkit[full]"` |
| **TypeScript** | [`@microsoft/agent-governance-sdk`](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-typescript) | `npm install @microsoft/agent-governance-sdk` |
| **Copilot CLI** | [`@microsoft/agent-governance-copilot-cli`](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-copilot-cli) | `npx @microsoft/agent-governance-copilot-cli install` |
| **Claude Code** | [`@microsoft/agent-governance-claude-code`](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-claude-code) | `claude --plugin-dir ./agent-governance-claude-code` |
| **OpenCode** | [`@microsoft/agent-governance-opencode`](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-opencode) | `npm install @microsoft/agent-governance-opencode` |
| **.NET** | [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) | `dotnet add package Microsoft.AgentGovernance` |
| **.NET MCP** | `Microsoft.AgentGovernance.Extensions.ModelContextProtocol` | `dotnet add package Microsoft.AgentGovernance.Extensions.ModelContextProtocol` |
| **Rust** | [`agent-governance`](https://crates.io/crates/agent-governance) | `cargo add agent-governance` |
| **Go** | [`agent-governance-toolkit`](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-golang) | `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang` |

Beş dil SDK'sının tamamı çekirdek yönetişimi (politika, kimlik, güven, denetim) uygular. Tam yığın Python'da mevcuttur. Copilot CLI ve Claude Code, TypeScript SDK üzerine kurulmuş birinci taraf geliştirici yüzeyleridir.
Dil bazında ayrıntılı kapsam için **[Language Package Matrix](../PACKAGE-FEATURE-MATRIX.md)** dosyasına bakın.

<details>
<summary><b>Python dağıtımları (v4.1.0 — birleştirilmiş)</b></summary>

v4.1.0 itibarıyla 45 paket, 5 üst düzey dağıtımda birleştirilmiştir:

| Dağıtım | PyPI | İçerdikleri |
|--------------|------|-----------------|
| `agent-governance-toolkit-core` | [`agent-governance-toolkit-core`](https://pypi.org/project/agent-governance-toolkit-core/) | Politika motoru, yetenek modeli, denetim, MCP geçidi, sıfır güven kimliği, güven puanlaması, A2A/MCP/IATP köprüleri |
| `agent-governance-toolkit-runtime` | [`agent-governance-toolkit-runtime`](https://pypi.org/project/agent-governance-toolkit-runtime/) | Yetki halkaları, saga orkestrasyonu, sonlandırma kontrolü, yürütme planı doğrulaması, komut reddetme listesi zorlaması |
| `agent-governance-toolkit-sre` | [`agent-governance-toolkit-sre`](https://pypi.org/project/agent-governance-toolkit-sre/) | SLO'lar, hata bütçeleri, kaos mühendisliği, devre kesiciler |
| `agent-governance-toolkit-cli` | [`agent-governance-toolkit-cli`](https://pypi.org/project/agent-governance-toolkit-cli/) | `agt` CLI, OWASP doğrulaması, bütünlük kontrolleri, politika linting |
| `agent-governance-toolkit[full]` | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | Yukarıdakilerin tümünü kuran meta paket |

Önceki paket adları (`agent-os-kernel`, `agentmesh-platform`, `agentmesh-runtime`, `agent-sre`, `agent-discovery`, `agent-hypervisor`, `agentmesh-marketplace`, `agentmesh-lightning`) birleştirilmiş dağıtımlara yönlendiren saplama paketler olarak kurulabilir durumdadır.

</details>

### Ön Koşullar

- **Python**: 3.10+
- **Node.js**: 18+ / npm 9+ (TypeScript SDK)
- **.NET**: 8+
- **Go**: 1.25+
- **Rust**: 1.70+
- **Opsiyonel**: Azure ile entegre özellikler için `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`

---

## Framework Desteği

| Framework | Entegrasyon |
|-----------|-------------|
| [**Microsoft Agent Framework**](https://github.com/microsoft/agent-framework) | Yerel ara katman (middleware) |
| [**Semantic Kernel**](https://github.com/microsoft/semantic-kernel) | Yerel (.NET + Python) |
| [AutoGen](https://github.com/microsoft/autogen) | Adaptör |
| [LangGraph](https://github.com/langchain-ai/langgraph) / [LangChain](https://github.com/langchain-ai/langchain) | Adaptör |
| [CrewAI](https://github.com/crewAIInc/crewAI) | Adaptör |
| [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) | Ara katman |
| Claude Code | Yönetişim eklenti paketi |
| [Google ADK](https://github.com/google/adk-python) | Adaptör |
| [LlamaIndex](https://github.com/run-llama/llama_index) | Ara katman |
| [Haystack](https://github.com/deepset-ai/haystack) | Pipeline |
| [Mastra](https://github.com/mastra-ai/mastra) | Adaptör |
| [Dify](https://github.com/langgenius/dify) | Eklenti |
| [Azure AI Foundry](https://learn.microsoft.com/azure/ai-studio/) | Devreye alma rehberi |
| GitHub Copilot CLI | Yönetişim kurulumu |

Tam liste: [Framework Integrations](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agentmesh-integrations) · [Quickstart Examples](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/quickstart)

---

## Örnekler

| Örnek | Framework | Neyi gösteriyor |
|---------|-----------|----------------------|
| [acs-email-tool](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/acs-email-tool) | Framework'ten bağımsız ACS host | Snapshot, karar (verdict), dönüştürme, reddetme ve host zorlaması |
| [acs-atr-annotator](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/acs-atr-annotator) | ACS özel politika | Hata durumunda kapalı kararlarla bağımsız tehdit kuralı açıklamaları |
| [openai-agents-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/openai-agents-governed) | OpenAI Agents SDK | Güven katmanlarıyla politika denetimli araç çağrıları |
| [crewai-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/crewai-governed) | CrewAI | Rol tabanlı politikalarla çok ajanlı yönetişim |
| [smolagents-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/smolagents-governed) | HuggingFace smolagents | Hafif ajan yönetişimi |
| [maf-integration](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/maf-integration) | MAF | Microsoft Agent Framework entegrasyonu |
| [mcp-trust-verified-server](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/mcp-trust-verified-server) | MCP | Güven doğrulamalı MCP sunucu uygulaması |
| [governance-dashboard](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/demos/governance-dashboard) | Streamlit | Gerçek zamanlı filo görünürlüğü panosu |

---

<a id="spesifikasyonlar"></a>

## Spesifikasyonlar

Her ana bileşenin, uygunluk testleriyle birlikte resmi bir RFC 2119 spesifikasyonu vardır. Bu spesifikasyonlar davranışsal sözleşmeyi tanımlar: uygulamaların ne yapmak ZORUNDA olduğunu, neyi YAPMASI GEREKTİĞİNİ ve neyi YAPABİLECEĞİNİ.

| Spesifikasyon | Kapsam | Test |
|---|---|---|
| [Agent OS Policy Engine](../specs/AGENT-OS-POLICY-ENGINE-1.0.md) | Yerel çalışma zamanı entegrasyonu ve hata durumunda kapalı semantik | — |
| [Agent Control Specification](https://github.com/microsoft/agent-governance-toolkit/blob/main/policy-engine/spec/SPECIFICATION.md) | Durumsuz müdahale noktası politika çalışma zamanı, kararlar, dönüştürme, hata durumunda kapalı | — |
| [AgentMesh Identity and Trust](../specs/AGENTMESH-IDENTITY-TRUST-1.0.md) | Kimlik bilgileri, güven puanlaması, yetki devri zincirleri | 135 |
| [Agent Hypervisor Execution Control](../specs/AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md) | Yetki halkaları, saga orkestrasyonu, acil durdurma anahtarı | 80 |
| [AgentMesh Trust and Coordination](../specs/AGENTMESH-TRUST-COORDINATION-1.0.md) | Eşler arası güven müzakeresi, ağ genelinde politika | 62 |
| [Agent SRE Governance](../specs/AGENT-SRE-GOVERNANCE-1.0.md) | SLO'lar, hata bütçeleri, kaos, devre kesiciler | 111 |
| [MCP Security Gateway](../specs/MCP-SECURITY-GATEWAY-1.0.md) | Araç zehirlenmesi, sapma tespiti, gizli talimatlar | 127 |
| [Agent Lightning Fast-Path](../specs/AGENT-LIGHTNING-FAST-PATH-1.0.md) | RL eğitimi yönetişimi, ihlal cezaları | 100 |
| [Framework Adapter Contract](../specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md) | Yerel framework aracılık sözleşmesi | — |
| [Audit and Compliance](../specs/AUDIT-COMPLIANCE-1.0.md) | Merkle denetimi, uyumluluk eşleştirmesi, Decision BOM | 157 |
| [AgentMesh Wire Protocol](../specs/AGENTMESH-WIRE-1.0.md) | Mesaj formatı, yönlendirme, serileştirme | — |

**992 uygunluk testi**, kodun spesifikasyonlarla hizalı kalmasını sağlar. Nedenlerini [29 Mimari Karar Kaydı](../adr/) belgeler.

---

## Standartlara Uyumluluk

| Standart | Kapsam |
|----------|----------|
| [OWASP Agentic AI Top 10](../compliance/owasp-agentic-top10-architecture.md) | Tüm ASI risk kategorileri deterministik kontrollerle eşleştirilmiş |
| [NIST AI RMF 1.0](../compliance/nist-ai-rmf-alignment.md) | GOVERN, MAP, MEASURE, MANAGE ile tam hizalanma |
| [EU AI Act](../compliance/) | Otomatik kanıt üretimiyle uyumluluk eşleştirmesi |
| [SOC 2](../compliance/soc2-mapping.md) | Denetim izi ihracıyla kontrol eşleştirmesi |
| [AARM Extended](https://aarm.dev/builders/agent-governance-toolkit-microsoft) | R1–R9 gereksinimlerinin tamamı karşılanmış; 14 Haziran 2026'da doğrulandı |
| [ATF](https://agentictrustframework.ai/ecosystem) | Beş unsurun tamamı eşleştirilmiş: Agent Mesh (kimlik), Agent OS (politika), Agent Compliance (yönetişim), Agent Runtime (yalıtım), Agent SRE (olay müdahalesi) |

---

## Güvenlik

AGT yönetişimi, işletim sistemi çekirdeği seviyesinde değil, uygulama ara katmanı seviyesinde zorlar. Politika motoru ve ajanlar aynı süreç sınırını paylaşır.

**Üretim önerisi:** İşletim sistemi seviyesinde yalıtım için her ajanı ayrı bir konteynerde çalıştırın. Bkz. [Mimari: Güvenlik Sınırları](../ARCHITECTURE.md).

| Araç | Kapsam |
|------|----------|
| CodeQL | Python + TypeScript SAST |
| Gitleaks | PR/push/haftalık gizli bilgi taraması |
| ClusterFuzzLite | 7 fuzz hedefi (politika, injection, MCP, sandbox, güven) |
| Dependabot | 13 ekosistem |
| OpenSSF Scorecard | Haftalık puanlama + SARIF yüklemesi |

Dürüst tasarım sınırları ve önerilen katmanlı savunma için [Bilinen Kısıtlar](../LIMITATIONS.md) dosyasına bakın.

---

## Dokümantasyon

| Kategori | Bağlantılar |
|----------|-------|
| **Başlangıç** | [Hızlı Başlangıç](./quickstart.tr.md) · [Öğreticiler](../tutorials/) (60+) · [SSS](../FAQ.md) |
| **Mimari** | [Sistem Tasarımı](../ARCHITECTURE.md) · [Tehdit Modeli](../security/threat-model.md) · [ADR'ler](../adr/) (29) |
| **Spesifikasyonlar** | [Tüm Spesifikasyonlar](../specs/) (10 resmi spesifikasyon, 992 uygunluk testi) |
| **API Referansı** | [Agent OS](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-os/README.md) · [AgentMesh](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-mesh/README.md) · [Agent SRE](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-sre/README.md) |
| **Uyumluluk** | [OWASP](../compliance/owasp-agentic-top10-architecture.md) · [EU AI Act](../compliance/) · [NIST AI RMF](../compliance/nist-ai-rmf-alignment.md) · [SOC 2](../compliance/soc2-mapping.md) · [AARM Extended](https://aarm.dev/builders/agent-governance-toolkit-microsoft) · [ATF](https://agentictrustframework.ai/ecosystem) |
| **Devreye Alma** | [Azure](../deployment/README.md) · [AWS](../deployment/README.md) · [GCP](../deployment/README.md) · [Docker Compose](../deployment/README.md) |
| **Eklentiler** | [VS Code](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-typescript/agent-os-vscode) · [Framework Integrations](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agentmesh-integrations) |

---

## Katkıda Bulunma

[Katkı Rehberi](https://github.com/microsoft/agent-governance-toolkit/blob/main/CONTRIBUTING.md) · [Topluluk](../COMMUNITY.md) · [Discord](https://discord.gg/TxMRqY3pFr) · [Güvenlik Politikası](https://github.com/microsoft/agent-governance-toolkit/blob/main/SECURITY.md) · [Değişiklik Günlüğü](https://github.com/microsoft/agent-governance-toolkit/blob/main/CHANGELOG.md)

**AGT kullanıyor musunuz?** Kurumunuzu [ADOPTERS.md](../ADOPTERS.md) dosyasına ekleyin.

## Yönetişim

| Belge | Amaç |
|----------|---------|
| [GOVERNANCE.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/GOVERNANCE.md) | Karar alma, roller, katkıcı basamakları |
| [CHARTER.md](../CHARTER.md) | Teknik tüzük (LF Projects formatı) |
| [MAINTAINERS.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/MAINTAINERS.md) | Bakımcılar ve kurumlar |
| [SECURITY.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/SECURITY.md) | Zafiyet bildirimi ve müdahale SLA'ları |
| [CODE_OF_CONDUCT.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/CODE_OF_CONDUCT.md) | Microsoft Açık Kaynak Davranış Kuralları |
| [ANTITRUST.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/ANTITRUST.md) | Katılımcılar için rekabet hukuku ilkeleri |
| [TRADEMARKS.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/TRADEMARKS.md) | Ticari marka kullanım politikası |

## Önemli Notlar

Agent Governance Toolkit'i üçüncü taraf ajan framework'leri veya servisleriyle çalışan uygulamalar geliştirmek için kullanıyorsanız, bunu kendi sorumluluğunuzda yaparsınız. Üçüncü taraf servislerle paylaşılan tüm verileri gözden geçirmenizi ve bu tarafların veri saklama süresi ile verinin bulunduğu konuma ilişkin uygulamalarının farkında olmanızı öneririz.

## Resmi Kaynaklar

Agent Governance Toolkit'in tek resmi kaynakları şunlardır:

| Kaynak | Konum |
|----------|----------|
| **Kaynak kod** | [github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) |
| **Dokümantasyon** | [microsoft.github.io/agent-governance-toolkit](https://microsoft.github.io/agent-governance-toolkit/) |
| **Python paketleri** | [pypi.org/user/agentgovtoolkit](https://pypi.org/user/agentgovtoolkit/) |
| **npm paketleri** | [npmjs.com](https://www.npmjs.com/) üzerinde `@microsoft/agent-governance-sdk` |
| **NuGet paketleri** | [nuget.org](https://www.nuget.org/) üzerinde `Microsoft.AgentGovernance.*` |
| **Rust crate'leri** | [crates.io](https://crates.io/) üzerinde `agent-governance`, `agent-governance-mcp` |

Proje ekibi, resmi olduğunu iddia eden üçüncü taraf web sitelerini, paketleri veya
dokümantasyon sitelerini ne yürütür ne de onaylar. Agent Governance Toolkit adını
kullanan şüpheli bir site veya paketle karşılaşırsanız, lütfen
[SECURITY.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/SECURITY.md)
dosyasında açıklanan kanallar üzerinden bildirin.

## Lisans

Bu proje [MIT Lisansı](https://github.com/microsoft/agent-governance-toolkit/blob/main/LICENSE) ile lisanslanmıştır.

## Ticari Markalar

Bu proje, projelere, ürünlere veya servislere ait ticari markalar ya da logolar içerebilir. Microsoft
ticari markalarının veya logolarının yetkili kullanımı
[Microsoft'un Ticari Marka ve Marka Yönergeleri](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general)
belgesine tabidir ve bu belgeye uymak zorundadır.
Bu projenin değiştirilmiş sürümlerinde Microsoft ticari markalarının veya logolarının kullanımı karışıklığa yol açmamalı ya da Microsoft sponsorluğu ima etmemelidir.
Üçüncü taraf ticari markalarının veya logolarının her türlü kullanımı, ilgili üçüncü tarafın politikalarına tabidir.
