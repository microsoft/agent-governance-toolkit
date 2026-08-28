---
title: "Hızlı Başlangıç"
last_reviewed: 2026-08-27
owner: agt-maintainers
---

> Bu belge [docs/quickstart.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/quickstart.md) dosyasının Türkçe çevirisidir. En güncel bilgi için İngilizce sürümü kontrol edin.

🌍 [English](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/quickstart.md) | [日本語](./quickstart.ja.md) | [简体中文](./quickstart.zh-CN.md) | [한국어](./quickstart.ko.md) | [Türkçe](./quickstart.tr.md)

# Hızlı Başlangıç

Politika için yerel bir ACS manifestosu, framework yaşam döngüsü aracılığı için de
bir Agent OS adaptörü kullanın.

## Kurulum

```bash
pip install agent-governance-toolkit[full]
```

## Başlangıç paketi oluşturma

```bash
python -m agent_os.cli.cmd_policy_gen \
  --template strict \
  --output policies/
agt lint-policy policies/manifest.yaml
```

Oluşturulan dizin `manifest.yaml` ve `policy.rego` dosyalarını içerir. Manifesto,
Rego politikasını yerel müdahale noktalarına bağlar.

## Bir araç çağrısını değerlendirme

```python
from agent_control_specification import AgentControl, HostSession

runtime = AgentControl.from_path("policies/manifest.yaml")
session = HostSession(
    runtime,
    agent_id="quickstart-agent",
    session_id="quickstart-session",
)

evaluation = session.pre_tool_call(
    tool_name="delete_file",
    args={"path": "report.txt"},
)

print(evaluation.verdict)
print(evaluation.reason_code)
```

Denenen araç çağrıları, reddedilenler de dahil olmak üzere, değerlendirmeden önce
hesaba yazılır. Çalışma zamanının kendisi oturum sayaçları tutmaz.

## Bir framework bağlama

```python
from agent_os.integrations.langchain_adapter import LangChainKernel

kernel = LangChainKernel(runtime=runtime)
```

Desteklenen her adaptör, yerel çalışma zamanını `runtime=` üzerinden alır. Politika
tanımları, engellenen içerik, araç katalogları, bütçeler, dönüştürmeler ve onay
akışı, adaptörün yapıcı metodunda değil manifestoda yer alır.

## Bir reddi ele alma

```python
from agent_os.exceptions import PolicyViolationError

if not evaluation.verdict.decision.permits:
    error = PolicyViolationError.from_evaluation_result(evaluation)
    print(str(error))
    print(error.evaluation_result.audit_record())
```

Genel (public) istisna metni sanitize edilmiştir. Güvenilir kod, yapılandırılmış
denetim ve yönlendirme için ekli `PolicyEvaluation` nesnesini kullanabilir.

## Sonraki adımlar

- [Agent Control Specification](../tutorials/55-agent-control-specification.md)
- [Framework entegrasyonları](../tutorials/03-framework-integrations.md)
- [Politika testi](../tutorials/policy-as-code/06-policy-testing.md)
- [Aşamalı yönetişim](../tutorials/progressive-governance.md)
