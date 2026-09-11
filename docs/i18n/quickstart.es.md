---
# cspell:disable - Spanish translation; the shared dictionary is English-only.
title: Inicio rápido
last_reviewed: 2026-08-10
owner: agt-maintainers
---

🌍 [English](../quickstart.md) | [Español](./quickstart.es.md) | [日本語](./quickstart.ja.md) | [简体中文](./quickstart.zh-CN.md) | [한국어](./quickstart.ko.md) | [繁體中文](./quickstart.zh-TW.md)

# Inicio rápido

Usa un manifiesto ACS nativo para la política y un adaptador de Agent OS para la
mediación del ciclo de vida del framework.

## Instalación

```bash
pip install agent-governance-toolkit[full]
```

## Crear un paquete inicial

```bash
python -m agent_os.cli.cmd_policy_gen \
  --template strict \
  --output policies/
agt lint-policy policies/manifest.yaml
```

El directorio generado contiene `manifest.yaml` y `policy.rego`. El
manifiesto vincula la política de Rego con los puntos de intervención nativos.

## Evaluar una llamada a una herramienta

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

Los intentos de llamada a herramientas se contabilizan antes de la evaluación,
incluidos los intentos denegados. El runtime en sí permanece libre de contadores de sesión.

## Conectar un framework

```python
from agent_os.integrations.langchain_adapter import LangChainKernel

kernel = LangChainKernel(runtime=runtime)
```

Todos los adaptadores compatibles reciben el runtime nativo a través de `runtime=`. Las
definiciones de política, el contenido bloqueado, los catálogos de herramientas, los
presupuestos, las transformaciones y la aprobación pertenecen al manifiesto, no al
constructor del adaptador.

## Gestionar una denegación

```python
from agent_os.exceptions import PolicyViolationError

if not evaluation.verdict.decision.permits:
    error = PolicyViolationError.from_evaluation_result(evaluation)
    print(str(error))
    print(error.evaluation_result.audit_record())
```

El texto público de la excepción está saneado. El código de confianza puede usar la
`PolicyEvaluation` adjunta para auditoría estructurada y despacho.

## Siguientes pasos

- [Agent Control Specification](../tutorials/55-agent-control-specification.md)
- [Integraciones de frameworks](../tutorials/03-framework-integrations.md)
- [Pruebas de políticas](../tutorials/policy-as-code/06-policy-testing.md)
- [Gobernanza progresiva](../tutorials/progressive-governance.md)

<!-- cspell:enable -->
