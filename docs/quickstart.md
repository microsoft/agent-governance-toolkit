---
title: Quickstart
last_reviewed: 2026-07-12
owner: docs-team
---

# Quickstart

Use a native ACS manifest for policy and an Agent OS adapter for framework
lifecycle mediation.

## Install

```bash
pip install agent-governance-toolkit[full]
```

## Create a starter bundle

```bash
python -m agent_os.cli.cmd_policy_gen \
  --template strict \
  --output policies/
agt lint-policy policies/manifest.yaml
```

The generated directory contains `manifest.yaml` and `policy.rego`. The
manifest binds the Rego policy to native intervention points.

## Evaluate a tool call

```python
from agt.policies import AdapterRuntimeSession, AgtRuntime

runtime = AgtRuntime("policies/manifest.yaml")
session = AdapterRuntimeSession(
    runtime,
    agent_id="quickstart-agent",
    session_id="quickstart-session",
)

evaluation = session.evaluate_pre_tool_call(
    tool_name="delete_file",
    args={"path": "report.txt"},
)

print(evaluation.verdict)
print(evaluation.reason_code)
```

Attempted tool calls are charged before evaluation, including denied attempts.
The runtime itself remains free of session counters.

## Attach a framework

```python
from agent_os.integrations.langchain_adapter import LangChainKernel

kernel = LangChainKernel(runtime=runtime)
```

Every supported adapter receives the native runtime through `runtime=`. Policy
definitions, blocked content, tool catalogs, budgets, transforms, and approval
belong in the manifest rather than the adapter constructor.

## Handle a denial

```python
from agent_os.exceptions import PolicyViolationError

if not evaluation.is_allowed():
    error = PolicyViolationError.from_evaluation_result(evaluation)
    print(str(error))
    print(error.evaluation_result.audit_record())
```

The public exception text is sanitized. Trusted code can use the attached
`PolicyEvaluation` for structured audit and dispatch.

## Next steps

- [Agent Control Specification](tutorials/55-agent-control-specification.md)
- [Framework integrations](tutorials/03-framework-integrations.md)
- [Policy testing](tutorials/policy-as-code/06-policy-testing.md)
- [Progressive governance](tutorials/progressive-governance.md)
