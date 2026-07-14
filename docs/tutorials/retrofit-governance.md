---
title: Retrofit Governance
last_reviewed: 2026-07-12
owner: docs-team
---

# Retrofit Governance

Add native ACS governance to an existing agent without moving policy logic into
the framework adapter.

## 1. Create the manifest

Start from a manifest under `examples/policy-templates/` or generate one with
the policy generator. Bind each policy to the intervention points the adapter
can mediate.

```bash
python -m agent_os.cli.cmd_policy_gen --template strict --output policies/
agt lint-policy policies/manifest.yaml
```

## 2. Construct the runtime

```python
from agt.policies import AgtRuntime

runtime = AgtRuntime("policies/manifest.yaml")
```

Runtime folder discovery is not supported. Resolve ACS `extends` before adapter
preflight or use a manifest chain through the native ACS SDK.

## 3. Attach the framework adapter

```python
from agent_os.integrations.langchain_adapter import LangChainKernel

kernel = LangChainKernel(runtime=runtime)
```

Use the adapter for the framework lifecycle. Do not pass inline rules, blocked
patterns, tool lists, or policy directories to adapter constructors.

## 4. Handle denials

```python
from agent_os.exceptions import PolicyViolationError

try:
    result = kernel.evaluate_input(context, "user request")
    if not result.allowed:
        raise result.to_policy_violation(PolicyViolationError)
except PolicyViolationError as error:
    print(str(error))
    audit_payload = error.evaluation_result.audit_record()
```

The public message is sanitized. The structured native evaluation remains
attached for trusted audit and dispatch code.

## 5. Add session and sandbox controls

`AdapterRuntimeSession` owns counters. `SandboxConfig` owns host resource,
network, filesystem, and tool-exposure settings. Keep both outside the manifest
policy interpreter.

## 6. Verify the retrofit

```bash
agt test policies/manifest.yaml policies/fixtures.json
pytest tests/
```

Exercise allow, deny, transform, escalate, and runtime-error paths that the
manifest binds. Verify every framework side effect occurs only after its
pre-intervention evaluation.

See [Framework Integrations](03-framework-integrations.md) and
[v4 policy-language removal](../v4-removal.md).
