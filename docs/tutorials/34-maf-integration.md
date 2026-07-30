---
title: Microsoft Agent Framework Integration
last_reviewed: 2026-07-12
owner: docs-team
---

# Microsoft Agent Framework Integration

The Agent OS MAF adapter mediates framework input and tool paths through a
native ACS runtime.

## Create the policy bundle

Use one of the runnable examples under `examples/maf-integration/` or generate a
starter bundle.

```bash
python -m agent_os.cli.cmd_policy_gen \
  --template strict \
  --output policies/
agt lint-policy policies/manifest.yaml
```

## Construct the adapter

```python
from agt.policies import AgtRuntime
from agent_os.integrations.maf_adapter import MAFKernel

runtime = AgtRuntime("policies/manifest.yaml")
kernel = MAFKernel(runtime=runtime)
```

Policy definitions, tool catalogs, budgets, prompt-injection rules, transforms,
and approval bindings belong in the manifest.

## Middleware

Attach the MAF middleware produced by the kernel to the framework pipeline. The
middleware must evaluate input and tool calls before invoking the next handler.
Denied evaluations raise the canonical `PolicyViolationError`.

## Audit

The adapter keeps host lifecycle audit separate from native policy evaluation.
Trusted audit code can record `PolicyEvaluation.audit_record()` while public
errors remain sanitized.

## Examples

- `examples/maf-integration/01-loan-processing/python/`
- `examples/maf-integration/02-customer-service/python/`
- `examples/maf-integration/03-healthcare/python/`
- `examples/maf-integration/04-it-helpdesk/python/`
- `examples/maf-integration/05-devops-deploy/python/`

Each example contains a native manifest and Rego policy.
