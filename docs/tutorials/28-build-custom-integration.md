---
title: Build a Custom Integration
last_reviewed: 2026-07-12
owner: docs-team
---

# Build a Custom Integration

A custom framework integration owns host lifecycle behavior and delegates
policy evaluation to the native ACS runtime.

## Define the adapter

```python
from typing import Any

from agent_os.integrations.base import (
    AdapterExecutionState,
    BaseIntegration,
    get_adapter_runtime,
)


class ExampleKernel(BaseIntegration):
    def __init__(self, *, runtime: Any) -> None:
        super().__init__(runtime=runtime)
        self._adapter_runtime = get_adapter_runtime(runtime)

    def evaluate_input(
        self,
        context: AdapterExecutionState,
        body: str,
    ):
        return self._adapter_runtime.evaluate_input(context, body=body)

    def evaluate_tool(
        self,
        context: AdapterExecutionState,
        tool_name: str,
        arguments: dict[str, Any],
    ):
        return self._adapter_runtime.evaluate_pre_tool_call(
            context,
            tool_name=tool_name,
            args=arguments,
        )
```

Require `runtime=`. Do not accept inline policy objects, policy directories, or
compatibility result types.

## Mediate before side effects

Every public framework path must reach its pre-intervention evaluation before
calling the model, tool, network, filesystem, or output sink. Buffer streaming
output until the post check completes.

## Use the native result

`AdapterResult` exposes the native `PolicyEvaluation`, verdict, transform,
identities, sanitized public message, and canonical exception conversion.

```python
from agent_os.exceptions import PolicyViolationError

result = kernel.evaluate_tool(context, "write_file", {"path": "report.txt"})
if not result.allowed:
    raise result.to_policy_violation(PolicyViolationError)
```

## Session state

Use the shared adapter runtime seam so each framework session receives one
`AdapterRuntimeSession`. Synchronize host counters but do not duplicate native
attempted-call charging.

## Manifest contract

If the adapter requires specific intervention points, tool catalogs, approval,
or transforms, define an `AdapterManifestContract` and validate it before
execution.

## Tests

Cover:

- required constructor arguments
- allow, deny, transform, escalate, and runtime-error outcomes
- side-effect ordering
- streaming disclosure
- attempted-call and token accounting
- canonical exception identity
- sanitized public error text
- audit payload preservation

Add the adapter to `test_adapter_mediation_contract.py` so new public framework
paths cannot bypass native mediation.

See [Framework Integrations](03-framework-integrations.md) and the
[Framework Adapter Contract](../specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md).
