---
title: Chaos Testing Governed Agents
last_reviewed: 2026-07-12
owner: docs-team
---

# Chaos Testing Governed Agents

Chaos tests should exercise the same native ACS runtime and host controls used
in production.

## Setup

```python
from agt.policies import AdapterRuntimeSession, AgtRuntime

runtime = AgtRuntime("policies/chaos-manifest.yaml")
session = AdapterRuntimeSession(
    runtime,
    agent_id="chaos-agent",
    session_id="chaos-session",
)
```

## Latency injection

Delay the host tool implementation, then verify runtime timeouts, circuit
breakers, and audit remain correct. Policy evaluation still occurs before the
side effect.

## Tool failure

Return errors from the tool and call `evaluate_post_tool_call` with the error.
Verify the session charges the attempted call and subsequent evaluations see
the updated counter.

```python
pre = session.evaluate_pre_tool_call(
    tool_name="query_service",
    args={"query": "status"},
)
if pre.is_allowed():
    post = session.evaluate_post_tool_call(
        tool_name="query_service",
        args={"query": "status"},
        result=None,
        error="upstream timeout",
    )
```

## Budget pressure

Generate repeated attempts around the manifest limit. Include allowed, denied,
and runtime-error outcomes. Attempted calls count even when the policy denies
them.

## Approval failure

Use a manifest that can return `escalate`. Exercise approval success, denial,
timeout, suspension, and enforced-identity mismatch. The mismatch must fail
closed with `runtime_error:approval_action_mismatch`.

## Transform validation

Exercise transforms at input and output intervention points. Verify the host
uses `TransformResult.applied_value` and never publishes the unmediated value.

## Sandbox failure

Run provider tests with denied network defaults, filtered egress, resource
exhaustion, cancellation, and provider startup failure. Sandbox resources
belong in `SandboxConfig`; governance remains the optional `runtime=`.

## Assertions

- No side effect occurs before its pre-intervention evaluation.
- Public denial text does not expose policy or user detail.
- Audit records preserve verdict, reason code, identities, transform, evidence,
  and approval metadata.
- Session counters never move backward.
- Runtime and approval errors fail closed.

Use `agt test` for deterministic manifest replay and package-specific chaos
tests for host failures.
