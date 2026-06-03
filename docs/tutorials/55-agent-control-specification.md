---
title: Agent Control Specification Tutorial
last_reviewed: 2026-06-02
owner: docs-team
---

# Tutorial 55: Agent Control Specification

> **Time**: 20 minutes · **Level**: Intermediate · **Prerequisites**: Python 3.11+, a repository checkout, and `opa` on `PATH`

## What you will build

This tutorial builds a small ACS policy enforcement point around an email tool. The host submits a complete snapshot to ACS before and after the tool call. ACS returns a verdict, and the host enforces it.

You will create:

- a flat ACS manifest
- a Rego policy bundle
- a Python host that calls `AgentControl.run_tool()`
- three outcomes: `allow`, `transform`, and `deny`

!!! important "Public Preview"
    ACS is vendored into AGT under `policy-engine/` as the AGT 5.0 policy layer. The APIs and manifest shape may change before GA.

## How ACS fits in AGT

ACS is the policy decision runtime. Your application or adapter is the policy enforcement point.

```text
Host adapter -> snapshot -> ACS runtime -> verdict -> host enforcement
```

ACS is stateless. The host supplies all context for every evaluation, including the intervention point, tool call, tool result, and any ambient labels or metadata.

## Step 1: Install the Python SDK from the repo

From the repository root:

```bash
cd policy-engine
python -m pip install ./sdk/python
```

The SDK distribution is named `agent-control-specification`. It builds the native Rust core with maturin when installed from source.

OPA-backed Rego examples require the `opa` CLI on `PATH`.

## Step 2: Create the tutorial workspace

```bash
mkdir -p /tmp/acs-email-tutorial/policy
cd /tmp/acs-email-tutorial
```

## Step 3: Write the ACS manifest

Create `manifest.yaml`:

```yaml
agent_control_specification_version: "0.3.1-beta"
metadata:
  name: acs-email-tutorial
policies:
  email_policy:
    type: rego
    bundle: ./policy
    query: data.agent_control_specification.email_policy.verdict
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: email_policy
  post_tool_call:
    policy_target: $.tool_result
    policy_target_kind: tool_result
    tool_name_from: $.tool_call.name
    policy:
      id: email_policy
tools:
  send_email:
    type: Tool
    id: send_email
    clearance: internal
```

The manifest binds the same Rego policy at two intervention points:

| Intervention point | What ACS evaluates |
| --- | --- |
| `pre_tool_call` | The outbound tool arguments before the email tool runs |
| `post_tool_call` | The tool result before it returns to the caller |

## Step 4: Write the Rego policy

Create `policy/email_policy.rego`:

```rego
package agent_control_specification.email_policy

import rego.v1

default verdict := {"decision": "allow"}

verdict := {
  "decision": "deny",
  "reason": "external_recipient_blocked",
  "message": "Messages to external recipients are blocked."
} if {
  input.intervention_point == "pre_tool_call"
  input.tool.name == "send_email"
  endswith(input.policy_target.value.to, "@example.net")
}

verdict := {
  "decision": "transform",
  "reason": "redact_tracking_token",
  "message": "Tracking token redacted before tool execution.",
  "transform": {
    "path": "$policy_target.body",
    "value": "Your case is ready. Tracking token: [REDACTED]"
  }
} if {
  input.intervention_point == "pre_tool_call"
  input.tool.name == "send_email"
  contains(input.policy_target.value.body, "TRACK-")
}
```

The policy returns:

| Input | Verdict |
| --- | --- |
| Normal internal email | `allow` |
| Internal email with a tracking token | `transform` |
| External `@example.net` recipient | `deny` |

## Step 5: Write the host

Create `run.py`:

```python
import asyncio
from pathlib import Path

from agent_control_specification import AgentControl, AgentControlBlocked

ROOT = Path(__file__).parent


async def send_email(args):
    return {"sent": True, "to": args["to"], "body": args["body"]}


async def main():
    control = AgentControl.from_path(str(ROOT / "manifest.yaml"))

    allowed = await control.run_tool(
        "send_email",
        {"to": "customer@example.com", "body": "Your case is ready."},
        send_email,
        tool_call_id="email-1",
    )
    print(allowed.value)

    transformed = await control.run_tool(
        "send_email",
        {
            "to": "customer@example.com",
            "body": "Your case is ready. Tracking token: TRACK-123",
        },
        send_email,
        tool_call_id="email-2",
    )
    print(transformed.value)

    try:
        await control.run_tool(
            "send_email",
            {"to": "partner@example.net", "body": "Hello."},
            send_email,
            tool_call_id="email-3",
        )
    except AgentControlBlocked as exc:
        print(exc.result.verdict.reason)


asyncio.run(main())
```

The host calls `run_tool()`. ACS evaluates `pre_tool_call`, the host runs the tool only if the verdict permits it, and ACS then evaluates `post_tool_call`.

## Step 6: Run it

```bash
python run.py
```

Expected output:

```text
{'sent': True, 'to': 'customer@example.com', 'body': 'Your case is ready.'}
{'sent': True, 'to': 'customer@example.com', 'body': 'Your case is ready. Tracking token: [REDACTED]'}
external_recipient_blocked
```

The second call proves the `transform` verdict changed the policy target before tool execution. The third call proves a `deny` verdict blocked the tool.

## Step 7: Inspect the policy input shape

ACS policies evaluate a canonical policy input. For the `pre_tool_call` point in this tutorial, the Rego policy sees fields like:

```json
{
  "intervention_point": "pre_tool_call",
  "policy_target": {
    "path": "$.tool_call.args",
    "kind": "tool_args",
    "value": {
      "to": "customer@example.com",
      "body": "Your case is ready."
    }
  },
  "tool": {
    "name": "send_email",
    "id": "send_email",
    "clearance": "internal"
  }
}
```

The exact input can include additional snapshot, annotation, and manifest-derived fields. The policy should read the canonical fields it needs and avoid depending on host-local state.

## Step 8: Try a fail-closed case

Change the manifest so `tool_name_from` points at a missing path:

```yaml
tool_name_from: $.tool_call.missing_name
```

Run the host again. ACS fails closed with a runtime error verdict instead of allowing the call.

This is the core ACS safety model: malformed manifests, missing paths, policy dispatcher failures, and invalid transform targets produce `deny` verdicts with reserved runtime-error reasons.

## Next steps

- Read the [Agent Control Specification package page](../packages/agent-control-specification.md).
- Compare Rego and Cedar in [OPA / Rego / Cedar Policies](08-opa-rego-cedar-policies.md).
- Add human review with [Approval Workflows](38-approval-workflows.md).
- Review policy composition with [Policy Composition](35-policy-composition.md).
