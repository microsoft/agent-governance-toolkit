---
title: Rego and Cedar in ACS
last_reviewed: 2026-11-21
owner: docs-team
---

# Rego and Cedar in ACS

ACS manifests declare Rego and Cedar policies under `policies`.

Rego policies reference a bundle and query. Cedar policies use the native
inline policy set or file fields defined by the manifest schema. Bind the
policy identifier at one or more intervention points.

## Cedar policies in a manifest

A Cedar policy declares `type: cedar` and exactly one of `policy_set` (inline
policy text) or `policy_path`, with optional `entities_path`, `schema_path` and
`query`:

```yaml
policies:
  refund_guard:
    type: cedar
    policy_set: |
      permit(principal, action, resource)
      when { principal.department == "finance" };
```

## The Python boundary

The native runtime's default policy dispatcher evaluates Rego only. A manifest
that declares a Cedar policy therefore fails at construction:

```
default policy dispatcher supports only Rego policies; policy 'refund_guard' uses engine 'cedar'
```

Cedar is evaluated where you decide to evaluate it. Supply a host dispatcher
implementing `PolicyDispatcher`, a protocol with a single synchronous
`evaluate(invocation)` that returns a decision mapping. `AgentControl.from_path`,
`from_url`, `from_manifest_chain` and `from_native` all accept
`policy_dispatcher=`.

```python
import cedarpy
from agent_control_specification import AgentControl


class CedarDispatcher:
    """Evaluates the manifest's Cedar policy set with cedarpy."""

    def __init__(self, policy_set: str, to_cedar):
        self._policy_set = policy_set
        self._to_cedar = to_cedar  # maps your payload onto a Cedar request

    def evaluate(self, invocation):
        request = self._to_cedar(invocation["input"])
        result = cedarpy.is_authorized(request, self._policy_set, [])
        return {"decision": "allow" if result.allowed else "deny"}


control = AgentControl.from_path("manifest.yaml", policy_dispatcher=CedarDispatcher(policy_set, to_cedar))
```

`evaluate` runs synchronously on the runtime thread, so it must not block on
remote calls. It receives the invocation the runtime built and returns a
decision mapping; the mapping from your payload's identity fields to
`principal`, `action`, `resource` and `context` is yours to define, which is
what `to_cedar` above isolates. Return `decision` as `allow`, `deny` or
`transform`. A policy may also express the intents `warn` and `escalate`: the
engine normalises `warn` to an allow carrying a `warnings` entry and `escalate`
to a deny carrying an `approval` block, so a final verdict never carries either
word (`SPECIFICATION.md` section 13.1).

A Cedar policy can carry an `advice` annotation. The
[cedar advice schema](https://github.com/microsoft/agent-governance-toolkit/blob/main/policy-engine/spec/schema/cedar_advice.schema.json)
defines the JSON it may hold, including the `warn`, `escalate` and `transform`
decisions a dispatcher can map onto a verdict. The `CedarDispatcher` above does
not read advice, so a policy that relies on it needs a dispatcher that does.

See the [manifest schema](https://github.com/microsoft/agent-governance-toolkit/blob/main/policy-engine/spec/schema/manifest.schema.json)
and [ACS specification](https://github.com/microsoft/agent-governance-toolkit/blob/main/policy-engine/spec/SPECIFICATION.md).
