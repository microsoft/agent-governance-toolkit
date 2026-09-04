# cedarling-acs

Cedarling policy dispatcher for the Agent Governance Toolkit ACS v5 runtime.

Connects [Cedarling](https://docs.jans.io/stable/cedarling/)
to AGT through the ACS v5 custom policy extension point without modifying AGT core.

> **Community integration.** This package is maintained outside the core runtime
> so that Cedarling stays a fully optional, zero-impact dependency. The runtime
> never imports it; the integration is one-way.

## Installation

```bash
pip install 'agent-governance-toolkit-integrations[cedarling]'
```

The `cedarling` extra pulls in `cedarling-python`. Without it, constructing the
dispatcher raises `ImportError` with install guidance.

## Architecture

```
Your host / adapter
    │
    ▼
agent_control_specification runtime (ACS v5 manifest)
    │  policy_dispatcher=
    ▼
CedarlingPolicyDispatcher      ← this package
    │
    └── cedarling_python  (in-process, required)
```

The runtime builds the policy input at each intervention point and calls the
dispatcher. Passing no dispatcher keeps the bundled `cedar` dispatcher; passing
this one replaces it for a `custom` policy bound to the `cedarling` adapter.

## Quick Start

Bind a `custom` policy to the dispatcher in the manifest:

```yaml
agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: cedarling_governed
policies:
  cedarling:
    type: custom
    adapter: cedarling
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: cedarling
```

Construct the dispatcher and pass it to the runtime:

```python
from agent_control_specification import AgentControl
from cedarling_acs import CedarlingConfig, CedarlingPolicyDispatcher

dispatcher = CedarlingPolicyDispatcher.from_bootstrap(
    {"CEDARLING_POLICY_STORE_LOCAL_FN": "policy-store/"},
    config=CedarlingConfig(namespace="AGT"),
)
runtime = AgentControl.from_path("manifest.yaml", policy_dispatcher=dispatcher)
```

## Configuration

### `CedarlingPolicyDispatcher.from_bootstrap`

| Param | Default | Description |
|-------|---------|-------------|
| `bootstrap_config` | `None` | Configuration values passed to `cedarling_python.BootstrapConfig` (for example `CEDARLING_POLICY_STORE_LOCAL_FN`) |
| `application_name` | `"agent-governance-toolkit"` | Sets `CEDARLING_APPLICATION_NAME` in the bootstrap |
| `config` | `CedarlingConfig()` | Request-mapping configuration below |

Already have an engine? Construct directly: `CedarlingPolicyDispatcher(engine, config=...)`.

### `CedarlingConfig`

| Field | Default | Description |
|-------|---------|-------------|
| `auth_type` | `"unsigned"` | `"unsigned"` uses a principal built from the snapshot; `"multi-issuer"` uses JWTs |
| `namespace` | `None` | Cedar namespace prepended to entity types (for example `"AGT"` gives `AGT::Agent`) |
| `principal_attributes_path` | `("envelope", "agent", "attributes")` | Snapshot path to the principal attribute map (unsigned only) |
| `principal_entity_type` | `"Agent"` | Cedar entity type for the principal |
| `resource_entity_type` | `"PolicyTarget"` | Cedar entity type at non-tool intervention points |
| `tool_entity_type` | `"Tool"` | Cedar entity type at tool intervention points |
| `action_namespace` | `"Action"` | Cedar namespace for actions (gives `Action::"<intervention_point>"`) |
| `token_paths` | `(("tokens",), ("envelope", "agent", "tokens"))` | Snapshot paths searched for the multi-issuer token map; first hit wins |
| `policy_store_pointer` | `None` | Optional URL recorded in the verdict `evidence.verification_pointers.policy_store` |

## Auth types

### Unsigned

The principal comes from the snapshot: `envelope.agent.id` is the id and
`envelope.agent.attributes` populate its entity attributes. Suitable for internal
services, background jobs, or test harnesses.

```python
dispatcher = CedarlingPolicyDispatcher.from_bootstrap(
    {"CEDARLING_POLICY_STORE_LOCAL_FN": "policy-store/unsigned"},
    config=CedarlingConfig(namespace="AGT", auth_type="unsigned"),
)
```

The store schema declares the principal with its attributes:

```
namespace AGT {
  entity Agent = { role: String };
  ...
}
```

Policies then check `principal.role == "admin"`.

### Multi-issuer

The principal comes from JWTs a trusted issuer vouches for. The dispatcher reads
the token map from the snapshot (`token_paths`) and passes each token to
Cedarling keyed by the Cedar entity type it maps to.

```python
dispatcher = CedarlingPolicyDispatcher.from_bootstrap(
    {
        "CEDARLING_POLICY_STORE_LOCAL_FN": "policy-store/multi-issuer",
        "CEDARLING_JWT_SIG_VALIDATION": "enabled",
        "CEDARLING_JWT_STATUS_VALIDATION": "enabled",
    },
    config=CedarlingConfig(namespace="AGT", auth_type="multi-issuer"),
)
```

The snapshot carries the tokens (default under `envelope.agent.tokens`):

```python
"snapshot": {
    "envelope": {"agent": {"id": "agent-ops", "tokens": {"AGT::Access_Token": "<jwt>"}}},
}
```

The token key must match an `entity_type_name` in the store's
`trusted-issuers` metadata.

## How a policy input maps to Cedar

The dispatcher receives the ACS final policy input under `invocation["input"]`
(the five members `intervention_point`, `policy_target`, `snapshot`,
`annotations`, `tool`) and builds a Cedar query. Defaults mirror the bundled
`cedar` dispatcher (spec section 12.4):

| Policy input source | Cedar field |
|---|---|
| `snapshot.envelope.agent.id` | `principal` entity id (`AGT::Agent`), unsigned only |
| `snapshot.envelope.agent.attributes` | principal entity attributes, unsigned only |
| `snapshot.envelope.agent.tokens` | JWTs keyed by Cedar entity type, multi-issuer only |
| `intervention_point` | `action` (`AGT::Action::"pre_tool_call"`) |
| `tool.name` | `resource` id (`AGT::Tool`) at tool points |
| `policy_target.kind` | `resource` id (`AGT::PolicyTarget`) at non-tool points |
| `snapshot` minus `envelope`, plus each annotation | Cedar `context` |

## Verdicts

| Cedarling outcome | Verdict |
|---|---|
| permit | `{"decision": "allow", "reason": "<permitting policy id>"}` |
| forbid | `{"decision": "deny", "reason": "<forbidding policy id>"}` |
| default deny (no policy applied) | `{"decision": "deny", "reason": "cedarling_deny"}` |
| `AuthorizeError` | `{"decision": "deny", "reason": "cedarling_authorization_error"}` |
| missing input, missing `cedarling-python`, other error | `{"decision": "deny", ...}` |

The `reason` is the first contributing Cedar policy id from the decision
diagnostics, sorted for determinism, so it names the actual policy for both
permit and forbid. The generic `cedarling_allow` / `cedarling_deny` codes appear
only when no policy contributed (a default deny). The full contributing list is
in `message`. Every failure path denies, and reasons never use the reserved
`runtime_error:` prefix, which belongs to the runtime.

## Migration from the v4 backend

The removed `cedarling-agentmesh` backend implemented the v4
`ExternalPolicyBackend` contract and registered with `BackendRegistry`. That
contract disappeared in v5. Replace `CedarlingBackend` +
`BackendRegistry.register(...)` with constructing `CedarlingPolicyDispatcher` and
passing it as `policy_dispatcher=`. Cedarling policy stores and `.cedar` files
carry over unchanged.
