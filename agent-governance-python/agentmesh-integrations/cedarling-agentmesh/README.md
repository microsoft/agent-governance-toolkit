# Cedarling AgentMesh

Community integration package — connects [Cedarling](https://github.com/JanssenProject/jans/tree/main/jans-cedarling)
to AGT's `ExternalPolicyBackend` contract without modifying AGT core.

> **Community integration.** This package is maintained outside of `agent-os-kernel`
> so that Cedarling remains a fully optional, zero-impact dependency.

## Installation

> **Status.** `cedarling-agentmesh` is not yet published to PyPI. Install it from source
> until a release is available. `cedarling-python` is published and pulled separately.

```bash
pip install -e .          # cedarling-agentmesh, from source (not yet on PyPI)
pip install cedarling-python
```

## Architecture

```
Your agent code
    │
    ▼
PolicyEvaluator (agent-os-kernel)
    │  add_backend()
    ▼
CedarlingBackend          ← this package
    │
    └── cedarling_python  (in-process, required)
```

`agent-os-kernel` never imports this package. The integration is one-way.

## Parameters

### `CedarlingBackend.__init__`

| Param | Default | Description |
|-------|---------|-------------|
| `bootstrap_config` | `None` | Dict passed to `cedarling_python.BootstrapConfig` |
| `application_name` | `"agent-governance-toolkit"` | Sets `CEDARLING_APPLICATION_NAME` in bootstrap |
| `namespace` | `None` | Cedar namespace prepended to entity types (e.g. `"AGT"` → `AGT::Agent`) |
| `auth_type` | `"unsigned"` | `"unsigned"` - no JWT tokens; `"multi-issuer"` - JWT tokens from one or more issuers |
| `principal_entity_type` | `"Agent"` | Cedar entity type for the principal |
| `resource_entity_type` | `"Resource"` | Cedar entity type for the resource |
| `action_namespace` | `"Action"` | Cedar namespace for actions (e.g. `"Action::\"ReadData\""`) |
| `cedarling_instance` | `None` | Pre-created `Cedarling` engine instance. If omitted, one is created from `bootstrap_config` |

### `evaluate(request)` request keys

| Key | Type | Purpose |
|-----|------|---------|
| `agent_id` | `str` | Principal entity ID (default: `"anonymous"`) |
| `tool_name` | `str` | Snake-case tool name, converted to PascalCase action (default: `"unknown"`) |
| `resource` | `str` | Resource entity ID (default: `""`) |
| `principal_attributes` | `dict` | **(unsigned only)** Attributes for the principal entity (e.g. `{"role": "admin"}`) |
| `tokens` | `dict[str, str]` | **(multi-issuer)** Mapping `entity_type_name` → JWT (e.g. `{"AGT::Access_Token": "<jwt>"}`) |
| any other key | any | Passed through to Cedar `context` (also spread into resource entity attributes) |

## Auth types

### Unsigned

Principal identity comes from `agent_id` plus optional `principal_attributes`.
Suitable for internal services, background jobs, or test harnesses.

```python
from agent_os.policies import PolicyEvaluator
from cedarling_agentmesh import CedarlingBackend

evaluator = PolicyEvaluator()
evaluator.add_backend(
    CedarlingBackend(
        namespace="AGT",
        auth_type="unsigned",
        bootstrap_config={
            "CEDARLING_POLICY_STORE_LOCAL_FN": "/path/to/policy-store",
        },
    )
)

decision = evaluator.evaluate({
    "tool_name": "read_data",
    "agent_id": "agent-42",
    "resource": "doc-1",
    "principal_attributes": {"role": "admin"},
})
print(decision.allowed)   # True / False
```

The policy store schema defines the principal entity with attributes:

```
namespace AGT {
    entity Agent = { role: __cedar::String };
    ...
}
```

Policies can then check `principal.role == "admin"`.

### Multi-issuer

Principal identity comes from JWT tokens. Each token is mapped to a Cedar
entity type via the `tokens` dict key (format: `"Namespace::EntityType"`).

```python
evaluator.add_backend(
    CedarlingBackend(
        namespace="Jans",
        auth_type="multi-issuer",
        bootstrap_config={
            "CEDARLING_POLICY_STORE_LOCAL_FN": "/path/to/multi-issuer-store",
        },
    )
)

decision = evaluator.evaluate({
    "tool_name": "update",
    "resource": "issue-456",
    "tokens": {
        "Jans::Access_Token": "<your-jwt>",
        "Jans::Id_Token": "<your-jwt>",
    },
})
print(decision.allowed)   # True / False
```

The mapping string must match an `entity_type_name` declared in the policy
store's `trusted_issuers` → `token_metadata` section.

## Request-to-Cedar Mapping

| AGT request key | Cedarling field |
|-----------------|-----------------|
| `agent_id` | `principal` entity id |
| `tool_name` | `action` (Snake-case tool name, converted to PascalCase action (e.g. "read_data" -> "ReadData")) |
| `resource` | `resource` entity id |
| `principal_attributes` | principal entity payload attributes (unsigned only) |
| all other keys | Cedar `context` attributes + resource entity payload |

`request_id` and `diagnostics` from Cedarling are available in `BackendDecision.raw_result`.
