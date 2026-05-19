# Cedarling AgentMesh

Community integration package — connects [Cedarling](https://github.com/JanssenProject/jans/tree/main/jans-cedarling)
to AGT's `ExternalPolicyBackend` contract without modifying AGT core.

> **Community integration.** This package is maintained outside of `agent-os-kernel`
> so that Cedarling remains a fully optional, zero-impact dependency.

## Installation

```bash
# AGT integration adapter (required)
pip install cedarling_agentmesh

# Cedarling Python bindings (optional — fastest evaluation)
pip install cedarling_python

# Or point the backend at an existing Cedarling HTTP service — no extra package.
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
    ├── cedarling_python  (in-process, optional)
    └── HTTP service      (optional)
```

`agent-os-kernel` never imports this package. The integration is one-way.

## Quick Start

```python
from agent_os.policies import PolicyEvaluator
from cedarling_agentmesh import CedarlingBackend

evaluator = PolicyEvaluator()
evaluator.add_backend(
    CedarlingBackend(
        bootstrap_config={
            "application_name": "my-agent",
            "policy_store_uri": "https://example.com/cedarling/policies",
        }
    )
)

decision = evaluator.evaluate({"tool_name": "read_data", "agent_id": "agent-1"})
print(decision.allowed)   # True / False
```

HTTP service mode and JWT token forwarding:

```python
# HTTP service (no cedarling_python required)
evaluator.add_backend(
    CedarlingBackend(
        cedarling_url="http://cedarling.internal:8080",
        mode="http",
    )
)

# OIDC/JWT-aware evaluation
evaluator.add_backend(
    CedarlingBackend(
        bootstrap_config={"application_name": "my-agent", "policy_store_uri": "..."},
        tokens={"access_token": "<your-oidc-jwt>"},
    )
)
```

## Evaluation Modes

| Mode | Behaviour |
|------|-----------|
| `"auto"` (default) | Python bindings → HTTP (if `cedarling_url` set) → safe denial |
| `"python"` | Requires `cedarling_python` |
| `"http"` | Requires `cedarling_url`; no Python extras needed |

## Context Mapping

| AGT context key | Cedarling field |
|-----------------|-----------------|
| `agent_id` | `principal` entity id |
| `tool_name` | `action` (PascalCase, e.g. `"ReadData"`) |
| `resource` | `resource` entity id |
| all other keys | Cedar `context` attributes |

`request_id` and `diagnostics` from Cedarling are available in `BackendDecision.raw_result`.
