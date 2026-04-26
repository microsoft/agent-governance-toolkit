# Tutorial 08 — OPA/Rego & Cedar Policy Backends

> **Package:** `agent-os-kernel` · **Time:** 35 minutes · **Prerequisites:** Python 3.10+

---

## What You'll Learn

- External policy backends for OPA/Rego and Cedar
- 3 evaluation modes: standalone, hybrid, and multi-backend
- Enterprise policy integration with existing infrastructure

---

The Agent Governance Toolkit ships with a declarative YAML policy engine that
covers most use cases out of the box.But enterprises rarely start from
scratch—they already have policy investments in [Open Policy Agent
(OPA)](https://www.openpolicyagent.org/) with Rego, or
[Cedar](https://www.cedarpolicy.com/) from AWS. Rather than force a rewrite,
the toolkit lets you **plug those existing policies straight into the same
evaluation pipeline** that powers YAML rules, so a single
`PolicyEvaluator.evaluate()` call can consult Rego files, Cedar statements, and
YAML documents together.

This tutorial walks through both backends end-to-end—from a five-line quick
start to production multi-backend deployments.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [Quick Start](#quick-start) | Evaluate a Rego policy in 5 lines |
| [OPA/Rego Backend](#oparego-backend) | Loading Rego files, package configuration, evaluation |
| [Three Evaluation Modes](#three-evaluation-modes) | Embedded engine, remote OPA server, built-in fallback |
| [Cedar Backend](#cedar-backend) | Cedar policy syntax, schema validation, compilation |
| [Cedar with AgentMesh](#cedar-with-agentmesh) | Trust-aware Cedar policies via `CedarEvaluator` |
| [BackendDecision](#backenddecision) | Normalized output format from any backend |
| [Combining Backends](#combining-backends) | Using OPA + Cedar + YAML together |
| [Migration Guide](#migration-guide) | Moving from YAML-only to OPA/Cedar |
| [Integration with PolicyEvaluator](#integration-with-agent-os-policyevaluator) | Cross-reference with Tutorial 01 |
| [Next Steps](#next-steps) | Where to go from here |

---

## Installation

The core packages include OPA and Cedar support with **zero mandatory
dependencies**—both backends ship built-in fallback evaluators that parse common
policy patterns without external tooling. Install the optional tools when you
need full language coverage.

```bash
# Core packages (built-in OPA/Cedar fallback included)
pip install agent-os-kernel           # Agent-OS policy engine
pip install agentmesh-platform        # AgentMesh governance layer

# Optional: full OPA support
# Install the OPA CLI — https://www.openpolicyagent.org/docs/latest/#running-opa
# Linux/macOS:
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod 755 ./opa && sudo mv opa /usr/local/bin/

# Optional: full Cedar support
pip install cedarpy                   # Python bindings to Rust Cedar engine
# Or install the Cedar CLI — https://github.com/cedar-policy/cedar
```

> **Note:** If neither the CLI tool nor the Python bindings are found, the
> backends automatically fall back to the built-in pattern evaluator. This
> handles common `default allow = false` / `permit(...)` / `forbid(...)`
> patterns and is perfect for development and testing.

---

## Quick Start

Evaluate a Rego policy in five lines:

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_rego(rego_content="""
package agentos
default allow = false
allow { input.tool_name == "web_search" }
allow { input.role == "admin" }
""")

decision = evaluator.evaluate({"tool_name": "web_search", "role": "analyst"})
print(decision.allowed)   # True — tool_name matches "web_search"
print(decision.reason)    # Explanation from the OPA backend
```

And a Cedar policy in five lines:

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_cedar(policy_content="""
permit(principal, action == Action::"ReadData", resource);
forbid(principal, action == Action::"DeleteFile", resource);
""")

decision = evaluator.evaluate({"tool_name": "read_data", "agent_id": "agent-1"})
print(decision.allowed)   # True — ReadData is permitted
```

Both methods return a standard `PolicyDecision` object (see
[Tutorial 01](./01-policy-engine.md)), so downstream code never needs to know
which backend made the call.

---

## OPA/Rego Backend

### Overview

`OPABackend` lives in `agent_os.policies.backends` and implements the
`ExternalPolicyBackend` protocol. It evaluates Rego policies and returns a
`BackendDecision`.

```python
from agent_os.policies.backends import OPABackend

backend = OPABackend(
    mode="local",                         # "remote" or "local"
    opa_url="http://localhost:8181",       # remote OPA server URL
    rego_path="./policies/agent.rego",    # path to .rego file
    rego_content=None,                    # or inline Rego string
    package="agentos",                    # Rego package name
    query=None,                           # explicit query (overrides package)
    timeout_seconds=5.0,                  # max evaluation time
)
```

### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | `Literal["remote", "local"]` | `"local"` | `"remote"` queries an OPA REST API; `"local"` uses the `opa eval` CLI or built-in fallback |
| `opa_url` | `str` | `"http://localhost:8181"` | Base URL of the OPA server (remote mode only) |
| `rego_path` | `str \| None` | `None` | Path to a `.rego` policy file |
| `rego_content` | `str \| None` | `None` | Inline Rego policy string (takes precedence over `rego_path` if both set) |
| `package` | `str` | `"agentos"` | Rego package name used to construct the default query |
| `query` | `str \| None` | `None` | Explicit Rego query; overrides automatic `data.<package>.allow` construction |
| `timeout_seconds` | `float` | `5.0` | Maximum wall-clock time for evaluation |

### Loading Rego Files

```python
# From a file on disk
backend = OPABackend(rego_path="./policies/production.rego")

# From an inline string
backend = OPABackend(rego_content="""
package agentos

default allow = false

# Allow web search for any agent
allow { input.tool_name == "web_search" }

# Admins can do anything
allow { input.role == "admin" }

# Block file deletion unconditionally
allow { input.tool_name != "file_delete" }
""")
```

### Package Configuration

The `package` parameter controls how the backend constructs the default Rego
query. If your Rego file declares `package myorg.security`, set
`package="myorg.security"` and the query becomes
`data.myorg.security.allow`:

```python
backend = OPABackend(
    rego_path="./policies/corp.rego",
    package="myorg.security",
)

# Equivalent to evaluating: data.myorg.security.allow
decision = backend.evaluate({"tool_name": "web_search"})
```

To use a fully custom query, pass `query` directly:

```python
backend = OPABackend(
    rego_path="./policies/corp.rego",
    query="data.myorg.security.is_permitted",
)
```

### Evaluation

Call `evaluate()` with a context dictionary. The context is passed to Rego as
`input`:

```python
context = {
    "tool_name": "execute_code",
    "agent_id": "agent-42",
    "role": "analyst",
    "token_count": 1500,
}

decision = backend.evaluate(context)
print(decision.allowed)        # bool
print(decision.reason)         # human-readable explanation
print(decision.backend)        # "opa"
print(decision.evaluation_ms)  # latency in milliseconds
```

### Writing Effective Rego for Agents

A minimal Rego policy for agent governance:

```rego
package agentos

default allow = false

# Allow read-only tools for all agents
allow {
    input.tool_name == "web_search"
}

allow {
    input.tool_name == "read_file"
}

# Admin agents bypass restrictions
allow {
    input.role == "admin"
}

# Block high-token requests from non-admin agents
deny {
    input.token_count > 8192
    input.role != "admin"
}
```

> **Tip:** The built-in fallback evaluator supports `default allow = false`,
> equality (`==`), inequality (`!=`), negation (`not`), and truthy checks on
> `input.*` paths. For more complex Rego (sets, comprehensions, built-in
> functions), install the OPA CLI or use a remote server.

---

## Three Evaluation Modes

`OPABackend` supports three ways to run Rego evaluation, tried in this order
when `mode="local"`:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  opa eval   │ ──▶ │  Built-in    │ ──▶ │  (error)        │
│  CLI found  │     │  Fallback    │     │                 │
└─────────────┘     └──────────────┘     └─────────────────┘
```

When `mode="remote"`, it posts directly to the OPA REST API:

```
┌─────────────────────────────────┐
│  POST http://host:8181/v1/data  │
└─────────────────────────────────┘
```

### Mode 1: Remote OPA Server

Query a running OPA instance via its REST API. Ideal for production
environments with centralized policy management.

```python
backend = OPABackend(
    mode="remote",
    opa_url="http://policy-server.internal:8181",
    package="agentos",
    timeout_seconds=3.0,
)

decision = backend.evaluate({"tool_name": "web_search", "agent_id": "agent-1"})
# Sends POST to http://policy-server.internal:8181/v1/data/agentos/allow
# with body: {"input": {"tool_name": "web_search", "agent_id": "agent-1"}}
```

Start an OPA server for development:

```bash
# Start OPA with a policy bundle
opa run --server --addr :8181 ./policies/

# Test manually
curl -X POST http://localhost:8181/v1/data/agentos/allow \
  -H "Content-Type: application/json" \
  -d '{"input": {"tool_name": "web_search"}}'
```

### Mode 2: Local `opa eval` CLI

Shells out to the `opa eval` command-line tool. No server required—each
evaluation is a subprocess call.

```python
backend = OPABackend(
    mode="local",
    rego_path="./policies/agent.rego",
    package="agentos",
)

# Runs: opa eval -d ./policies/agent.rego -i <input.json> "data.agentos.allow"
decision = backend.evaluate({"tool_name": "web_search"})
```

> **Performance note:** CLI mode incurs subprocess overhead (~50–200 ms per
> call). Use remote mode for latency-sensitive production workloads. The
> built-in fallback is faster for simple patterns.

### Mode 3: Built-in Fallback

When neither the OPA CLI nor a remote server is available, `OPABackend` falls
back to its built-in Rego parser. This handles the most common policy patterns
without any external dependencies:

```python
# No OPA CLI needed — the built-in evaluator handles this
backend = OPABackend(rego_content="""
package agentos
default allow = false
allow { input.tool_name == "web_search" }
allow { input.role == "admin" }
""")

decision = backend.evaluate({"tool_name": "web_search"})
print(decision.allowed)  # True
```

**Supported built-in patterns:**

| Pattern | Example |
|---------|---------|
| Default value | `default allow = false` |
| Equality | `allow { input.tool_name == "web_search" }` |
| Inequality | `allow { input.tool_name != "file_delete" }` |
| Negation | `allow { not input.is_blocked }` |
| Truthy check | `allow { input.is_admin }` |
| Nested paths | `allow { input.agent.role == "admin" }` |

**Not supported by built-in** (requires OPA CLI or remote server):

- Set comprehensions and aggregation
- Built-in Rego functions (`count`, `startswith`, `regex.match`, etc.)
- Partial rules and rule indexing
- Package imports

### Mode Comparison

| Feature | Remote Server | Local CLI | Built-in Fallback |
|---------|:------------:|:---------:|:-----------------:|
| Full Rego support | ✅ | ✅ | ❌ (common patterns only) |
| No external deps | ❌ | ❌ | ✅ |
| Sub-millisecond latency | ✅ | ❌ | ✅ |
| Policy hot-reload | ✅ | ❌ | ❌ |
| Centralized management | ✅ | ❌ | ❌ |
| Development/testing | ⭐ | ⭐ | ⭐⭐⭐ |
| Production workloads | ⭐⭐⭐ | ⭐ | ⭐⭐ |

---

## Cedar Backend

### Overview

`CedarBackend` lives in `agent_os.policies.backends` and evaluates
[Cedar](https://www.cedarpolicy.com/) authorization policies. Cedar's
permit/forbid model is a natural fit for agent governance: you declare what
actions are allowed and what are explicitly forbidden.

```python
from agent_os.policies.backends import CedarBackend

backend = CedarBackend(
    policy_path="./policies/agent.cedar",   # path to .cedar file
    policy_content=None,                     # or inline Cedar string
    entities_path=None,                      # path to entities JSON
    entities=None,                           # entities list
    schema_path=None,                        # path to Cedar schema
    mode="auto",                             # "auto", "cedarpy", "cli", "builtin"
    timeout_seconds=5.0,
)
```

### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `policy_path` | `str \| None` | `None` | Path to a `.cedar` policy file |
| `policy_content` | `str \| None` | `None` | Inline Cedar policy string |
| `entities_path` | `str \| None` | `None` | Path to Cedar entities JSON file |
| `entities` | `list[dict] \| None` | `None` | Entities list for authorization context |
| `schema_path` | `str \| None` | `None` | Path to Cedar schema file for validation |
| `mode` | `Literal["auto", "cedarpy", "cli", "builtin"]` | `"auto"` | Evaluation engine; `"auto"` tries cedarpy → CLI → builtin |
| `timeout_seconds` | `float` | `5.0` | Maximum wall-clock time for evaluation |

### Cedar Policy Syntax

Cedar policies use a declarative `permit`/`forbid` model:

```cedar
// Allow all agents to read data
permit(principal, action == Action::"ReadData", resource);

// Allow all agents to run web searches
permit(principal, action == Action::"WebSearch", resource);

// Forbid file deletion for all agents
forbid(principal, action == Action::"DeleteFile", resource);

// Forbid code execution
forbid(principal, action == Action::"ExecuteCode", resource);

// Catch-all: permit anything not explicitly forbidden
permit(principal, action, resource);
```

> **How tool names map to Cedar actions:** The backend converts `snake_case`
> tool names to `PascalCase` Cedar actions automatically. For example,
> `file_read` becomes `Action::"FileRead"`, and `execute_code` becomes
> `Action::"ExecuteCode"`.

### Evaluation

```python
backend = CedarBackend(policy_content="""
permit(principal, action == Action::"ReadData", resource);
forbid(principal, action == Action::"DeleteFile", resource);
""")

# ReadData is permitted
decision = backend.evaluate({"tool_name": "read_data", "agent_id": "agent-1"})
print(decision.allowed)   # True
print(decision.backend)   # "cedar"

# DeleteFile is forbidden
decision = backend.evaluate({"tool_name": "delete_file", "agent_id": "agent-1"})
print(decision.allowed)   # False
```

### Authorization Request Construction

When you call `evaluate(context)`, the `CedarBackend` internally builds a Cedar
authorization request using `_build_cedar_request()`:

```python
# Your context dict
context = {
    "agent_id": "agent-42",
    "tool_name": "read_data",
    "resource": "dataset-alpha",
}

# Internally constructed Cedar request:
# {
#     "principal": "Agent::\"agent-42\"",
#     "action": "Action::\"ReadData\"",
#     "resource": "Resource::\"dataset-alpha\"",
#     "context": { ... full context dict ... }
# }
```

### Schema Validation

Cedar schemas let you validate policies at compile time rather than runtime.
Supply a schema file to catch errors early:

```python
backend = CedarBackend(
    policy_path="./policies/agent.cedar",
    schema_path="./policies/agent.cedarschema",
)
```

Example Cedar schema:

```json
{
    "": {
        "entityTypes": {
            "Agent": {},
            "Resource": {}
        },
        "actions": {
            "ReadData": {
                "appliesTo": {
                    "principalTypes": ["Agent"],
                    "resourceTypes": ["Resource"]
                }
            },
            "WriteData": {
                "appliesTo": {
                    "principalTypes": ["Agent"],
                    "resourceTypes": ["Resource"]
                }
            },
            "DeleteFile": {
                "appliesTo": {
                    "principalTypes": ["Agent"],
                    "resourceTypes": ["Resource"]
                }
            }
        }
    }
}
```

### Cedar Evaluation Modes

Like `OPABackend`, Cedar supports multiple evaluation engines:

| Mode | Engine | When to use |
|------|--------|-------------|
| `"auto"` | Tries cedarpy → CLI → builtin | Default; auto-selects best available |
| `"cedarpy"` | Python bindings to Rust Cedar | Fastest; `pip install cedarpy` |
| `"cli"` | `cedar authorize` subprocess | Full Cedar support without Python bindings |
| `"builtin"` | Built-in pattern matcher | Zero dependencies; handles common permit/forbid patterns |

```python
# Force cedarpy (fastest, requires pip install cedarpy)
backend = CedarBackend(policy_content=policy, mode="cedarpy")

# Force CLI (requires cedar binary on PATH)
backend = CedarBackend(policy_content=policy, mode="cli")

# Force built-in (always available, limited pattern support)
backend = CedarBackend(policy_content=policy, mode="builtin")
```

### Entities

Cedar entities define the principals, resources, and their relationships. Pass
entities to give the Cedar engine richer authorization context:

```python
entities = [
    {
        "uid": {"type": "Agent", "id": "agent-42"},
        "attrs": {"role": "analyst", "team": "research"},
        "parents": [{"type": "Team", "id": "research-team"}],
    },
    {
        "uid": {"type": "Resource", "id": "dataset-alpha"},
        "attrs": {"classification": "internal"},
        "parents": [],
    },
]

backend = CedarBackend(
    policy_content='permit(principal, action == Action::"ReadData", resource);',
    entities=entities,
)

decision = backend.evaluate({
    "agent_id": "agent-42",
    "tool_name": "read_data",
    "resource": "dataset-alpha",
})
```

---

## Cedar with AgentMesh

The AgentMesh package provides its own Cedar evaluator at
`agentmesh.governance.cedar` with additional features for trust-aware,
multi-agent governance.

### CedarEvaluator

```python
from agentmesh.governance.cedar import CedarEvaluator, CedarDecision

evaluator = CedarEvaluator(
    mode="auto",                           # "auto", "cedarpy", "cli", "builtin"
    policy_path="./policies/mesh.cedar",   # path to .cedar file
    policy_content=None,                   # or inline Cedar string
    entities=None,                         # entities list
    entities_path=None,                    # path to entities JSON
    schema_path=None,                      # path to Cedar schema
    timeout_seconds=5.0,
)
```

Unlike the Agent-OS `CedarBackend`, `CedarEvaluator.evaluate()` takes an
explicit `action` string and a `context` dict:

```python
decision = evaluator.evaluate(
    action='Action::"ReadData"',
    context={
        "agent_did": "did:mesh:agent-42",
        "resource": "dataset-alpha",
        "trust_score": 0.92,
    },
)

print(decision.allowed)        # bool
print(decision.action)         # "Action::\"ReadData\""
print(decision.evaluation_ms)  # latency
print(decision.source)         # "cedarpy", "cli", "builtin", or "fallback"
print(decision.error)          # None if successful
```

### CedarDecision

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `bool` | Whether the policy permits the action |
| `raw_result` | `Any` | Raw response from the Cedar engine |
| `action` | `str` | The Cedar action that was evaluated |
| `evaluation_ms` | `float` | Evaluation latency in milliseconds |
| `source` | `Literal["cedarpy", "cli", "builtin", "fallback"]` | Which engine performed the evaluation |
| `error` | `str \| None` | Error message if evaluation failed |

### Trust-Aware Cedar Policies

Combine Cedar with AgentMesh trust scoring to create policies that adapt based
on agent reputation:

```python
from agentmesh.governance.cedar import CedarEvaluator
from agentmesh.governance.policy import PolicyEngine

engine = PolicyEngine()

# Load Cedar policies alongside YAML policies
engine.load_cedar(
    cedar_content="""
    permit(principal, action == Action::"Analyze", resource);
    permit(principal, action == Action::"ReadData", resource);
    forbid(principal, action == Action::"ExecuteCode", resource);
    """,
)

# Evaluate with agent DID and context
decision = engine.evaluate("did:mesh:agent-42", {
    "tool_name": "analyze",
    "trust_score": 0.85,
})
print(decision.allowed)  # True
```

### Loading Cedar into PolicyEngine

The helper function `load_cedar_into_engine()` registers a `.cedar` file with
an existing `PolicyEngine`:

```python
from agentmesh.governance.cedar import load_cedar_into_engine
from agentmesh.governance.policy import PolicyEngine

engine = PolicyEngine()
cedar_eval = load_cedar_into_engine(
    engine,
    cedar_path="./policies/mesh.cedar",
    entities=[
        {"uid": {"type": "Agent", "id": "agent-42"}, "attrs": {"role": "admin"}, "parents": []},
    ],
)
```

---

## OPA/Rego with AgentMesh

The AgentMesh package provides its own OPA evaluator at
`agentmesh.governance.opa` with the same trust-aware integration pattern.

### OPAEvaluator

```python
from agentmesh.governance.opa import OPAEvaluator, OPADecision

evaluator = OPAEvaluator(
    mode="local",                          # "remote" or "local"
    opa_url="http://localhost:8181",        # remote OPA server URL
    rego_path="./policies/mesh.rego",      # path to .rego file
    rego_content=None,                     # or inline Rego string
    timeout_seconds=5.0,
)
```

Unlike the Agent-OS `OPABackend`, `OPAEvaluator.evaluate()` takes an explicit
`query` string and an `input_data` dict:

```python
decision = evaluator.evaluate(
    query="data.agentmesh.allow",
    input_data={
        "agent": {"role": "admin", "did": "did:mesh:agent-42"},
        "action": {"type": "analyze"},
        "resource": {"id": "dataset-alpha"},
    },
)

print(decision.allowed)        # bool
print(decision.query)          # "data.agentmesh.allow"
print(decision.evaluation_ms)  # latency
print(decision.source)         # "remote", "local", or "fallback"
print(decision.error)          # None if successful
```

### OPADecision

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `bool` | Whether the policy permits the action |
| `raw_result` | `Any` | Raw response from the OPA engine |
| `query` | `str` | The Rego query that was evaluated |
| `evaluation_ms` | `float` | Evaluation latency in milliseconds |
| `source` | `Literal["remote", "local", "fallback"]` | How evaluation was performed |
| `error` | `str \| None` | Error message if evaluation failed |

### Loading Rego into PolicyEngine

```python
from agentmesh.governance.opa import load_rego_into_engine
from agentmesh.governance.policy import PolicyEngine

engine = PolicyEngine()
opa_eval = load_rego_into_engine(
    engine,
    rego_path="./policies/mesh.rego",
    package="agentmesh",
)
```

### AgentMesh Rego Patterns

Write Rego policies that leverage AgentMesh context fields:

```rego
package agentmesh

default allow = false

# Allow trusted agents to analyze data
allow {
    input.agent.role == "analyst"
    input.action.type == "analyze"
}

# Admins can do anything
allow {
    input.agent.role == "admin"
}

# Block cross-mesh requests from untrusted agents
deny {
    input.agent.trust_score < 0.5
    input.action.type == "export"
}
```

---

## BackendDecision

Both `OPABackend` and `CedarBackend` in Agent-OS return a `BackendDecision`—a
normalized dataclass that provides a consistent interface regardless of which
engine performed the evaluation.

```python
from agent_os.policies.backends import BackendDecision
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed` | `bool` | — | Whether the policy permits the action |
| `action` | `str` | `"allow"` | `"allow"` or `"deny"` |
| `reason` | `str` | `""` | Human-readable explanation of the decision |
| `backend` | `str` | `""` | Backend name: `"opa"` or `"cedar"` |
| `raw_result` | `Any` | `None` | Raw response from the backend engine |
| `evaluation_ms` | `float` | `0.0` | Evaluation latency in milliseconds |
| `error` | `str \| None` | `None` | Error message if evaluation failed |

### Usage

```python
from agent_os.policies.backends import OPABackend

backend = OPABackend(rego_content="""
package agentos
default allow = false
allow { input.tool_name == "web_search" }
""")

decision = backend.evaluate({"tool_name": "web_search"})

# Inspect the result
assert decision.allowed is True
assert decision.backend == "opa"
assert decision.error is None
print(f"Evaluated in {decision.evaluation_ms:.2f}ms")

# Access raw engine output if needed
if decision.raw_result:
    print(decision.raw_result)
```

### Error Handling

When evaluation fails (timeout, invalid policy, unreachable server), the
`BackendDecision` captures the error instead of raising an exception:

```python
backend = OPABackend(
    mode="remote",
    opa_url="http://unreachable-server:8181",
    timeout_seconds=2.0,
)

decision = backend.evaluate({"tool_name": "web_search"})
if decision.error:
    print(f"Evaluation failed: {decision.error}")
    print(f"Allowed defaulted to: {decision.allowed}")
```

### BackendDecision vs OPADecision vs CedarDecision

The toolkit has three decision types at different layers:

| Type | Package | Used by | Key differences |
|------|---------|---------|-----------------|
| `BackendDecision` | `agent_os.policies.backends` | `OPABackend`, `CedarBackend` | Normalized; feeds into `PolicyEvaluator` |
| `OPADecision` | `agentmesh.governance.opa` | `OPAEvaluator` | Includes `query` and `source` fields |
| `CedarDecision` | `agentmesh.governance.cedar` | `CedarEvaluator` | Includes `action` and `source` fields |

All three share the `allowed`, `raw_result`, `evaluation_ms`, and `error`
fields. The Agent-OS `BackendDecision` adds `action`, `reason`, and `backend`
for use in the `PolicyEvaluator` pipeline.

---

## Combining Backends

The real power of the toolkit is mixing policy formats. The `PolicyEvaluator`
evaluates YAML rules first (sorted by priority); if no YAML rule matches, it
consults external backends in registration order.

### Evaluation Order

```
PolicyEvaluator.evaluate(context)
    │
    ├─ 1. YAML/JSON rules (sorted by priority, highest first)
    │     └─ First matching rule → PolicyDecision (done)
    │
    ├─ 2. External backends (in registration order)
    │     ├─ OPABackend.evaluate(context) → BackendDecision
    │     ├─ CedarBackend.evaluate(context) → BackendDecision
    │     └─ First backend that returns a decision → PolicyDecision (done)
    │
    └─ 3. Default action (from PolicyDefaults)
          └─ PolicyDecision with defaults.action
```

### Example: YAML + OPA + Cedar

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()

# 1. Load YAML rules (evaluated first, highest priority wins)
evaluator.load_policies("./policies/yaml/")

# 2. Register OPA backend (consulted if no YAML rule matches)
evaluator.load_rego(
    rego_path="./policies/rego/agent.rego",
    package="agentos",
)

# 3. Register Cedar backend (consulted if OPA doesn't match either)
evaluator.load_cedar(
    policy_content="""
    permit(principal, action == Action::"ReadData", resource);
    forbid(principal, action == Action::"DeleteFile", resource);
    """,
)

# Evaluate — checks YAML → OPA → Cedar → defaults
decision = evaluator.evaluate({
    "tool_name": "read_data",
    "agent_id": "agent-42",
    "role": "analyst",
    "token_count": 500,
})

print(decision.allowed)
print(decision.matched_rule)  # Name of the rule/backend that decided
print(decision.reason)
```

### Using `add_backend()` Directly

For custom or third-party backends, use `add_backend()` instead of the
convenience methods:

```python
from agent_os.policies import PolicyEvaluator
from agent_os.policies.backends import OPABackend, CedarBackend

evaluator = PolicyEvaluator()

# Register backends manually
opa = OPABackend(rego_path="./policies/agent.rego", package="agentos")
cedar = CedarBackend(policy_path="./policies/agent.cedar")

evaluator.add_backend(opa)
evaluator.add_backend(cedar)

# Backends are consulted in registration order
decision = evaluator.evaluate(context)
```

### The ExternalPolicyBackend Protocol

Any class that implements the `ExternalPolicyBackend` protocol can be registered
as a backend:

```python
from agent_os.policies.backends import ExternalPolicyBackend, BackendDecision

class MyCustomBackend:
    """Custom policy backend—just implement name and evaluate()."""

    @property
    def name(self) -> str:
        return "my-custom"

    def evaluate(self, context: dict) -> BackendDecision:
        # Your evaluation logic here
        allowed = context.get("role") == "admin"
        return BackendDecision(
            allowed=allowed,
            action="allow" if allowed else "deny",
            reason="Admin check" if allowed else "Not an admin",
            backend=self.name,
        )

evaluator = PolicyEvaluator()
evaluator.add_backend(MyCustomBackend())
```

### Multi-Backend Strategy Patterns

#### Pattern 1: Defense in Depth

YAML for fast, simple rules; OPA for complex logic; Cedar for fine-grained
authorization.

```python
evaluator = PolicyEvaluator()

# Fast YAML rules catch obvious cases
evaluator.load_policies("./policies/quick-checks/")

# OPA handles complex cross-cutting rules
evaluator.load_rego(rego_content="""
package agentos
default allow = false
allow { input.role == "admin" }
allow {
    input.tool_name == "web_search"
    input.token_count < 4096
}
""")

# Cedar provides fine-grained resource-level authorization
evaluator.load_cedar(policy_content="""
permit(principal, action == Action::"ReadData", resource);
forbid(principal, action == Action::"WriteData", resource)
  when { resource.classification == "restricted" };
""")
```

#### Pattern 2: Migration Bridge

Run both old YAML and new OPA policies during migration; compare decisions in
audit logs:

```python
evaluator = PolicyEvaluator()
evaluator.load_policies("./policies/legacy-yaml/")
evaluator.load_rego(rego_path="./policies/new-rego/agent.rego")

decision = evaluator.evaluate(context)
# YAML rules still take precedence during migration
# Once validated, remove YAML files and let OPA handle everything
```

---

## Migration Guide

### Moving from YAML-Only to OPA/Cedar

If you're already using the YAML policy engine from
[Tutorial 01](./01-policy-engine.md), migrating to OPA or Cedar is
incremental—you don't have to rewrite everything at once.

### Step 1: Identify Rules to Migrate

Start with rules that are hard to express in YAML—complex conditions,
cross-field logic, or rules that reference external data:

```yaml
# This YAML rule is simple — keep it
- name: block-code-execution
  condition:
    field: tool_name
    operator: eq
    value: execute_code
  action: block
  priority: 100
  message: Code execution is blocked

# This logic is better expressed in Rego
# "Allow web_search only if token_count < 4096 AND role != 'intern'"
# YAML can't express AND conditions across fields
```

### Step 2: Write the Rego/Cedar Equivalent

**Rego version:**

```rego
package agentos

default allow = false

# Simple rules stay in YAML; complex ones go here
allow {
    input.tool_name == "web_search"
    input.token_count < 4096
    input.role != "intern"
}

allow {
    input.role == "admin"
}
```

**Cedar version:**

```cedar
// Permit web searches for non-intern agents
permit(
    principal,
    action == Action::"WebSearch",
    resource
) when {
    context.role != "intern" && context.token_count < 4096
};

// Admins get full access
permit(principal, action, resource)
  when { principal.role == "admin" };
```

### Step 3: Register Alongside Existing YAML

```python
evaluator = PolicyEvaluator()

# Keep existing YAML policies (they take priority)
evaluator.load_policies("./policies/yaml/")

# Add new OPA backend
evaluator.load_rego(rego_path="./policies/rego/agent.rego")

# Same evaluate() call — no downstream code changes
decision = evaluator.evaluate(context)
```

### Step 4: Validate and Remove YAML Gradually

Run both in parallel and compare decisions. Once you're confident the OPA/Cedar
policies produce identical results, remove the YAML equivalents:

```python
# Test helper to validate migration
def validate_migration(evaluator_yaml, evaluator_opa, test_contexts):
    for ctx in test_contexts:
        yaml_decision = evaluator_yaml.evaluate(ctx)
        opa_decision = evaluator_opa.evaluate(ctx)
        assert yaml_decision.allowed == opa_decision.allowed, (
            f"Mismatch for {ctx}: YAML={yaml_decision.allowed}, "
            f"OPA={opa_decision.allowed}"
        )
    print("✅ All decisions match — safe to remove YAML rules")
```

### YAML → Rego Cheat Sheet

| YAML Operator | Rego Equivalent |
|--------------|-----------------|
| `eq` | `input.field == "value"` |
| `ne` | `input.field != "value"` |
| `gt` | `input.field > value` |
| `lt` | `input.field < value` |
| `gte` | `input.field >= value` |
| `lte` | `input.field <= value` |
| `in` | `input.field == list[_]` |
| `contains` | `contains(input.field, "substr")` |
| `matches` | `regex.match("pattern", input.field)` |

### YAML → Cedar Cheat Sheet

| YAML Concept | Cedar Equivalent |
|-------------|-----------------|
| `action: allow` | `permit(principal, action, resource)` |
| `action: deny` | `forbid(principal, action, resource)` |
| `action: block` | `forbid(...)` with `advice("message")` |
| `field: tool_name` | `action == Action::"ToolName"` |
| `operator: eq` | `context.field == "value"` |
| `operator: ne` | `context.field != "value"` |
| Condition on field | `when { context.field == "value" }` |

---

## Integration with Agent OS PolicyEvaluator

This section connects the OPA/Cedar backends to the broader Agent-OS policy
engine covered in [Tutorial 01](./01-policy-engine.md).

### How PolicyEvaluator Uses Backends

The `PolicyEvaluator` class in `agent_os.policies.evaluator` orchestrates all
policy sources:

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()

# Native YAML policies
evaluator.load_policies("./policies/")

# External backends
evaluator.load_rego(rego_content="...")
evaluator.load_cedar(policy_content="...")

# Single evaluate() call handles everything
decision = evaluator.evaluate(context)
```

### PolicyDecision Output

Whether the decision came from a YAML rule, OPA, or Cedar, you always get back
a `PolicyDecision`:

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `bool` | Whether the action is permitted (default `True`) |
| `matched_rule` | `str \| None` | Name of the rule that fired, or `None` if defaults applied |
| `action` | `str` | Action taken: `"allow"`, `"deny"`, `"audit"`, or `"block"` |
| `reason` | `str` | Human-readable explanation |
| `audit_entry` | `dict` | Structured audit data (policy, rule, timestamp, context) |

```python
decision = evaluator.evaluate({
    "tool_name": "read_data",
    "agent_id": "agent-42",
    "token_count": 500,
})

if not decision.allowed:
    print(f"Blocked by: {decision.matched_rule}")
    print(f"Reason: {decision.reason}")
else:
    print(f"Allowed (rule: {decision.matched_rule})")
```

### Middleware Integration

When using the MAF (Microsoft Agent Framework) middleware stack, backends work
transparently:

```python
from agent_os.policies import PolicyEvaluator
from agent_os.integrations.maf_adapter import GovernancePolicyMiddleware

evaluator = PolicyEvaluator()
evaluator.load_policies("./policies/yaml/")
evaluator.load_rego(rego_path="./policies/rego/agent.rego")
evaluator.load_cedar(policy_path="./policies/cedar/agent.cedar")

middleware = GovernancePolicyMiddleware(evaluator=evaluator)
# Add to your agent's middleware stack — see Tutorial 01
```

### Complete Example: Production Setup

```python
from agent_os.policies import PolicyEvaluator
from agent_os.policies.backends import OPABackend, CedarBackend

# Create evaluator
evaluator = PolicyEvaluator()

# Layer 1: Fast YAML guardrails
evaluator.load_policies("./policies/guardrails/")

# Layer 2: OPA for complex business logic (remote server in production)
opa = OPABackend(
    mode="remote",
    opa_url="http://policy.internal:8181",
    package="agentos",
    timeout_seconds=3.0,
)
evaluator.add_backend(opa)

# Layer 3: Cedar for fine-grained resource authorization
cedar = CedarBackend(
    policy_path="./policies/cedar/authorization.cedar",
    entities_path="./policies/cedar/entities.json",
    schema_path="./policies/cedar/schema.cedarschema",
    mode="auto",  # cedarpy if available, else CLI, else builtin
)
evaluator.add_backend(cedar)

# Evaluate — YAML → OPA → Cedar → defaults
decision = evaluator.evaluate({
    "tool_name": "read_data",
    "agent_id": "agent-42",
    "role": "analyst",
    "resource": "dataset-alpha",
    "token_count": 1200,
})

print(f"Allowed: {decision.allowed}")
print(f"Rule: {decision.matched_rule}")
print(f"Reason: {decision.reason}")
```

---

## Next Steps

| Tutorial | What it covers |
|----------|---------------|
| [Tutorial 01 — Policy Engine](./01-policy-engine.md) | YAML policy syntax, operators, conflict resolution |
| [Tutorial 02 — Trust and Identity](./02-trust-and-identity.md) | Agent DIDs and trust scoring |
| [Tutorial 03 — Framework Integrations](./03-framework-integrations.md) | Wrapping LLM frameworks with governance |
| [Tutorial 04 — Audit and Compliance](./04-audit-and-compliance.md) | Audit trails and OWASP compliance |

### Explore Further

- **OPA Playground:** Test Rego policies at [play.openpolicyagent.org](https://play.openpolicyagent.org/)
- **Cedar Playground:** Test Cedar policies at [cedarpolicy.com/playground](https://www.cedarpolicy.com/en/playground)
- **Custom backends:** Implement `ExternalPolicyBackend` to integrate any policy engine
- **AgentMesh multi-backend:** Combine `PolicyEngine` with `OPAEvaluator` and `CedarEvaluator` for trust-aware governance

---

## Source Files

| Component | Location |
|-----------|----------|
| `ExternalPolicyBackend` protocol | `agent-governance-python/agent-os/src/agent_os/policies/backends.py` |
| `OPABackend` | `agent-governance-python/agent-os/src/agent_os/policies/backends.py` |
| `CedarBackend` | `agent-governance-python/agent-os/src/agent_os/policies/backends.py` |
| `BackendDecision` | `agent-governance-python/agent-os/src/agent_os/policies/backends.py` |
| `PolicyEvaluator` | `agent-governance-python/agent-os/src/agent_os/policies/evaluator.py` |
| `PolicyDecision` | `agent-governance-python/agent-os/src/agent_os/policies/evaluator.py` |
| `OPAEvaluator` | `agent-governance-python/agent-mesh/src/agentmesh/governance/opa.py` |
| `OPADecision` | `agent-governance-python/agent-mesh/src/agentmesh/governance/opa.py` |
| `CedarEvaluator` | `agent-governance-python/agent-mesh/src/agentmesh/governance/cedar.py` |
| `CedarDecision` | `agent-governance-python/agent-mesh/src/agentmesh/governance/cedar.py` |
| `PolicyEngine` | `agent-governance-python/agent-mesh/src/agentmesh/governance/policy.py` |
| OPA tests | `agent-governance-python/agent-mesh/tests/test_opa.py` |
| Cedar tests | `agent-governance-python/agent-mesh/tests/test_cedar.py` |

---

## Next Steps

- **Policy Engine:** [Tutorial 01 — Policy Engine](01-policy-engine.md)
- **Prompt Injection:** [Tutorial 09 — Prompt Injection Detection](09-prompt-injection-detection.md)
- **Compliance Verification:** [Tutorial 18 — Compliance Verification](18-compliance-verification.md)
