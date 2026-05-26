# Wire-Protocol-Aware Policy Evaluation

AGT policy rules can now reference wire-level protocol semantics — not just HTTP
metadata — through **protocol facets**.  Facets are structured fields extracted
from raw protocol context (SQL queries, Kubernetes API paths, etc.) and merged
into the policy evaluation context before rules are evaluated.

## How it works

When `PolicyEngine.evaluate()` is called, it runs
`extract_protocol_facets(context)` before evaluating rules.  If the context
contains a `sql` or `k8s` sub-dict, the relevant parser populates structured
fields that YAML rules can reference with dot-notation conditions.

## SQL facets

Populate `context["sql"]["query"]` with a SQL statement.  The following fields
are extracted and available in policy conditions:

| Field | Example value | Description |
|---|---|---|
| `sql.verb` | `SELECT`, `DROP`, `DELETE` | Uppercase SQL verb |
| `sql.target` | `users` | Primary table/object being operated on |
| `sql.tables` | `orders,users` | Comma-joined list of all tables referenced |
| `sql.functions` | `COUNT,NOW` | Comma-joined list of SQL functions used |

**Requires `sqlglot`** (`pip install sqlglot`).  Without it, `sql.verb` is set
to `UNKNOWN` (fail-closed).

### Example rules

Each rule matches a single extracted field via `{field, operator, value}`.
Compound checks (e.g. verb + target) should be expressed as separate rules
with appropriate priorities.

```yaml
rules:
  - name: deny-destructive-sql
    condition: {field: "sql.verb", operator: in, value: ["DROP", "TRUNCATE", "DELETE"]}
    action: deny
    priority: 100

  - name: deny-schema-changes
    condition: {field: "sql.verb", operator: in, value: ["ALTER", "GRANT", "REVOKE"]}
    action: deny
    priority: 100

  - name: allow-read-only-sql
    condition: {field: "sql.verb", operator: eq, value: "SELECT"}
    action: allow
    priority: 5
```

### Example evaluation context

```python
engine.evaluate(
    agent_did="did:example:agent1",
    context={"sql": {"query": "DROP TABLE production"}},
)
```

## Kubernetes facets

Populate `context["k8s"]["method"]` (HTTP method) and `context["k8s"]["path"]`
(API server path).  The following fields are extracted:

| Field | Example value | Description |
|---|---|---|
| `k8s.verb` | `get`, `list`, `delete`, `create` | Kubernetes API verb |
| `k8s.resource` | `pods`, `deployments` | Resource type |
| `k8s.namespace` | `production` | Namespace (empty for cluster-scoped) |
| `k8s.name` | `mypod` | Resource name (empty for collection requests) |
| `k8s.subresource` | `exec`, `log` | Subresource (empty if none) |

HTTP methods are mapped to Kubernetes verbs:

| HTTP | Named resource | Collection |
|---|---|---|
| GET | `get` | `list` |
| DELETE | `delete` | `deletecollection` |
| POST | `create` | `create` |
| PUT | `update` | `update` |
| PATCH | `patch` | `patch` |

### Example rules

```yaml
rules:
  - name: deny-k8s-production-namespace
    condition: {field: "k8s.namespace", operator: eq, value: "production"}
    action: deny
    priority: 110

  - name: deny-k8s-exec
    condition: {field: "k8s.subresource", operator: eq, value: "exec"}
    action: deny
    priority: 100

  - name: deny-k8s-deletecollection
    condition: {field: "k8s.verb", operator: eq, value: "deletecollection"}
    action: deny
    priority: 100

  - name: allow-k8s-readonly
    condition: {field: "k8s.verb", operator: in, value: ["get", "list", "watch"]}
    action: allow
    priority: 5
```

### Example evaluation context

```python
engine.evaluate(
    agent_did="did:example:agent1",
    context={
        "k8s": {
            "method": "DELETE",
            "path": "/api/v1/namespaces/production/pods/mypod",
        }
    },
)
```

## Transparent proxy integration

The MCP proxy (`agentmesh proxy`) automatically populates wire-protocol context
from tool call arguments:

- Tool arguments named `query` or `sql` → `context["sql"]["query"]`
- Tool arguments named `method`/`http_method` + `path`/`api_path` starting with
  `/api/` or `/apis/` → `context["k8s"]`

No application changes are required.  Define SQL or K8s rules in your policy
file and they apply automatically to proxied tool calls.

## Adding custom protocol parsers

Register new protocol extractors via the module-level `default_registry`:

```python
from agentmesh.governance.protocol_facets import default_registry

def extract_redis_facets(redis_ctx: dict) -> dict:
    cmd = (redis_ctx.get("command") or "").upper()
    return {"verb": cmd, "key": redis_ctx.get("key", "")}

default_registry.register("redis", extract_redis_facets)
```

Then pass `{"redis": {"command": "FLUSHALL"}}` in the evaluation context and
write rules like:

```yaml
- name: deny-redis-flush
  condition: {field: "redis.verb", operator: in, value: ["FLUSHALL", "FLUSHDB"]}
  action: deny
```

See [`examples/policy-templates/wire-protocol-rules.yaml`](../examples/policy-templates/wire-protocol-rules.yaml)
for a full set of example rules.

## Language parity

The same facet model is available in the language SDKs. Each SDK exposes
`FacetRegistry`, `defaultRegistry`, and `extractProtocolFacets`, ships
`sql.*` and `k8s.*` extractors with the same field names, and runs the
extractors automatically inside policy evaluation.

| Language   | Module / package | Status |
|------------|------------------|--------|
| Python     | `agentmesh.governance.protocol_facets` | Shipped (#2553) |
| TypeScript | `@microsoft/agent-governance-sdk` → `protocol-facets` | Shipped (#2537) |
| Rust       | `agentmesh::protocol_facets` | Shipped (#2588) |
| .NET       | `agent-governance-dotnet` | Tracked in #2589 |
| Go         | `agent-governance-golang` | Tracked in #2590 |

### TypeScript usage

```ts
import {
  PolicyEngine,
  extractProtocolFacets,
  defaultRegistry,
} from '@microsoft/agent-governance-sdk';

const engine = new PolicyEngine();
engine.loadYaml(/* see agent-governance-typescript/examples/wire-protocol-rules.yaml */);

// Facets are extracted automatically inside evaluatePolicy() — you only need
// to populate the raw protocol context.
const decision = engine.evaluatePolicy('did:example:agent1', {
  sql: { query: 'DROP TABLE production' },
});
// decision.action === 'deny'

// Register a custom protocol extractor on the module-level registry:
defaultRegistry.register('redis', (ctx) => ({
  verb: String(ctx.command ?? '').toUpperCase(),
  key: String(ctx.key ?? ''),
}));
```

Rule conditions in the TypeScript SDK use the expression-string format
(`"sql.verb in ['DROP']"`) rather than the Python `{field, operator, value}`
dict form, but the available fields and decision outcomes are identical.

> **SQL parser note.** The TypeScript extractor uses a built-in regex
> tokenizer that handles the common verb / target / function cases used by
> policy rules. The Python implementation uses `sqlglot` for full AST
> parsing. For complex dialect-specific SQL, register a custom extractor
> backed by a full parser via `defaultRegistry.register('sql', ...)`.

### Rust usage

The Rust SDK exposes the same facet model under the
[`agentmesh::protocol_facets`](https://docs.rs/agentmesh) module:
`FacetRegistry`, `default_registry()`, `extract_protocol_facets`,
`extract_sql_facets`, `extract_k8s_facets`. The same `sql.*` and `k8s.*`
fields are surfaced, and `PolicyEngine::evaluate` invokes the registry on a
defensive copy of the caller's context before matching rules.

```rust
use agentmesh::{PolicyEngine, default_registry};
use serde_yaml::Value;
use std::collections::HashMap;

let engine = PolicyEngine::new();
engine.load_from_yaml(r#"
version: "1"
agent: "did:example:agent1"
policies:
  - name: deny-destructive-sql
    type: capability
    denied_actions: ["*"]
    conditions:
      sql.verb: [DROP, TRUNCATE, DELETE]
"#).unwrap();

let mut sub = serde_yaml::Mapping::new();
sub.insert(Value::String("query".into()), Value::String("DROP TABLE production".into()));
let mut ctx = HashMap::new();
ctx.insert("sql".to_string(), Value::Mapping(sub));

let decision = engine.evaluate("db.exec", Some(&ctx));
// decision == PolicyDecision::Deny(...)

// Register a custom protocol extractor:
default_registry().register("redis", |sub| {
    let mut m = std::collections::HashMap::new();
    if let Some(cmd) = sub.get(Value::String("command".into())).and_then(|v| v.as_str()) {
        m.insert("verb".to_string(), Value::String(cmd.to_uppercase()));
    }
    m
});
```

Rule conditions in the Rust SDK use the existing YAML mapping shape
(`key: value` or `key: [v1, v2]` for `in`-style membership). Field names
and decision outcomes are identical to the Python implementation.

> **SQL parser note.** The Rust extractor uses a built-in regex tokenizer
> that handles the common verb / target / function cases used by policy
> rules. For complex dialect-specific SQL, register a custom extractor via
> `default_registry().register("sql", ...)`.
