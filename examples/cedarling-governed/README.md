# Cedarling Governed Agent

Demonstrates how to integrate [Cedarling](https://github.com/JanssenProject/jans/tree/main/jans-cedarling)
with AGT's `PolicyEvaluator` using the `cedarling-agentmesh` community integration package.

AGT core is not modified — Cedarling is registered as an external policy backend
via `PolicyEvaluator.add_backend()`. The backend evaluates Cedar policies
**in-process** against the local policy store bundled in [`policy-store/`](policy-store).

## Run

```bash
pip install -r requirements.txt
python example.py
```

`cedarling-python` (pulled in by `requirements.txt`) evaluates the policies in-process against the bundled store.

Expected output:

```
Cedarling backend : 'cedarling'
Policy store       : .../examples/cedarling-governed/policy-store

[ALLOW] agent-analyst (role=admin) → read_data on reports
         reason : Cedarling: allowed (unsigned)
         backend: cedarling  timing: 0.68ms

[DENY ] agent-guest (role=guest) → read_data on reports
         reason : Cedarling: denied (unsigned)
         backend: cedarling  timing: 0.08ms

[DENY ] agent-writer (role=admin) → write on db
         reason : Cedarling: denied (unsigned)
         backend: cedarling  timing: 0.07ms

[DENY ] agent-auditor (role=auditor) → write on db
         reason : Cedarling: denied (unsigned)
         backend: cedarling  timing: 0.07ms
```

(Timings will vary.)

## What it shows

- `CedarlingBackend` registered with `PolicyEvaluator.add_backend()` — zero
  modifications to `agent-os-kernel`.
- In-process Cedar evaluation against a real local policy store.
- The full decision spread: an explicit `permit`, two default denials, and an
  explicit `forbid`.
- The aggregated `PolicyDecision` — `allowed`, `action`, `reason`, plus the
  deciding `backend` and `evaluation_ms` on its `audit_entry`. (The backend's
  own `BackendDecision` also carries raw Cedar diagnostics, matched policy ids
  in `raw_result`, available when you call `backend.evaluate()` directly.)

## How a request maps to Cedar

The backend translates each AGT request dict into a Cedar authorization query:

| AGT request key        | Cedar field                                                        |
|------------------------|--------------------------------------------------------------------|
| `agent_id`             | `principal` entity id (`AGT::Agent`)                               |
| `tool_name`            | `action` — snake_case → PascalCase (`read_data` → `ReadData`)     |
| `resource`             | `resource` entity id (`AGT::Resource`)                            |
| `principal_attributes` | principal entity attributes — **unsigned auth only**              |
| any other key          | Cedar `context` attribute (also spread onto the resource entity)   |

The `AGT::` prefix comes from the `namespace="AGT"` argument, which matches the
namespace declared in [`policy-store/schema.cedarschema`](policy-store/schema.cedarschema).

## The bundled policy store

[`policy-store/`](policy-store) is a standard Cedarling local store:

```
policy-store/
├── metadata.json          # store id / version
├── schema.cedarschema     # entity + action definitions (namespace AGT)
└── policies/
    ├── allow-read.cedar    # permit Read/ReadData when principal.role == "admin"
    └── forbid-write.cedar  # forbid Write when principal.role == "auditor"
```

Edit the `.cedar` files and re-run `example.py` to see decisions change —
everything that isn't explicitly permitted is denied by default.

## Using your own policy store

Point `CEDARLING_POLICY_STORE_LOCAL_FN` at a different directory (or a policy-store JSON file):

```python
backend = CedarlingBackend(
    namespace="AGT",
    auth_type="unsigned",
    bootstrap_config={
        "CEDARLING_POLICY_STORE_LOCAL_FN": "/path/to/your/policy-store",
    },
)
```

## Multi-issuer (JWT) auth

For production identity, switch to `auth_type="multi-issuer"` and pass JWTs
per-request via a `tokens` key. The mapping key must match an `entity_type_name`
declared in the policy store's trusted-issuer metadata:

```python
backend = CedarlingBackend(
    namespace="AGT",
    auth_type="multi-issuer",
    bootstrap_config={
        "CEDARLING_POLICY_STORE_LOCAL_FN": "/path/to/multi-issuer-store",
    },
)

decision = evaluator.evaluate({
    "tool_name": "read_data",
    "resource": "doc-1",
    "tokens": {"AGT::Access_Token": "<your-jwt>"},
})
```

See the [`cedarling-agentmesh` README](../../agent-governance-python/agentmesh-integrations/cedarling-agentmesh/README.md)
for the full parameter reference.
