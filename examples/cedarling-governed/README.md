# Cedarling Governed Agent

Authorization for autonomous agents with [Cedarling](https://docs.jans.io/stable/cedarling),
plugged into AGT's `PolicyEvaluator` as an external policy backend (no changes
to AGT core). Cedarling evaluates Cedar policies **in-process** against a local
policy store.

Two examples, one per authorization mode:

| Example | Mode | Identity comes from | Demonstrates |
|---------|------|---------------------|--------------|
| [`unsigned_example.py`](unsigned_example.py) | `unsigned` | the request dict (`agent_id` + `principal_attributes`) | role-based access control |
| [`multi_issuer_example.py`](multi_issuer_example.py) | `multi-issuer` | verified JWTs from trusted issuers | capability-based authorization |

```bash
pip install -r requirements.txt
python unsigned_example.py
python multi_issuer_example.py
```

`cedarling-python` (pulled in by `requirements.txt`) evaluates the policies
in-process against the bundled stores in [`policy-stores/`](policy-stores).

---

## Unsigned authorization (role-based)

For internal services, background jobs, and test harnesses there is often no
token. In unsigned mode the principal's identity and attributes come straight
from the request dict — `agent_id` becomes the principal, `principal_attributes`
(e.g. `{"role": "admin"}`) populate its entity attributes — and policies check
those attributes.

Expected output of `unsigned_example.py`:

```
[ALLOW] agent-analyst (role=admin) → read_data on reports
         reason : Cedarling: allowed (unsigned)
[DENY ] agent-guest (role=guest) → read_data on reports
         reason : Cedarling: denied (unsigned)
[DENY ] agent-writer (role=admin) → write on db
         reason : Cedarling: denied (unsigned)
[DENY ] agent-auditor (role=auditor) → write on db
         reason : Cedarling: denied (unsigned)
```

The full decision spread: an explicit `permit`, two default denials, and an
explicit `forbid`. Policies in [`policy-stores/unsigned/`](policy-stores/unsigned):

```
allow-read   : permit Read/ReadData when principal.role == "admin"
forbid-write : forbid Write        when principal.role == "auditor"
```

---

## Multi-issuer authorization (capability-based)

The differentiator: a capability is the combination of **verified JWT claims**
and the **request context**, not a role the caller asserts about itself.

In the example an operations agent manages infrastructure config. Whether it may
*write* depends on two things together: a `role` claim carried by a verified
access token, and the device posture passed as request context. An admin agent
on a managed laptop may write; the *same admin token* presented from an insecure
device (a personal mobile) may not — the capability is revoked by context.
Reading is allowed from any device, and a non-admin token never writes.
"Multi-issuer" because the store may trust several issuers; policies reason over
the claims they vouch for plus the request context.

Expected output of `multi_issuer_example.py`:

```
[ALLOW] admin agent on managed laptop writes config → write on infra-config (device=laptop)
         reason : Cedarling: allowed (multi-issuer)
[DENY ] admin agent on personal mobile writes config → write on infra-config (device=mobile)
         reason : Cedarling: denied (multi-issuer)
[ALLOW] admin agent on personal mobile reads config → read_data on infra-config (device=mobile)
         reason : Cedarling: allowed (multi-issuer)
[DENY ] operator agent on managed laptop writes config → write on infra-config (device=laptop)
         reason : Cedarling: denied (multi-issuer)
```

The first two requests carry the *same admin token* and differ only in the
device context — write follows the capability, so a weaker device drops it. The
fourth request shows the role gate: an operator token never writes. Policies in
[`policy-stores/multi-issuer/`](policy-stores/multi-issuer):

```
allow-admin-read  : permit Read/ReadData when token role == "admin"
allow-admin-write : permit Write when token role == "admin" AND device != "mobile"
```

> The demo forges its own JWTs and runs with signature/status validation
> disabled so the claims are readable and no IdP is needed. In production these
> tokens come from your identity provider — keep both validations **on**.

### Adding more issuers

The store trusts one issuer; "multi-issuer" means it can trust several. Drop
another file in `policy-stores/multi-issuer/trusted-issuers/`, add its
`<issuer>_access_token` field to the `Context` type in `schema.cedarschema`, and
pass that token alongside the others in the per-request `tokens` dict:

```python
decision = evaluator.evaluate({
    "tool_name": "write",
    "resource": "infra-config",
    "device": "laptop",
    "tokens": {
        "AGT::Access_Token": "<jwt-from-issuer-a>",
        # "AGT::Id_Token":   "<jwt-from-issuer-b>",
    },
})
```

---

## What both examples show

- `CedarlingBackend` registered with `PolicyEvaluator.add_backend()` — zero
  modifications to `agent-os-kernel`.
- In-process Cedar evaluation against a real local policy store.
- The aggregated `PolicyDecision` — `allowed`, `action`, `reason`, plus the
  deciding `backend` and `evaluation_ms` on its `audit_entry`. (The backend's
  own `BackendDecision` also carries the Cedar `request_id` and matched-policy
  diagnostics in `raw_result`, available when you call `backend.evaluate()`
  directly.)

## How a request maps to Cedar

The backend translates each AGT request dict into a Cedar authorization query:

| AGT request key        | Cedar field                                                      |
|------------------------|------------------------------------------------------------------|
| `agent_id`             | `principal` entity id (`AGT::Agent`) — unsigned only             |
| `tool_name`            | `action` — snake_case → PascalCase (`read_data` → `ReadData`)    |
| `resource`             | `resource` entity id (`AGT::Resource`)                           |
| `principal_attributes` | principal entity attributes — **unsigned only**                  |
| `tokens`               | JWTs keyed by Cedar entity type — **multi-issuer only**          |
| any other key          | Cedar `context` attribute (also spread onto the resource entity) |

The `AGT::` prefix comes from the `namespace="AGT"` argument, which matches the
namespace declared in each store's `schema.cedarschema`.

## Policy store layout

Each store under [`policy-stores/`](policy-stores) is a standard Cedarling local
store:

```
policy-stores/
├── unsigned/
│   ├── metadata.json                # store id / version
│   ├── schema.cedarschema           # entity + action definitions (Agent has a role)
│   └── policies/
│       ├── allow-read.cedar
│       └── forbid-write.cedar
└── multi-issuer/
    ├── metadata.json
    ├── schema.cedarschema           # adds Access_Token entity + Context (tokens + device)
    ├── trusted-issuers/
    │   └── janssen.json             # the IdP whose tokens are trusted
    └── policies/
        ├── allow-admin-read.cedar
        └── allow-admin-write.cedar
```

Edit the `.cedar` files and re-run the examples to see decisions change —
everything that isn't explicitly permitted is denied by default.

## Using your own policy store

Point `CEDARLING_POLICY_STORE_LOCAL_FN` at a different directory (or a
policy-store JSON file). See the [`cedarling-agentmesh` README](../../agent-governance-python/agentmesh-integrations/cedarling-agentmesh/README.md)
for the full parameter reference.
