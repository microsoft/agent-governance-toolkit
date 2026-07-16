# Cedarling Governed Agent

This example demonstrates how you can perform authorization for autonomous agents with [Cedarling](https://docs.jans.io/stable/cedarling),
plugged into AGT's `PolicyEvaluator` as an external policy backend. This does not introduce any changes
to the AGT core.

Cedarling evaluates Cedar policies **in-process** against a local [Cedar policy](https://cedarpolicy.com/) store.

This document offers two runnable examples. 

| Demonstrates | Identity comes from | Cedarling mode | Example |
|--------------|---------------------|------|---------|
| Role-based access control | Authorization request data | `unsigned` | [`unsigned_example.py`](unsigned_example.py) |
| Token-based authorization | Verified JWTs from trusted issuers | `multi-issuer` | [`multi_issuer_example.py`](multi_issuer_example.py) |

## Install requirements

```bash
pip install -r requirements.txt
```

`cedarling-python` (pulled in by `requirements.txt`) evaluates the policies
in-process against the bundled stores in [`policy-stores/`](policy-stores).

## Role-based access control (Unsigned mode)

[`unsigned_example.py`](unsigned_example.py) implements typical RBAC authorization. This uses Cedarling's [unsigned mode of authorization](https://docs.jans.io/head/cedarling/reference/cedarling-authz/#unsigned-authorization-authorize_unsigned). In this case, the principal entity and it's attributes are provided by the application itself when it sends the request for authorization. 

In our example, the request supplied data 

- `agent_id` becomes the principal
- `principal_attributes`(e.g. `{"role": "admin"}`) populate its entity attributes 

[Policies used in this example](policy-stores/unsigned) are built to check the above attributes.
These policies effectively does the following:

```
allow-read   : permit Read/ReadData when principal.role == "admin"
forbid-write : forbid Write        when principal.role == "auditor"
```

Use command below to run the example:

```bash
python unsigned_example.py
```

Expected output:

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

## Token-based authorization (Multi-issuer mode)


This example demonstrates how you can implement [token-based](https://docs.jans.io/stable/cedarling/#proof-based-authorization-token-based-access-control-tbac) 
or token-based access control.

### Policies

In this example, users from the operations team are requesting authorization to read/update the infrastructure configuration. They may use their secure corporate devices or personal insecure devices to authenticate and perform the action.

[Policies](policy-stores/multi-issuer) are designed to consider a combination of user claims(role) and contextual data(device information) to `allow` or `deny` the authorization. Both of these inputs are extracted from the tokens.

| User role | Device info         | Action | Result |
| --------- | ------------------- | ------ | ------ |
| admin     | secure laptop       | write  | allow  |
| admin     | unidentified device | write  | deny   |
| admin     | personal mobile     | read   | allow  |
| operator  | secure laptop       | write  | deny   |

### Tokens to carry the context

Role and device data is extracted from the access token claims. Policies reason over the claims that the issuers have published in the token. Plus, the request context.
Refer to [TBAC](https://docs.jans.io/stable/cedarling/#proof-based-authorization-token-based-access-control-tbac) principles to understand the benefits.
 
This mode is called "Multi-issuer" mode because the policy store can be configured to trust tokens issued by several issuers. 

### Run the example

Use command below to run the example:

```bash
python multi_issuer_example.py
```

Expected output:

```
[ALLOW] admin agent on managed laptop writes config → write on infra-config (device=laptop)
         reason : Cedarling: allowed (multi-issuer)
[DENY ] admin agent on personal mobile writes config → write on infra-config (device=mobile)
         reason : Cedarling: denied (multi-issuer)
[DENY ] admin agent on an unidentified device writes config → write on infra-config (device=tablet)
         reason : Cedarling: denied (multi-issuer)
[ALLOW] admin agent on personal mobile reads config → read_data on infra-config (device=mobile)
         reason : Cedarling: allowed (multi-issuer)
[DENY ] operator agent on managed laptop writes config → write on infra-config (device=laptop)
         reason : Cedarling: denied (multi-issuer)
```

For the above output, the requests carried admin access tokens with device information in its 
claims. Based on this information, the second and third requests are denied as coming from an unmanaged 
device. The fifth request shows the role gate: an operator token never writes. 

See the complete policies at [`policy-stores/multi-issuer/`](policy-stores/multi-issuer). 
These policies effectively implement the following:

```
allow-admin-read  : permit Read/ReadData when token role == "admin"
allow-admin-write : permit Write when token role == "admin" AND device in {"laptop", "workstation"}
```

> Note:
> In absence of an IDP, this demo forges its own JWTs and runs with signature/status validation
> disabled so the claims are readable. In production these
> tokens come from your identity provider — keep both validations **on**.

### Adding more issuers

The store used in this example trusts one issuer. 

Follow the steps below to add additional issuers:

- Drop another file in `policy-stores/multi-issuer/trusted-issuers/`
- Add its `<issuer>_access_token` field to the `Context` type in `schema.cedarschema`
- Pass that token alongside the others in the per-request `tokens` dictionary

```python
decision = evaluator.evaluate({
    "tool_name": "write",
    "resource": "infra-config",
    "tokens": {
        "AGT::Access_Token": "<jwt-from-issuer-a>",
        # "AGT::Id_Token":   "<jwt-from-issuer-b>",
    },
})
```

## What both examples show

- `CedarlingBackend` registered with `PolicyEvaluator.add_backend()` without modifying
  the `agent-os-kernel`
- In-process Cedar evaluation against a real local policy store.
- The aggregated `PolicyDecision` — `allowed`, `action`, `reason`, plus the
  deciding `backend` and `evaluation_ms` on its `audit_entry`. (The backend's
  own `BackendDecision` also carries the Cedar `request_id` and matched-policy
  diagnostics in `raw_result`, available when you call `backend.evaluate()`
  directly.)

## How a request maps to Cedar

The backend translates each AGT request parameters into a Cedar authorization query:

| AGT request key        | Cedar field                                                      |
|------------------------|------------------------------------------------------------------|
| `agent_id`             | `principal` entity id (`AGT::Agent`) — unsigned only             |
| `tool_name`            | `action` — snake_case → PascalCase (`read_data` → `ReadData`)    |
| `resource`             | `resource` entity id (`AGT::Resource`)                           |
| `principal_attributes` | principal entity attributes — **unsigned mode only**                  |
| `tokens`               | JWTs keyed by Cedar entity type — **multi-issuer mode only**          |
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
    ├── schema.cedarschema           # Access_Token entity carries role + device claims as tags
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
