# Cedarling Governed Agent

Authorization for autonomous agents with [Cedarling](https://docs.jans.io/stable/cedarling),
plugged into the AGT ACS v5 runtime through its custom policy extension point
(no changes to AGT core). Cedarling evaluates Cedar policies **in-process**
against a local policy store.

The `CedarlingPolicyDispatcher` implements the
`agent_control_specification.PolicyDispatcher` protocol. The runtime hands it the
final policy input at each intervention point; it returns an ACS verdict. Passing
no dispatcher keeps the bundled `cedar` dispatcher; passing this one adds signed
stores, JWT/token principal resolution, and multi-issuer auth on top.

Two examples, one per authorization mode:

| Example | Mode | Identity comes from | Demonstrates |
|---------|------|---------------------|--------------|
| [`unsigned_example.py`](unsigned_example.py) | `unsigned` | the snapshot (`envelope.agent.id` + `attributes`) | role-based access control |
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
from the snapshot: `envelope.agent.id` becomes the principal and
`envelope.agent.attributes` (for example `{"role": "admin"}`) populate its entity
attributes. Policies check those attributes.

Expected output of `unsigned_example.py`:

```
[ALLOW] agent-analyst (role=admin) → pre_tool_call on read_data
         decision: allow  reason: allow-admin-tools
[DENY ] agent-guest (role=guest) → pre_tool_call on read_data
         decision: deny  reason: cedarling_deny
[ALLOW] agent-writer (role=admin) → pre_tool_call on delete_file
         decision: allow  reason: allow-admin-tools
[DENY ] agent-auditor (role=auditor) → pre_tool_call on delete_file
         decision: deny  reason: forbid-auditor-delete
```

The `reason` names the deciding Cedar policy id. Two permits, a default
denial (no policy applied, so the generic `cedarling_deny` code), and an
explicit forbid. Policies in [`policy-stores/unsigned/`](policy-stores/unsigned):

```
allow-admin-tools     : permit pre_tool_call on any Tool when principal.role == "admin"
forbid-auditor-delete : forbid pre_tool_call on Tool::"delete_file" when principal.role == "auditor"
```

---

## Multi-issuer authorization (capability-based)

The differentiator: a capability is the combination of **verified JWT claims**
and the **request context**, not a role the caller asserts about itself.

An operations agent manages infrastructure config. Whether it may write depends
on two things together: a `role` claim carried by a verified access token, and
the device posture passed as request context. An admin agent on a managed laptop
may write; the *same admin token* presented from an insecure device (a personal
mobile) may not, because the capability is revoked by context. Reading is allowed
from any device, and a non-admin token never writes. "Multi-issuer" because the
store may trust several issuers; policies reason over the claims they vouch for
plus the request context.

Expected output of `multi_issuer_example.py`:

```
[ALLOW] admin agent on managed laptop writes config → pre_tool_call on write_config (device=laptop)
         decision: allow  reason: allow-admin-write
[DENY ] admin agent on personal mobile writes config → pre_tool_call on write_config (device=mobile)
         decision: deny  reason: cedarling_deny
[ALLOW] admin agent on personal mobile reads config → pre_tool_call on read_config (device=mobile)
         decision: allow  reason: allow-admin-read
[DENY ] operator agent on managed laptop writes config → pre_tool_call on write_config (device=laptop)
         decision: deny  reason: cedarling_deny
[DENY ] admin agent deletes production (hard-blocked) → pre_tool_call on delete_prod (device=laptop)
         decision: deny  reason: forbid-prod-delete
```

The first two requests carry the *same admin token* and differ only in the
device context, so the weaker device drops the write capability. The fourth shows
the role gate: an operator token never writes. The fifth is an explicit forbid:
some tools are hard-blocked even for an admin token, and its reason names the
policy. Policies in
[`policy-stores/multi-issuer/`](policy-stores/multi-issuer):

```
allow-admin-read   : permit pre_tool_call on Tool::"read_config" when token role == "admin"
allow-admin-write  : permit pre_tool_call on Tool::"write_config" when token role == "admin" AND device != "mobile"
forbid-prod-delete : forbid pre_tool_call on Tool::"delete_prod" for any principal (hard block)
```

> The demo forges its own JWTs and runs with signature/status validation
> disabled so the claims are readable and no IdP is needed. In production these
> tokens come from your identity provider. Keep both validations **on**.

### Adding more issuers

The store trusts one issuer; "multi-issuer" means it can trust several. Drop
another file in `policy-stores/multi-issuer/trusted-issuers/`, add its
`<issuer>_access_token` field to the `Context` type in `schema.cedarschema`, and
place that token alongside the others in the snapshot token map:

```python
"snapshot": {
    "envelope": {
        "agent": {
            "id": "agent-ops",
            "tokens": {
                "AGT::Access_Token": "<jwt-from-issuer-a>",
                # "AGT::Id_Token":   "<jwt-from-issuer-b>",
            },
        }
    },
    "device": "laptop",
}
```

---

## Wiring into the runtime

The examples call `dispatcher.evaluate(...)` directly with a hand-built policy
input so they run without the native runtime. In a real host you bind a `custom`
policy to the dispatcher in the manifest and pass the dispatcher to
`AgentControl`. See [`manifest.yaml`](manifest.yaml):

```python
from agent_control_specification import AgentControl
from cedarling_acs import CedarlingConfig, CedarlingPolicyDispatcher

dispatcher = CedarlingPolicyDispatcher.from_bootstrap(
    {"CEDARLING_POLICY_STORE_LOCAL_FN": "policy-stores/unsigned"},
    config=CedarlingConfig(namespace="AGT"),
)
runtime = AgentControl.from_path("manifest.yaml", policy_dispatcher=dispatcher)
```

The runtime assembles the snapshot, resolves the policy target, and calls the
dispatcher. Its verdict drives enforcement at the `pre_tool_call` boundary.

## How a policy input maps to Cedar

The dispatcher receives the ACS final policy input under `invocation["input"]`
(the five members `intervention_point`, `policy_target`, `snapshot`,
`annotations`, `tool`) and builds a Cedar query. Defaults mirror the bundled
`cedar` dispatcher:

| Policy input source | Cedar field |
|---|---|
| `snapshot.envelope.agent.id` | `principal` entity id (`AGT::Agent`), unsigned only |
| `snapshot.envelope.agent.attributes` | principal entity attributes, unsigned only |
| `snapshot.envelope.agent.tokens` | JWTs keyed by Cedar entity type, multi-issuer only |
| `intervention_point` | `action` (`AGT::Action::"pre_tool_call"`) |
| `tool.name` | `resource` id (`AGT::Tool`) at tool points |
| `policy_target.kind` | `resource` id (`AGT::PolicyTarget`) at non-tool points |
| `snapshot` minus `envelope`, plus each annotation | Cedar `context` |

The `AGT::` prefix comes from `CedarlingConfig(namespace="AGT")`, matching the
namespace in each store's `schema.cedarschema`.

## Policy store layout

Each store under [`policy-stores/`](policy-stores) is a standard Cedarling local
store:

```
policy-stores/
├── unsigned/
│   ├── metadata.json                # store id / version
│   ├── schema.cedarschema           # entities + actions (Agent has a role)
│   └── policies/
│       ├── allow-admin-tools.cedar
│       └── forbid-auditor-delete.cedar
└── multi-issuer/
    ├── metadata.json
    ├── schema.cedarschema           # adds Access_Token entity + Context (tokens + device)
    ├── trusted-issuers/
    │   └── janssen.json             # the IdP whose tokens are trusted
    └── policies/
        ├── allow-admin-read.cedar
        ├── allow-admin-write.cedar
        └── forbid-prod-delete.cedar
```

Edit the `.cedar` files and re-run the examples to see decisions change.
Everything not explicitly permitted is denied by default.

## Using your own policy store

Point `CEDARLING_POLICY_STORE_LOCAL_FN` at a different directory (or a
policy-store JSON file). See the
[`cedarling-acs` README](../../agent-governance-python/agentmesh-integrations/cedarling-acs/README.md)
for the dispatcher and `CedarlingConfig` reference.
