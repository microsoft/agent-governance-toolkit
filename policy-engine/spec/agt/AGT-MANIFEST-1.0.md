# AGT-MANIFEST-1.0.md — AGT manifest surface

**Status:** Draft. **Version:** `1.0.0-alpha`. **Supersedes:** none.

This document describes the full manifest surface AGT hosts author. An AGT
manifest is a strict superset of the ACS manifest defined in
`policy-engine/spec/SPECIFICATION.md`, with two additional top-level
sections owned by AGT.

The AGT host first resolves the manifest chain (folder discovery + scope
filter + merge) per `AGT-RESOLUTION-1.0.md`, then passes a single flat
manifest to the engine with `extends: []`.

## 1. Layout

```yaml
agent_control_specification_version: "0.3.0-alpha-agt"  # see §2
metadata: {...}                                          # free-form
extends: []                                              # AGT host pre-resolves; engine sees empty
policies: {...}                                          # ACS-defined; supports rego, cedar, test, custom
intervention_points: {...}                               # ACS-defined; 8 well-known keys
tools: {...}                                             # ACS-defined; AGT may add content_hash field
annotators: {...}                                        # ACS-defined; classifier | llm | endpoint

# ── AGT-extended top-level sections ──

approval: {...}                                          # see SPECIFICATION.md §24
limits: {...}                                            # see §3 below
```

## 2. Version identifier

AGT manifests MUST set `agent_control_specification_version` to a value of the
form `<acs-version>-agt[+<agt-rev>]`. Example: `0.3.0-alpha-agt`. The engine
strips the `-agt[...]` suffix before validating against the ACS version
constraint.

## 3. `limits` section

The `limits` section declares engine resource limits the runtime enforces per
ACS §15. It is normative to the engine.

```yaml
limits:
  max_snapshot_bytes: 1048576       # 1 MiB
  max_policy_input_bytes: 524288    # 512 KiB
  max_annotators_per_point: 16
  max_annotator_output_bytes: 65536
  max_extends_depth: 8              # host-resolution layer enforces
  max_intervention_points_per_run: 256
```

Defaults match the ACS reference defaults.

This section corresponds to ACS §15's "A host MAY configure those limits" and
is normative within the AGT manifest profile.

## 4. AGT additions to `tools`

`tools` entries accept all the ACS-defined fields (`clearance`,
`security_labels`, arbitrary host-defined fields) plus the AGT-defined fields
below:

| Field | Type | Meaning |
| --- | --- | --- |
| `content_hash` | string | SHA-256 of the tool implementation's source bytes. Verified at `pre_tool_call` by stock `content_hash.rego` when imported. |
| `mcp_origin` | object | `{ server: url, tool: name }` — links a tool entry to its MCP source for cross-reference. |

These fields are projected verbatim into `$pi.tool` at tool intervention
points.

## 5. AGT-managed annotator types

AGT hosts MAY register additional annotator types beyond ACS's `classifier`,
`llm`, `endpoint`. Custom types use the `endpoint` ACS type with a
discriminator in the entry's `type` member: `type: endpoint`, plus
`type_hint: drift_detector | semantic_classifier | <name>`.

The discriminator is informational. The runtime treats it as part of the
opaque annotator config.

## 6. Conformance

An AGT host conforms to this manifest profile when it:

1. Resolves manifest chains per `AGT-RESOLUTION-1.0.md` before calling the
   engine.
2. Passes the engine a flat manifest with `extends: []`.
3. Sets `agent_control_specification_version` per §2.
4. Supplies all ACS-required fields (`policies`, `intervention_points`).
5. MAY include `approval` and `limits` sections.
6. Honours the engine verdict per ACS §17, including the `transform` verdict
   per `SPECIFICATION.md` §14.

An engine that receives an AGT manifest is itself just an ACS engine; the
extra sections (`approval`, `limits`) are validated against this profile but
their semantics are documented in `SPECIFICATION.md` §24.

## 7. Examples

A minimal AGT manifest binding an OPA policy at `pre_tool_call`:

```yaml
agent_control_specification_version: "0.3.0-alpha-agt"
metadata:
  name: support-agent
policies:
  pii:
    type: rego
    bundle: ./policy
    data_paths: ["./policy/lib"]
    query: data.agt.support.pii_pretool
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args"
    policy_target_kind: tool_args
    tool_name_from: "$.tool_call.name"
    policy:
      id: pii
tools:
  send_email:
    clearance: confidential
    security_labels: [external]
    content_hash: "sha256:abc123..."
approval:
  default_resolver: webhook
  timeout_seconds: 120
  resolvers:
    webhook:
      type: webhook
      url: https://example.com/approve
limits:
  max_snapshot_bytes: 2097152
  max_annotators_per_point: 4
```
