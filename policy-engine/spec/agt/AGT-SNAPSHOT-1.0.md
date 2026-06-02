# AGT-SNAPSHOT-1.0.md — Per-intervention-point snapshot shape

**Status:** Draft. **Version:** `1.0.0-alpha`. **Normative for:** AGT host SDKs and the AGT stock Rego/Cedar libraries.

This document fixes the JSON shape of the snapshot AGT host SDKs build for each
intervention point. The snapshot is the input the engine sees at
`$snap` (and at `$.x`, which aliases to `$snap.x`). Without a fixed shape
AGT-authored Rego or Cedar rules cannot be portable across hosts; with this
document, a rule written against the AGT manifest works in any AGT SDK.

Engines themselves treat the snapshot as opaque — this document binds AGT
**hosts**.

## 1. Common envelope

Every snapshot MUST carry an `envelope`:

```jsonc
{
  "envelope": {
    "agent": { "id": "string", "version": "string", "name": "string" },
    "session": { "id": "string", "started_at": "ISO-8601 UTC" },
    "intervention_point": "agent_startup|input|...|agent_shutdown",
    "timestamp": "ISO-8601 UTC",
    "budgets": {
      "tool_call_count": 0,
      "token_count": 0,
      "elapsed_seconds": 0.0,
      "cost_usd": 0.0
    },
    "trace": { "trace_id": "string", "span_id": "string" },
    "tenant": { "id": "string", "name": "string" }
  }
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `envelope.agent.id` | yes | Stable agent identifier. |
| `envelope.session.id` | yes | Stable session identifier (matches v4 `ExecutionContext.session_id`). |
| `envelope.intervention_point` | yes | Mirrors the request's intervention point. Provided in snapshot so policies can write a single rule across multiple hooks. |
| `envelope.timestamp` | yes | When the snapshot was built. |
| `envelope.budgets` | yes | The host-tracked counter values **as of the start of this evaluation**. These are read-only inside the engine; the host increments them after `post_*` hooks. |
| `envelope.trace` | no | OpenTelemetry trace correlation. |
| `envelope.tenant` | no | Multi-tenant deployments. |

## 2. Per-intervention-point shapes

The remaining snapshot fields are intervention-point-specific. The shape table
is **closed**: an AGT host MUST emit exactly the fields below for each
intervention point.

### 2.1 `agent_startup`

```jsonc
{
  "envelope": { ... },
  "agent_init": {
    "capabilities": ["string"],
    "model": { "name": "string", "vendor": "string" },
    "tools_registered": ["string"]
  }
}
```

### 2.2 `input`

```jsonc
{
  "envelope": { ... },
  "input": {
    "body": "string | object",
    "source": "user|webhook|scheduled|other",
    "headers": { "<k>": "string" },
    "ifc": { "source_labels": ["string"] }
  }
}
```

The `input.ifc.source_labels` field is the IFC label-flow source labels per
ACS §11. Note the path: AGT stock IFC rules read `input.ifc.source_labels`
(at `input`) and `response.ifc.result_labels` (at `output`), not
`snapshot.ifc.*`. The AGT-correct IFC library is shipped as
`policy/lib/agt_ifc.rego` (package `data.agt.ifc`) and is the one AGT manifest
authors MUST import; the upstream `policy/lib/ifc.rego` (package
`agent_control_specification.lib.ifc`) is retained for callers that supply
the upstream snapshot shape.

### 2.3 `pre_model_call`

```jsonc
{
  "envelope": { ... },
  "model": {
    "name": "string",
    "vendor": "string",
    "params": { "temperature": 0.0, "max_tokens": 0 }
  },
  "messages": [
    { "role": "system|user|assistant|tool", "content": "string|object" }
  ],
  "tools": [{ "name": "string", "description": "string", "schema": {} }],
  "request_id": "string"
}
```

### 2.4 `post_model_call`

```jsonc
{
  "envelope": { ... },
  "model": { "name": "string", "vendor": "string" },
  "request_id": "string",
  "response": {
    "content": "string|object",
    "tool_calls": [{ "name": "string", "args": {} }],
    "finish_reason": "stop|length|tool_calls|content_filter|other"
  },
  "usage": { "prompt_tokens": 0, "completion_tokens": 0 }
}
```

### 2.5 `pre_tool_call`

```jsonc
{
  "envelope": { ... },
  "tool_call": {
    "name": "string",
    "args": {},
    "id": "string",
    "content_hash": "sha256:..."   // optional; matched against tools.<name>.content_hash by stock rule
  }
}
```

`tool_call.name` is the value referenced by `tool_name_from: "$.tool_call.name"`
in the manifest.

### 2.6 `post_tool_call`

```jsonc
{
  "envelope": { ... },
  "tool_call": {
    "name": "string",
    "args": {},
    "id": "string"
  },
  "tool_result": {
    "value": "any",
    "error": null,
    "duration_ms": 0.0
  }
}
```

### 2.7 `output`

```jsonc
{
  "envelope": { ... },
  "response": {
    "content": "string|object",
    "ifc": { "result_labels": ["string"] }
  },
  "message_chain": [{ "role": "...", "content": "..." }]
}
```

### 2.8 `agent_shutdown`

```jsonc
{
  "envelope": { ... },
  "summary": {
    "tool_calls": 0,
    "tokens": 0,
    "errors": 0,
    "duration_seconds": 0.0
  }
}
```

## 3. Snapshot stability and canonicality

A host MUST produce the same snapshot bytes for the same logical state. Object
keys MUST be emitted in lexicographic order. Floats follow ECMA-262 number
serialization. The snapshot MUST round-trip through JSON without loss.

This canonicality is the basis for the action-identity SHA-256 (ACS §13). Two
hosts on different SDKs that observe the same state MUST produce the same
action identity.

## 4. Schema artefacts

`policy-engine/spec/schema/snapshot/<intervention_point>.schema.json` exists
for each intervention point (M3 deliverable). The snapshot-builder helpers in
each SDK validate against these schemas in debug builds and skip the check in
release builds.

## 5. Versioning

The snapshot shape is versioned through the AGT manifest version (§2 of
`AGT-MANIFEST-1.0.md`). Shape changes are MAJOR-version events. Additive
optional fields are MINOR-version events.
