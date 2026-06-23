# Agent Control Specification

This document specifies version `0.3.1-beta` of the Agent Control Specification (ACS). Its status is Draft.

The machine readable manifest contract is `schema/manifest.schema.json` in artifact kits and `spec/schema/manifest.schema.json` in this repository. That schema governs manifest syntax. This document governs runtime semantics, which are the evaluation order, the policy input shape, verdict handling, transform application, and fail closed behavior.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here. The references are listed in section 23.

## 1. Model

ACS evaluates one intervention point of one agent at a time. The host assembles a complete JSON snapshot for that intervention point and calls the runtime. The runtime selects the value under evaluation, attaches host supplied annotations, calls a host supplied policy dispatcher, normalizes the result into a verdict, and validates any transform the verdict carries. In enforce mode a `transform` verdict produces a transformed policy target.

The runtime computes verdicts and produces a transformed policy target. Acting on a verdict, by allowing, transforming, escalating, or refusing the action under control, happens at the host integration boundary defined in section 17. The ACS SDKs implement that boundary in their adapters, so a host that wraps an action in an adapter gets enforcement without writing it by hand.

### 1.1 Invariants

The runtime is stateless. It MUST NOT retain mutable state that influences a verdict from one evaluation to the next. State scoped to a single call and passed through the call stack is permitted. Process level and module level registries that influence a verdict are not.

The runtime is deterministic. Two evaluations with the same manifest, snapshot, mode, and dispatcher results MUST produce the same verdict and the same transformed policy target.

The runtime fails closed. Any error during evaluation MUST yield a `deny` verdict whose reason is one of the reserved identifiers in section 16. The runtime MUST NOT apply a transform on any path that ends in a runtime error.

Intervention point evaluation performs no input or output of its own. Network requests during evaluation, classifier and judge execution, policy engine execution, model calls, tool calls, stream assembly, and parallel dispatch belong to the host. File based manifest loading may perform bounded HTTPS fetches for URL `extends` during construction, and a loader may also fetch the top level manifest itself from an HTTPS URL as defined in section 2.3. The runtime and host exchange typed values through synchronous dispatcher interfaces.

### 1.2 Terminology

This section defines the terms this document uses with a specific meaning. Every other term carries its ordinary meaning.

**Host.** The application that embeds ACS. The host assembles snapshots, calls the runtime, supplies dispatchers, and acts on verdicts. The ACS SDK adapters run inside the host and perform that integration on its behalf.

**Runtime.** The stateless, deterministic engine defined by this document. The runtime computes a verdict and an optional transformed policy target and performs no input or output of its own.

**Snapshot.** The complete JSON document the host assembles for one intervention point. It is the only input the runtime reads about the agent and its environment.

**Intervention point.** A named place in the agent loop, such as `input`, `pre_tool_call`, or `output`, at which the host calls the runtime.

**Policy target.** The value selected from the snapshot that a policy evaluates and that a `transform` verdict may replace. The optional `policy_target_kind` is a descriptive label recorded on it.

**Annotation.** A value attached to the policy input under a named key. An annotator is the dispatcher that produces an annotation from host supplied or model supplied content.

**Policy.** A named decision rule bound to an intervention point. A dispatcher executes the policy and returns a result the runtime normalizes into a verdict.

**Dispatcher.** A host supplied synchronous interface the runtime calls to run an annotator or a policy. Dispatchers carry host trust and perform the input and output the runtime does not.

**Verdict.** The normalized decision the runtime returns, one of `allow`, `warn`, `deny`, `escalate`, or `transform`, together with a reason.

**Transform.** A replacement the runtime applies to the policy target, carried by a `transform` verdict, to produce the transformed policy target.

**Mode.** The binding setting of an evaluation request, either `enforce` or `evaluate_only`, defined in section 5.

## 2. Manifest

A manifest is a single YAML or JSON document. The schema rejects unknown top level properties.

| Property | Required | Meaning |
| --- | --- | --- |
| `agent_control_specification_version` | yes | Non empty version string. |
| `metadata` | no | Free form value the runtime does not interpret. |
| `extends` | no | Ordered array of parent manifest paths or HTTPS URLs, defined in section 2.2. |
| `policies` | yes | Map of named policy definitions, defined in section 12. |
| `intervention_points` | yes | Map of intervention point configurations, defined in section 4. |
| `tools` | no | Catalog of tools used for projection, defined in section 9. |
| `annotators` | no | Map of named annotator declarations, defined in section 10. |
| `approval` | no | Approval resolver declarations, defined in section 24. |

`policies` MUST contain at least one entry. `intervention_points` MUST contain at least one entry and MUST key its entries only by the names in section 4.

A manifest MUST be validated before any evaluation uses it. A manifest that fails validation MUST cause every evaluation to fail closed with `runtime_error:manifest_invalid`.

### 2.1 Version

`agent_control_specification_version` MUST be a non empty string. This document describes the value `0.3.1-beta`.

### 2.2 extends

`extends` is an ordered array of non empty parent references. A reference MAY be a string path, a string HTTPS URL, or an object with `url` and optional `integrity` or `sha256`. Existing string path entries remain valid. A file based loader resolves path entries relative to the including manifest and confines them to the directory tree rooted at the top level manifest. A file based loader resolves URL entries as HTTPS only, fetches them without ambient credentials, applies finite timeout, body size, and redirect limits, merges parents before children, and validates the merged manifest as a whole. Plain `http` and all non HTTPS URL schemes MUST fail closed. A URL whose host is a loopback or link-local IP address MUST fail closed, so the validated fetch URL cannot name the host itself or a cloud metadata endpoint such as `169.254.169.254`; RFC1918 private addresses remain allowed so internal HTTPS hosting keeps working. An IPv4-mapped or IPv4-compatible IPv6 literal MUST be canonicalized to its embedded IPv4 address before this check, so a form such as `[::ffff:169.254.169.254]` cannot route past the guard on a dual-stack host. This guard applies to IP literals only and is enforced on the initial fetch URL and on every redirect hop. The loader does not delegate redirect following to the HTTP client; it follows redirects itself and re runs each hop target through the same HTTPS and IP checks before following it, so a vetted public URL cannot bounce to plain HTTP or to a loopback, link-local, or cloud metadata host, and the redirect count stays capped. A host name that resolves into a blocked range and DNS rebinding are not revalidated by the runtime and remain host network responsibilities. URL entries without a hash pin are trusted because the host chose that URL. URL entries with `integrity` MUST use `sha256-<base64>` over the fetched bytes. URL entries with `sha256` MUST use a 64 character hexadecimal SHA-256 digest over the fetched bytes. A mismatch MUST fail closed. `integrity` and `sha256` MUST NOT appear together.

Merging is additive. A name defined in more than one manifest MUST be either identical in every manifest or non conflicting. Metadata object keys are merged additively, with nested object keys merged recursively when duplicate object values are non conflicting. For an intervention point, only its `annotations` may differ and are unioned. A conflicting duplicate definition MUST fail closed. Loading MUST also fail closed on a reference cycle, a missing file, a failed URL fetch, a URL body limit breach, or a version that differs between a parent and a child. A construction time load failure MAY surface by refusing to construct the runtime because no runtime exists yet to return an intervention verdict. A loader that parses an in memory string, including every FFI loader, cannot resolve `extends` against the file system or network. It may retain `extends` as data, but constructing an enforcing runtime from a manifest whose `extends` is non empty MUST fail closed, so such loaders MUST be given an already merged manifest.

An AGT host MAY pre-resolve `extends` host side before it constructs the runtime. The host side resolution algorithm, including its cycle, path traversal, governance validation, and merge conflict failures, is defined in [`spec/agt/AGT-RESOLUTION-1.0.md`](agt/AGT-RESOLUTION-1.0.md) and surfaces the `runtime_error:resolution_path_traversal`, `runtime_error:resolution_cycle`, `runtime_error:resolution_invalid_governance`, and `runtime_error:resolution_merge_conflict` reasons defined in section 16. The runtime itself receives an already merged manifest as required above.

### 2.3 Loading from a URL

A loader MAY fetch the top level manifest itself from an HTTPS URL rather than the file system. A URL load takes the URL and an optional `sha256` pin and applies the same fetch path and trust gate as a URL `extends` entry defined in section 2.2, so the fetch is HTTPS only, carries no ambient credentials, and is bounded by the same body size limit. The pin is optional, mirroring URL `extends`, where an unpinned URL is trusted because the host chose it. An unpinned top level URL provides no content integrity, so a host that needs integrity SHOULD supply a `sha256`. When a `sha256` is supplied it MUST be a 64 character hexadecimal SHA-256 digest over the fetched bytes and a mismatch MUST fail closed. A non HTTPS URL, a malformed or blank pin, a fetch error, or a body size breach MUST fail closed regardless of whether a pin is present. After the fetch the manifest is parsed, its own `extends` are resolved by the same loader, and the merged manifest is validated as a whole. A reference under a URL sourced manifest resolves against the URL, so a relative `extends` entry becomes a sibling URL. A URL sourced manifest has no file system manifest root, so it MUST NOT carry a filesystem path field. A rego `bundle`, an annotator `system_prompt_file`, a cedar `policy_path`, `entities_path`, or `schema_path`, or an adapter `data` or `data_paths` field MUST fail closed, because such a field would otherwise resolve against the process working directory at dispatch and let a remote manifest read local files. A URL sourced manifest references a remote prompt through the `system_prompt_url` form or supplies policy and prompt inline instead, and so never reaches the local file system. A URL sourced manifest also MUST NOT declare a rego `bundle_url`, because the bundled OPA dispatcher would run that remote rego with the host environment and network access, so attacker chosen rego could read a host secret through `opa.runtime` and exfiltrate it through `http.send`. The hash pin does not establish trust here because the same untrusted manifest chooses both the URL and the pin. The `bundle_url` form remains available to a file sourced manifest authored by the host operator. A URL sourced manifest also controls a dispatch endpoint, so it MUST NOT declare an annotator field that reads a host environment secret, namely `api_key_env` or an `aws_*_env` field, because a remote manifest could otherwise name a credential variable and exfiltrate it to a chosen endpoint. This restriction MUST be enforced on both the annotator declaration and the declaration overlaid with each intervention point binding, since a binding overlays its fields onto the declaration. Beyond the explicit fields, a bundled `llm` dispatcher serving a URL sourced manifest MUST NOT fall back to a host environment credential at dispatch, including a provider default credential variable such as `OPENAI_API_KEY` or `AWS_SESSION_TOKEN`, because that read carries no manifest field for a static scan to reject. Such a manifest supplies any credential inline.

## 3. Paths

Every path in a manifest starts with an explicit root and uses one fixed grammar. A `.name` segment selects an object member. A `[n]` segment selects a zero based array element and MUST NOT be negative. A `["name"]` segment selects an object member whose name contains a dot or a bracket. The runtime reads values without type coercion.

A required path that does not resolve MUST fail closed with `runtime_error:path_missing`. A path segment applied to an incompatible JSON type MUST fail closed with `runtime_error:path_type_mismatch`.

### 3.1 Roots

| Root | Resolves to |
| --- | --- |
| `$snap` | The raw host snapshot for the current intervention point. |
| `$` and `$.name` | Aliases that normalize to `$snap` and `$snap.name`. |
| `$pi` | The canonical policy input from section 7. |
| `$policy_target` | The value at `$pi.policy_target.value`. |
| `$tool` | The value at `$pi.tool`, which is `null` when no tool is projected. |

### 3.2 Allowed roots by field

| Field | Allowed roots |
| --- | --- |
| `policy_target` | `$snap`, `$`, `$.name` |
| `tool_name_from` | `$snap`, `$`, `$.name` |
| annotation `from` | `$pi` excluding `$pi.annotations`, `$policy_target`, `$tool`, `$snap`, `$`, `$.name` |
| `transform` `path` | `$policy_target` |

A manifest path that uses a root outside its allowed set MUST fail closed with `runtime_error:manifest_invalid`. A `transform` path outside `$policy_target` MUST fail closed with `runtime_error:transform_target_forbidden`. An annotation `from` path that reads `$pi.annotations` MUST fail closed with `runtime_error:manifest_invalid`, because annotator outputs do not exist when annotator inputs are resolved.

## 4. Intervention points

ACS defines eight intervention points. A request that names any other intervention point MUST fail closed with `runtime_error:intervention_point_unknown`.

| Intervention point | Position | Usual policy target |
| --- | --- | --- |
| `agent_startup` | Agent or session start. | Agent metadata. |
| `input` | Ingress of an external request. | User input or request payload. |
| `pre_model_call` | Before a model request is sent. | Model request. |
| `post_model_call` | After a model response returns. | Model response. |
| `pre_tool_call` | Before one concrete tool invocation. | Tool arguments. |
| `post_tool_call` | After one concrete tool invocation. | Tool result. |
| `output` | The assembled final response to the caller. | Final output. |
| `agent_shutdown` | Agent or session end. | Agent metadata or full snapshot. |

`pre_tool_call` and `post_tool_call` are the tool intervention points. They are the only points at which a tool is projected, and the only points where `tool_name_from` is valid.

### 4.1 Intervention point configuration

The schema rejects unknown members inside an intervention point entry. `policy_target` and `policy` are REQUIRED. `policy_target_kind`, `tool_name_from`, and `annotations` are OPTIONAL.

`policy_target` selects the value under evaluation from the snapshot and MUST use a snapshot root. `policy_target_kind`, when present, is a non empty descriptive label recorded on the policy target. `tool_name_from` selects the invoked tool name and is governed by section 9. `annotations` opts the point into named annotators and is governed by section 10. `policy` binds one policy and is governed by section 12.2.

## 5. Modes

An evaluation request carries one mode. In `enforce` mode the runtime applies the transform of a `transform` verdict and returns the transformed policy target. In `evaluate_only` mode the runtime runs the same pipeline and validates a `transform` verdict but applies none and returns no transformed policy target, which lets a host observe what the policy would decide without acting on it. The computed verdict, including `deny` and `escalate`, is the same in both modes. A runtime error fails closed to a `deny` verdict in both modes. Acting on a `deny` or an `escalate` verdict is the host obligation defined in section 17 and applies in `enforce` mode.

## 6. Evaluation order

For a request that carries an intervention point, a snapshot, and a mode, the runtime MUST perform the following steps in this order. A step that fails ends the evaluation and yields a `deny` verdict with the matching reserved reason. The canonical policy input built so far accompanies the result when one has been built.

1. Find the configuration for the named intervention point. An unknown name yields `runtime_error:intervention_point_unknown`.
2. Resolve `policy_target` against the snapshot to obtain the policy target value.
3. At a tool intervention point, resolve `tool_name_from` and project that tool from the catalog per section 9. At a non tool point the projected tool is `null`.
4. Build the preliminary policy input with an empty annotations object.
5. Collect annotations per section 10.
6. Build the final policy input with annotator outputs placed under `annotations`.
7. Resolve the bound policy, prepare a typed invocation, and call the policy dispatcher per section 12.
8. Normalize the dispatcher output into a verdict per section 13.
9. Validate the transform per section 14. When the decision is `transform` and the mode is `enforce`, apply it to the policy target and return the transformed policy target.

Annotation collection completes before the policy dispatcher is called. Transform handling runs after the verdict is normalized.

## 7. Policy input

The runtime builds one canonical policy input object. The preliminary form is the argument to each annotator. The final form is the argument to the policy dispatcher. The object has exactly five members.

```json
{
  "intervention_point": "pre_tool_call",
  "policy_target": {
    "kind": "tool_args",
    "path": "$snap.tool_call.args",
    "value": {}
  },
  "snapshot": {},
  "annotations": {},
  "tool": null
}
```

`intervention_point` is the name of the current intervention point. `policy_target.kind` is the configured `policy_target_kind` or `null`. `policy_target.path` is the configured `policy_target`. `policy_target.value` is the resolved policy target value. `snapshot` is the full raw snapshot. `annotations` is an empty object in the preliminary form and holds annotator outputs keyed by annotator name in the final form. `tool` is the projected tool object or `null`.

The policy input MUST contain exactly the members `intervention_point`, `policy_target`, `snapshot`, `annotations`, and `tool`. It MUST NOT contain a `request`, `resource`, or `tools` member.

## 8. Canonical serialization

When a stable string form of the policy input is required, the runtime sorts object members by name at every level and preserves array order. Scalar values are emitted unchanged. This form is the basis for any hash, cache key, or audit record derived from the policy input.

## 9. Tools

`tools` is a catalog keyed by tool name. The schema requires each entry to be an object and places no further constraint on its members. An entry MAY declare a `clearance` label, a `security_labels` array, and other host defined fields.

At a tool intervention point the runtime resolves `tool_name_from` to a string and projects the matching catalog entry into `tool`. A `tool_name_from` value that does not resolve to a string MUST fail closed. A tool name absent from the catalog MUST fail closed with `runtime_error:tool_unknown`. `tool_name_from` MUST NOT appear on a non tool intervention point, and a manifest that places it elsewhere MUST fail closed with `runtime_error:manifest_invalid`.

Tool call snapshots MAY carry `tool_call.id` as a caller supplied invocation identity. When present, hosts SHOULD preserve the same value across the surrounding `pre_tool_call` and `post_tool_call` evaluations. The field is not required by the runtime snapshot model.

## 10. Annotators

A top level `annotators` entry is a declaration whose `type` is `classifier`, `llm`, or `endpoint` and which MAY carry other host defined fields. A declaration does no work on its own.

An intervention point opts into an annotator by adding a member to `annotations` whose key is the annotator name. The key MUST name a declared annotator, and the member MUST carry a non empty `from` path. The runtime resolves each `from` path against the preliminary policy input and snapshot, then calls the host annotator dispatcher, which owns the network request, the classifier or judge call, caching, retries, and timeouts.

The runtime invokes the opted in annotators in ascending lexicographic order of annotator name. It places each output only under `annotations.<name>`. Annotator output MUST NOT overwrite or shadow `snapshot`, `policy_target`, `tool`, `intervention_point`, or any other root policy input member. An annotator output that is oversized, malformed, or contains a `reason` value with the reserved `runtime_error:` prefix MUST fail closed with `runtime_error:annotation_failed`. An annotator error MUST fail closed with `runtime_error:annotation_failed`. An annotator timeout MUST fail closed with `runtime_error:annotation_timeout`.

ACS defines no built in classifier or judge engine. Annotator execution is always host provided.

An implementation MAY ship host side default annotator dispatchers. A default `llm` dispatcher MAY provide provider presets for OpenAI compatible chat completions, Azure OpenAI chat completions, Amazon Bedrock Converse, Gemini `generateContent`, and Ollama chat. These presets MUST preserve runtime determinism by keeping network input and output outside pure decision logic. Provider credentials MUST come from explicit manifest fields or named environment variables. Provider responses MUST be normalized to a JSON annotation before policy execution. A malformed provider response, provider error, missing credential, missing label field, or invalid model JSON MUST fail closed as an annotator error. The normalized shape SHOULD include `label` and `raw` members, and a host MAY preserve a configurable `label_field` for model JSON.

A default `llm` dispatcher MAY read its system prompt from one of three sources. The inline `system_prompt` field, or its `prompt` alias, carries the prompt text directly. The `system_prompt_file` field names a manifest relative path that a file based loader rewrites relative to the directory of the declaring manifest using the same rule as a rego `bundle` path, and the dispatcher reads the file at evaluation time. Like a rego `bundle` path, the file source is not confined to the manifest directory, so an absolute or parent relative path is read as written. The `system_prompt_url` field is an object with a `url` member and a `sha256` or `integrity` pin that the dispatcher fetches over the extends fetch path and trust gate defined in section 2.2. At most one of these sources may be set, counting the annotator declaration merged with any intervention point annotation binding, and a manifest that sets more than one MUST fail closed with `runtime_error:manifest_invalid`. A `system_prompt_url` MUST use HTTPS and MUST declare a pin, so an unpinned or non HTTPS prompt URL MUST fail closed. A pinned fetch whose bytes do not match the pin, a fetch error, a body size breach, or a missing file MUST fail closed as an annotator error. When no source is set the dispatcher uses its preset default prompt.

## 11. Information flow control

ACS supports information flow control as a stateless label flow policy model. The runtime builds the canonical policy input and invokes the configured policy at each intervention point. The runtime performs no information flow control check, stores no label state, and propagates no taint between calls.

The host is the stateful policy enforcement point. The host MUST track provenance and labels as data flows through the agent loop. At each sink the host MUST call ACS with the labels of the data entering that sink. ACS intervention points are those sinks. Paths that bypass an intervention point are outside the ACS trust boundary.

The snapshot label convention is `input.snapshot.ifc.source_labels`. The value MUST be an array of label strings. Policies MUST treat a missing field, a non array value, an empty array, or an unknown label as a denial unless a host specific policy proves a lower sensitivity by other means.

Tool sink clearance is declared in the manifest tool catalog. A tool entry MAY set `clearance` to a single label that names the maximum sensitivity accepted by that sink. A tool entry MAY set `security_labels` to labels that describe the sink or capability. These fields are ordinary tool metadata and appear in the projected policy input as `input.tool.clearance` and `input.tool.security_labels`.

The reusable Rego library package `agent_control_specification.lib.ifc` defines the default lattice `public < internal < confidential < secret`. Integrators MAY pass an extended lattice data object to the library helpers. The library defines dominance over the lattice, maximum sensitivity over incoming labels, allow verdict helpers, and deny verdict helpers.

A no write down policy MUST deny a flow unless the sink clearance dominates every source label in `input.snapshot.ifc.source_labels`. If labels are incomparable, the comparison MUST fail closed. A policy emitted denial SHOULD use `reason` value `ifc_clearance_violation` with `decision` value `deny`.

This model follows established attribute and sink enforcement practice. ABAC and XACML provide labels as request attributes supplied by the policy enforcement point. OS information flow systems such as HiStar, Flume, and Asbestos enforce labels at sinks with labels carried on data. For LLM agents, CaMeL tracks data provenance and capabilities and enforces policy at tool call sinks.

## 12. Policies

### 12.1 Policy types

A `policies` entry is a named, reusable policy definition. The schema defines four types.

A `rego` policy targets Open Policy Agent. Its `query` and `bundle` members are optional in the schema. The runtime offers an optional bundled dispatcher that runs the `opa` executable when it is present, and the host MAY supply its own dispatcher instead. A `rego` policy MAY instead declare a `bundle_url` object with a `url` member and a `sha256` or `integrity` pin. The bundled dispatcher fetches that bundle over the extends fetch path and trust gate defined in section 2.2, verifies the pin, writes it to a dedicated temporary directory removed after evaluation, and passes the local path to `opa eval`. `bundle` and `bundle_url` are mutually exclusive, a `bundle_url` MUST use HTTPS and MUST declare a pin, and a non HTTPS URL, a missing pin, a fetch error, a body size breach, or a hash mismatch MUST fail closed. The fetched body is bounded by the same limit as URL extends.

A `cedar` policy targets the Cedar policy language. Its configuration, request mapping, and verdict mapping are defined in section 12.4. The runtime offers an optional bundled `cedar` dispatcher, and the host MAY supply its own dispatcher instead. `rego` and `cedar` are the two types with a bundled runtime execution path.

A `test` policy returns fixed verdicts for test doubles and is not a production engine.

A `custom` policy names a host adapter through its REQUIRED `adapter` member. It is the extension point through which a host adds any other backend.

ACS defines no other in manifest policy language.

### 12.2 Bindings

An intervention point binds one policy through `policy.id`. The binding MAY add a `query` and other host defined fields. The binding `id` MUST NOT be empty. A `rego` policy MUST have a query available on either the binding or the definition. A binding that names a policy not present in `policies` MUST fail closed with `runtime_error:manifest_invalid`.

### 12.3 Dispatcher boundary

The runtime prepares a typed invocation that carries the policy configuration and the final policy input, then passes it to the host policy dispatcher. The dispatcher owns policy execution and returns a verdict shaped JSON value. The runtime does not read a policy bundle or execute a policy language itself, apart from the optional bundled `opa` and `cedar` dispatchers. A dispatcher error MUST fail closed with `runtime_error:policy_invocation_failed`.

### 12.4 Cedar policy

A `cedar` policy targets the Cedar policy language (`https://www.cedarpolicy.com`). The policy definition carries the following fields.

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `type` | yes | string | MUST be `cedar`. |
| `policy_set` | exactly one of `policy_set` or `policy_path` | string | Inline Cedar policy text. |
| `policy_path` | exactly one of `policy_set` or `policy_path` | string | Filesystem path to a `.cedar` policy file or directory. |
| `entities_path` | no | string | Path to a Cedar entities JSON file. |
| `schema_path` | no | string | Path to a Cedar schema JSON file. |
| `query` | no | object | Cedar request template described below. |

A binding MAY add `principal`, `action`, `resource`, and `context` accessors that build the Cedar `Request` from the policy input. The Cedar runtime requires a `Request{principal, action, resource, context}`. The default mapping when no explicit binding is given is the following.

| Cedar field | Policy input source | Type |
| --- | --- | --- |
| `principal` | `$pi.snapshot.envelope.agent.id` resolved to `Agent::"<id>"` | `Agent` entity |
| `action` | The intervention point name mapped as `Action::"<ip>"` | `Action` entity |
| `resource` | `$pi.tool` projected as `Tool::"<name>"` at tool intervention points, otherwise `$pi.policy_target` projected as `PolicyTarget::"<kind>"` | entity |
| `context` | `$pi.snapshot` excluding the `envelope` block, plus each `$pi.annotations` entry keyed as `annotations.<name>` | record |

Hosts MAY override the mapping through the `query` member on either the policy definition or the binding. The source paths match the `envelope` shape in [`spec/agt/AGT-SNAPSHOT-1.0.md`](agt/AGT-SNAPSHOT-1.0.md).

Cedar's authorization result maps to a verdict. `Allow` maps to an `allow` verdict. `Deny` maps to a `deny` verdict whose `reason` is the first contributing policy id. A Cedar policy author MAY produce `warn`, `escalate`, or `transform` by attaching an `advice` annotation whose JSON matches this shape.

```json
{
  "verdict": "warn | escalate | transform",
  "reason": "<optional reason string>",
  "message": "<optional human message>",
  "transform": {"path": "$policy_target...", "value": "<any>"}
}
```

The dispatcher extracts the advice, validates it against [`spec/schema/cedar_advice.schema.json`](schema/cedar_advice.schema.json), and produces the corresponding verdict. Advice that does not match the schema MUST fail closed with `runtime_error:policy_output_invalid`. A `transform` advice without a `transform` body MUST fail closed with `runtime_error:transform_invalid`, and a `transform` advice whose `path` is outside `$policy_target` MUST fail closed with `runtime_error:transform_target_forbidden`.

The runtime offers an optional bundled `cedar` dispatcher that links the Cedar Rust crate when the `cedar` build feature is enabled. A host MAY supply its own dispatcher instead. A dispatcher error MUST fail closed with `runtime_error:policy_invocation_failed`.

## 13. Verdicts

A policy dispatcher returns a JSON object. The runtime normalizes it into a verdict with the following members.

| Member | Required | Type | Constraint |
| --- | --- | --- | --- |
| `decision` | yes | string | One of `allow`, `deny`, `warn`, `escalate`, `transform`. |
| `reason` | no | string | MUST NOT start with `runtime_error:`. |
| `message` | no | string | Free form text for a caller. |
| `transform` | required when `decision` is `transform`, forbidden otherwise | object | A `{path, value}` replacement rooted at `$policy_target` per section 14. |
| `evidence` | no | object | Offline verification evidence per section 13.3. |
| `result_labels` | no | array of strings | Information-flow labels for the data produced at this sink, returned verbatim to the host. See section 13.2. |

Normalization MUST fail closed with `runtime_error:policy_output_invalid` when the output is not an object, when `decision` is absent or is not one of the five values, when `reason` starts with the reserved `runtime_error:` prefix, when `reason` or `message` has the wrong JSON type, when `transform` is present while `decision` is not `transform`, when `transform` is absent while `decision` is `transform`, when `evidence` is present and is not an object, or when `result_labels` is present and is not an array of strings.

### 13.1 Decisions

`allow` permits the action with no change to the policy target. `warn` permits the action with no change to the policy target and records a warning. `transform` permits the action and replaces the policy target as defined in section 14. `deny` refuses the action. `escalate` defers the action to the host approval path defined in section 17.1. A host that previously expressed permit with redaction as a permit verdict that also rewrote the policy target MUST now express it as a `transform` verdict, or as an annotator that performs the rewrite upstream of the policy.

The runtime derives two action identities for each successful evaluation. Each is encoded as `sha256:` followed by lowercase hexadecimal bytes. `input_identity` is the SHA-256 digest of the canonical policy input JSON that the policy evaluated. `enforced_identity` is the SHA-256 digest of the canonical policy input after a `transform` path is applied to the policy target. The two identities are equal for `allow`, `warn`, `deny`, and `escalate`, and they are equal in `evaluate_only` mode because no transform is applied. Both identities cover the intervention point, policy target, full snapshot, annotations, and projected tool data that the policy evaluated. The escalation approval path in section 17.1 binds to `enforced_identity` so that the approver consents to the action that will execute.

### 13.2 Result labels

`result_labels` is the runtime's return channel for stateless information-flow control. A policy MAY return an array of label strings describing the data produced at the evaluated sink. The runtime returns the array verbatim in the verdict and does nothing else with it: it stores no labels, propagates no taint, and performs no information-flow check of its own. When the member is absent or `null` the runtime returns an empty array.

The host owns propagation. A host that practices information-flow control persists the returned `result_labels` alongside the data the sink produced, such as a tool result or a model output, and supplies them as `snapshot.ifc.source_labels` on later evaluations whose policy target derives from that data. This keeps label flow correct across turns without the runtime holding state. The host MUST NOT propagate `result_labels` for an action that did not proceed, such as a `deny` verdict or an `escalate` verdict that the approval seam did not approve: the member is only meaningful when the sink's data is actually produced. Accordingly the `agent_control_specification.lib.ifc` helpers omit `result_labels` on non-allow verdicts. Section 17 defines the host obligation; the reusable Rego library `agent_control_specification.lib.ifc` provides lattice and label-join helpers that compute the value a policy returns here.

### 13.3 Evidence

A verdict MAY carry an optional `evidence` object that points at an offline verifiable proof of the decision.

```json
"evidence": {
  "artefact": "sha256:<hex>",
  "verification_pointers": {
    "issuer_pubkey": "https://example.com/keys/2026.pem",
    "policy_registry": "https://example.com/policies/v1/"
  }
}
```

| Field | Required | Type | Constraint |
| --- | --- | --- | --- |
| `artefact` | no | string | Content address of an offline verifiable proof. SHOULD be `sha256:<lowercase-hex>` or a URI. |
| `verification_pointers` | no | object | Map of named URLs that an auditor MAY consult to re-verify the decision. |

The runtime treats `evidence` as opaque. It does not validate `artefact` and does not fetch any `verification_pointers`. A dispatcher that emits a non object `evidence` MUST fail closed with `runtime_error:policy_output_invalid`. The runtime propagates `evidence` into telemetry as defined in section 19. The URL values in `verification_pointers` MUST NOT appear in telemetry and are recovered from the audit record per [`spec/agt/AGT-EVIDENCE-1.0.md`](agt/AGT-EVIDENCE-1.0.md).

## 14. Transform

A `transform` verdict carries a single replacement that the runtime applies to the policy target and to nothing else. The `transform` body has two members.

| Field | Required | Type | Constraint |
| --- | --- | --- | --- |
| `path` | yes | string | MUST be rooted at `$policy_target`. |
| `value` | yes | any | New JSON value to set at `path`. |

The runtime resolves `path` against the current policy target and replaces the value at that location with `value`. The transformation is confined to the policy target. The runtime MUST NOT change the snapshot, the annotations, the projected tool, or any host state.

A `transform` whose `path` is rooted outside `$policy_target` MUST fail closed with `runtime_error:transform_target_forbidden`. A `transform` whose `path` cannot be parsed, whose `path` does not resolve against the policy target, whose `value` cannot be set because of a path type mismatch, or whose `value` member is missing MUST fail closed with `runtime_error:transform_invalid`.

In `enforce` mode the runtime applies the transform and the result is the transformed policy target. In `evaluate_only` mode the runtime validates the transform but applies none and returns no transformed policy target.

`transform` is the only form of value rewriting a verdict can request. A host that needs multi step rewriting at one intervention point expresses it by chaining intervention points, for example an annotator at `pre_model_call` produces sanitized text under `annotations.<name>` and the bound policy reads from that annotation.

## 15. Resource limits

A runtime MUST enforce finite limits while loading file based manifest extends, fetching HTTPS manifest extends, building policy input, serializing policy input, invoking annotators, normalizing policy output, and validating or applying a transform. A host MAY configure those limits. Policy output is measured as canonical JSON before verdict normalization. A transformed policy target produced by an applied transform MUST be reinserted into the request snapshot for snapshot limit validation before the runtime returns it to the host. A limit breach MUST fail closed with `runtime_error:resource_limit_exceeded`, except an individual annotator output limit breach MUST fail closed with `runtime_error:annotation_failed`.

## 16. Reserved reasons

A runtime failure yields a `deny` verdict whose `reason` is one of the identifiers below. A policy MUST NOT emit a reason that starts with `runtime_error:`.

| Reason | Cause |
| --- | --- |
| `runtime_error:manifest_invalid` | The manifest failed validation or bound an undefined policy. |
| `runtime_error:intervention_point_unknown` | The request named an intervention point the manifest does not configure. |
| `runtime_error:path_missing` | A required path did not resolve. |
| `runtime_error:path_type_mismatch` | A path segment met an incompatible JSON type. |
| `runtime_error:tool_unknown` | The projected tool name is absent from the catalog. |
| `runtime_error:annotation_failed` | An annotator dispatch failed. |
| `runtime_error:annotation_timeout` | An annotator dispatch timed out. |
| `runtime_error:policy_invocation_failed` | Policy preparation or dispatch failed. |
| `runtime_error:policy_output_invalid` | The dispatcher output could not be normalized. |
| `runtime_error:transform_invalid` | A `transform` was malformed, its path did not resolve, or its value could not be set. |
| `runtime_error:transform_target_forbidden` | A `transform` path pointed outside `$policy_target`. |
| `runtime_error:resource_limit_exceeded` | Evaluation or manifest loading exceeded a configured resource limit. |
| `runtime_error:approval_action_mismatch` | An approved action identity did not match the current action identity. |
| `runtime_error:approval_resolver_missing` | An `escalate` verdict was returned but no resolver matched the manifest `approval.default_resolver`. |
| `runtime_error:resolution_path_traversal` | AGT host side resolution refused an action path that resolved outside the workspace root. |
| `runtime_error:resolution_cycle` | AGT host side resolution detected a cycle while merging an `extends` chain. |
| `runtime_error:resolution_invalid_governance` | AGT host side resolution failed to validate a `governance.yaml` during merge. |
| `runtime_error:resolution_merge_conflict` | AGT host side resolution found two non rule sections that could not be merged. |

An SDK enforcement layer MAY also fail closed with a reserved `runtime_error:` reason that the core runtime never produces. Such a reason is SDK produced and is attributed to its producing layer. The reasons below are reserved for SDK enforcement helpers.

| Reason | Producer | Cause |
| --- | --- | --- |
| `runtime_error:approval_resolver_failed` | `sdk-approval` | An SDK approval resolver raised, returned an unrecognized result, or otherwise failed closed. |
| `runtime_error:streaming_unsupported` | `sdk-streaming` | An SDK streaming helper could not assemble a complete response snapshot for evaluation and failed closed. |
| `runtime_error:adapter_unsupported` | `sdk-adapter` | An SDK adapter detected an unmediated framework method or unsupported call shape and failed closed instead of invoking upstream code. |
| `runtime_error:request_invalid` | `sdk-wire` | A JSON wire binding received a malformed intervention request envelope and failed closed before policy input construction. |

A machine readable inventory of every reserved reason with producer attribution lives in [`spec/reserved-reasons.json`](reserved-reasons.json). A policy MUST NOT emit any reason that starts with `runtime_error:`, including the SDK layer reasons.

## 17. Host obligations

The runtime returns a verdict and, for a `transform` verdict in enforce mode, an optional transformed policy target. The host enforces them. In `enforce` mode the host MUST NOT carry out the action of a `deny` verdict, MUST route an `escalate` verdict to an approval path and MUST NOT carry out the action until that path resolves, and MUST use the transformed policy target in place of the original policy target when one is present. In `evaluate_only` mode the host MAY carry out the original action and SHOULD record the verdict. A host that ignores a `deny` or an unresolved `escalate` is not conformant.

### 17.1 Approval path

The approval path is a host concern and is not part of the policy input contract. An SDK MAY expose it as an approval resolver. The resolver is a host supplied callback that the SDK consults only for an `escalate` verdict in `enforce` mode. The resolver payload MUST include the `enforced_identity` returned by evaluation. The approval outcome MUST carry the approved `enforced_identity` for an allow or suspend result. The SDK MUST rederive the `enforced_identity` from the current policy input before proceeding and MUST fail closed with `runtime_error:approval_action_mismatch` when it differs from the approved identity. An SDK that consults a manifest declared resolver but finds none matching the manifest `approval.default_resolver` MUST fail closed with `runtime_error:approval_resolver_missing`. The path resolves to one of three outcomes.

1. Allow. The host carries out the action. An `escalate` verdict does not return or apply a transformed policy target.
2. Deny. The host MUST NOT carry out the action.
3. Suspend. The host stops the current run and hands the decision to an out of band process. Suspension is terminal for the run. Resumption is the host's responsibility and is not a runtime operation.

When no approval path is configured, or when the path fails or returns an unrecognized outcome, the host MUST fail closed and treat the `escalate` verdict as a `deny`. A `deny` verdict MUST NOT consult the approval path.

An `escalate` verdict at a post action intervention point, such as `post_model_call` or `post_tool_call`, is reached only after the action has already executed. A host that suspends at such a point and later resumes MUST deliver the result that was already produced and MUST NOT execute the action a second time.

## 18. Streaming and parallel tools

The runtime evaluates whole snapshots and not live token streams. A host MUST assemble streamed model output before `post_model_call` and streamed final output before `output`. Enforcement at the token or chunk level is outside this model.

A tool intervention point runs once for each concrete tool invocation. For parallel tool calls the host calls `pre_tool_call` and `post_tool_call` for each invocation on its own and MAY correlate the pair through a tool call identifier carried in the snapshot. A block applies to the one invocation that produced it. The host decides whether to cancel the batch or to omit only the blocked invocation.

## 19. Telemetry and audit

A host MAY supply a telemetry sink. Events are content safe and stable. Known event kinds are `decision`, `annotator_dispatch`, `policy_evaluation`, `evaluation_timing`, `intervention_point.transformed`, `annotator_failed`, and `policy_failed`. The runtime emits `intervention_point.transformed` in addition to `decision` whenever the verdict is `transform`. An event carries stable metadata such as the intervention point, enforcement mode, decision, reason code, error class, policy id, annotator names, duration, and whether a transform was applied. When a verdict carries `evidence` the event MAY include the `evidence_artefact` and the key names of `verification_pointers` recorded as `evidence_verification_pointer_keys`, and it MUST NOT include the pointer URL values. A runtime MAY include the `input_identity` and `enforced_identity` from section 13 as correlation identifiers. The runtime MUST NOT emit policy target values, tool arguments or results, annotation values, model messages, secrets, or personal data.

A host MAY derive an audit record from each evaluation. The action identities defined in section 13, the `input_identity` and `enforced_identity` `sha256:` digests of the canonical policy input, are the stable keys that tie an audit record to the exact intervention point, policy target, snapshot, annotations, and projected tool data the policy evaluated. An audit record SHOULD record the intervention point, the mode, the verdict, the reason, the error class for runtime errors, and the action identities when available. It MUST follow the same redaction rule as telemetry so that it carries no sensitive value.

The telemetry and audit contract is transport neutral. ACS ships an OpenTelemetry binding in the `agent_control_specification_otel` integration crate that maps these events to OpenTelemetry counters and histograms, described in [`docs/observability.md`](../docs/observability.md). That binding is one supported integration and is not required for conformance. A host MAY route the same events to any sink it chooses.

## 20. Conformance

An implementation conforms to this document as a runtime, as a host, or as both.

A conformant runtime MUST evaluate in the order defined in section 6, build the policy input defined in section 7, serialize it canonically as defined in section 8, normalize results into the verdicts defined in section 13, validate and apply a transform as defined in section 14, enforce the resource limits in section 15, and report failures using only the reserved reasons in section 16. It MUST be stateless and deterministic as defined in section 1.1 and MUST fail closed on every error.

A conformant host MUST honor the obligations in section 17. It MUST NOT carry out a denied action, MUST NOT carry out an action whose `escalate` verdict has not resolved to an allow, and MUST substitute the transformed policy target for the original when the runtime returns one. A host MUST NOT present an `evaluate_only` result as enforcement.

The reference conformance suite in the repository exercises these requirements across the core runtime and every SDK and is the practical test of conformance.

## 21. Security Considerations

ACS is fail closed by design. Any error during evaluation yields a `deny` verdict, so a misconfiguration or a dispatcher failure denies rather than permits. An implementation MUST preserve this property and MUST NOT add a manifest level fail open path.

The runtime trusts the snapshot the host supplies. It does not authenticate the snapshot or verify that its contents reflect the real agent state. A host MUST assemble the snapshot from trusted sources and MUST treat snapshot assembly as part of its trusted computing base.

Annotations are untrusted signal. An annotator observes potentially adversarial content such as a user prompt or a tool result. A policy MUST treat annotation values as data and MUST NOT let them widen authority. A failed annotator fails closed, so an annotator failure cannot silently allow an action.

A `transform` verdict is bounded to the policy target. The runtime applies a transform only within `$policy_target` and rejects any `transform` path rooted outside it, so a policy cannot use a transform to reach the snapshot, the projected tool, or host state.

Approvals bind to `enforced_identity`. An `escalate` verdict is approved against the `enforced_identity` of the action that will execute, and the SDK rederives that identity before proceeding and fails closed on a mismatch. This prevents an approval granted for one action from authorizing a different action and closes a time of check to time of use gap.

Telemetry MUST NOT carry sensitive values. The runtime emits low cardinality metadata only and never the values enumerated in section 19.

Resource limits bound the work of a single evaluation. A host SHOULD configure the limits in section 15 to match its environment so that a hostile or malformed snapshot, manifest, or annotator output cannot exhaust host resources.

Dispatchers run with host trust. A policy or annotator dispatcher executes host supplied code and reaches the network and other systems. The host is responsible for the security of that code and of the endpoints it contacts.

The repository threat model in [`docs/security-model.md`](../docs/security-model.md) records the assets, the adversaries, and the mitigations in full.

## 22. Versioning and stability

This document is versioned with the identifier in its first paragraph, and a manifest declares the version it targets through the `agent_control_specification_version` field defined in section 2.1. The version uses semantic versioning. A change that removes or repurposes a field, narrows an allowed value, adds a new requirement that an existing conformant implementation would fail, or changes the verdict for an input that was already specified is a breaking change and increments the major version. A change that adds an optional field, an intervention point, a reserved reason, or a telemetry event without altering existing behavior is additive and increments the minor version. An editorial change that does not change behavior increments the patch version.

The current version carries the `-alpha` pre release tag and the status Draft. While that tag is present the contract MAY change in breaking ways between minor versions, and an implementation SHOULD pin the exact version it targets. The intervention point names in section 4 and the reserved reasons in section 16 are a closed set that this document defines. A host MUST NOT invent new identifiers in either set. A host extends behavior through the `custom` policy type and through host supplied annotators rather than by adding identifiers.

## 23. References

### 23.1 Normative references

**[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

**[RFC 8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.

**[RFC 8259]** Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", RFC 8259, December 2017.

**[SCHEMA]** Agent Control Specification manifest schema, `schema/manifest.schema.json` in artifact kits and `spec/schema/manifest.schema.json` in this repository.

**[OPA]** Open Policy Agent and the Rego policy language, `https://www.openpolicyagent.org/`.

### 23.2 Informative references

**[THREAT-MODEL]** Agent Control Specification threat and security model, [`docs/security-model.md`](../docs/security-model.md).

**[IMPL-DESIGN]** Agent Control Specification stateless implementation design, [`docs/stateless-runtime.md`](../docs/stateless-runtime.md).

## 24. Approval manifest section

A manifest MAY carry a top level `approval` object that declares how a host resolves an `escalate` verdict. The section is optional. A manifest without it has no declared resolvers and a host falls back to its own approval configuration as described in section 17.1.

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `default_resolver` | no | string | Name of the resolver a host consults when a binding does not name one. |
| `timeout_seconds` | no | integer | Maximum wait before `on_timeout` triggers. |
| `on_timeout` | no | string | One of `deny`, `allow`, or `suspend`, applied when `timeout_seconds` elapses without a decision. |
| `fatigue_threshold` | no | integer | Soft cap on approvals per agent within `fatigue_window_seconds`. |
| `fatigue_window_seconds` | no | integer | Window across which the fatigue counter accumulates. |
| `resolvers` | no | object | Map of resolver name to an opaque resolver descriptor that carries a discriminating `type` field. |

The runtime validates the shape of `approval`. It MUST fail closed with `runtime_error:manifest_invalid` when `approval` is present and is not an object, when `default_resolver` or `on_timeout` is present and is not a string, when `timeout_seconds`, `fatigue_threshold`, or `fatigue_window_seconds` is present and is not a non negative integer, or when `resolvers` is present and is not an object. The runtime treats each resolver descriptor as opaque beyond its `type` discriminator and does not interpret the rest of its contents. Resolution of a resolver name to a concrete approval mechanism is a host concern defined in section 17.1. When an `escalate` verdict is returned and no resolver matches the `default_resolver`, the SDK enforcement layer MUST fail closed with `runtime_error:approval_resolver_missing`.

The `approval` schema is published at [`spec/schema/approval.schema.json`](schema/approval.schema.json).

## Appendix A. Worked example

This appendix is informative. It walks one evaluation from end to end.

A host governs the `input` intervention point with a custom policy. The manifest binds the policy and selects the user text as the policy target.

```yaml
agent_control_specification_version: 0.3.1-beta
metadata:
  name: worked-example
policies:
  input_guard:
    type: custom
    adapter: example_blocklist
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_guard
    policy_target: $.input
annotators: {}
```

The host assembles a snapshot for one turn and calls the runtime in `enforce` mode.

```json
{
  "input": { "text": "please drop table users" }
}
```

The runtime selects `$.input` as the policy target, builds the canonical policy input, and invokes the `example_blocklist` dispatcher. The dispatcher returns a deny.

```json
{
  "decision": "deny",
  "reason": "blocked_destructive_sql"
}
```

The runtime normalizes this into a `deny` verdict and applies no transform. In `enforce` mode the host MUST NOT carry out the action, as required by section 17. The same request in `evaluate_only` mode returns the same `deny` verdict, but the host MAY proceed and SHOULD record the verdict, which is how a team bakes a new policy on live traffic before it enforces.
