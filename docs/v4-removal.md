# v4 policy-language removal

AGT is removing the legacy v4 policy language so the ACS (v5) policy layer
is the only policy contract in the toolkit. v4 constructs survive only inside
a one-way migration tool that converts a v4 project to a v5 ACS manifest. This
is a breaking change for v4 users.

## What counts as v4 policy language

| Symbol | Home | Replacement |
|--------|------|-------------|
| `GovernancePolicy`, `PatternType` | `agent_os/integrations/base.py` | ACS manifest plus `AgtRuntime` |
| `PolicyInterceptor`, `ExecutionContext` | `agent_os/integrations/base.py` | `AdapterRuntimeSession` over `AgtRuntime` |
| `ViolationCategory`, `PolicyCheckResult` | `agent_os/policies/decision.py` | native v5 result and error contracts |
| `PolicyDocument`, `PolicyAction`, `CedarBackend` | `agent_os/policies/` | ACS `policies.type: cedar` and native manifests |
| `governance_to_acs_manifest` | `agt/policies/bridge.py` | migration tool only |
| `governance_to_document` | `agent_os/policies/bridge.py` | deleted |
| `get_runtime_bridge`, `AdapterRuntimeBridge` | `agent_os/integrations/_v5_runtime_bridge.py` | `AdapterRuntimeSession` |
| `to_v4_check_result` | `agt/policies/result.py` | deleted |
| runtime `governance.yaml` resolution | private `agt.cli` migrator | migration flattens once |

## The one allowed home

v4 policy language may remain only inside the migration tool. The ratchet
exempts an explicit allowlist of migration modules
(`agent-governance-python/agt-policies/src/agt/cli/migrate.py` and siblings,
later the dedicated `agt-v4-migrate` distribution and its tests), not a whole
directory. The migration tool reads a v4 project once and emits a flat ACS
manifest plus bundles. Runtime modules accept ACS and AGT manifests only.
Composition uses native ACS `extends`.

## Phased plan

The removal runs as an internal strangler followed by one atomic public
breaking release.

0. Semantic inventory and CI ratchet across Python, Rust, and TypeScript.
1. Define native v5 result, error, audit, typed manifest, and adapter
   enforcement contracts. Audit every `GovernancePolicy` field.
2. Extract an ACS-native `AdapterRuntimeSession` from the v4 runtime bridge and
   isolate and harden the migration translator.
3. Migrate every runtime-bridge consumer as green vertical slices with tests
   and examples.
4. Migrate non-adapter consumers and the legacy policy subsystem, and delete
   runtime `governance.yaml` resolution.
5. Rewrite the Rust and TypeScript v4 surfaces and fix package builds.
6. Atomically remove all bridges, v4 result conversion, and re-exports, then
   tighten the ratchet to zero.

## The ratchet

`scripts/check_v4_ratchet.py` inventories every surviving v4 symbol per file
and enforces a strict ratchet. No change may add v4 usage, no v4 marker may
move into a new file, and no per-symbol count may rise. Python detection is
AST and import aware so strings and comments never miscount. It counts class
and function definitions, aliased imports and their uses, keyword and
parameter names, `__all__` entries, compound string annotations, and
semantic string constants used by dynamic imports, `getattr`, and
`mock.patch`, so a count cannot fall without real removal. Names that collide
with unrelated code (`ExecutionContext`, `PolicyEvaluator`) are counted only
when bound from or accessed through a qualifying v4 module, or defined and
used in the canonical v4 file, so foreign look-alikes are not miscounted.
Markdown requires qualified v4 context for those ambiguous names. Any Python
file that cannot be decoded or parsed fails the gate closed. Rust and
TypeScript use identifier-boundary token matching. Markdown and the normative
AGT spec layer are scanned from one vocabulary. Every YAML, YML, and JSON file
is inspected for the complete v4 `PolicyDocument` and `PolicyDefaults` schema,
with explicit ACS, Kubernetes, and AgentMesh trust-policy exclusions.
`governance.yaml` and `governance.yml` count regardless of contents, so the
docs, spec, and policy-data purge obligations are visible to the zero gate.

```bash
python scripts/check_v4_ratchet.py            # gate against the baseline
python scripts/check_v4_ratchet.py --report   # inspect the inventory
python scripts/check_v4_ratchet.py --update-baseline   # after a real reduction
```

`scripts/v4_ratchet_baseline.json` is the committed baseline. `--update-baseline`
refuses to bless an increase unless `--allow-baseline-increase` is passed for a
deliberate scanner-semantics change. The migration allowlist is inventoried and
reported but never counted against the ratchet. The gate, its unit tests, and
lint run on every pull request through `.github/workflows/v4-removal-ratchet.yml`.
The final gate in phase 6 drives the non-migration total to zero, including
normative specs.

## Phase 1 native contracts

`AgtRuntime.from_manifest(...)` is the canonical runtime constructor. It
accepts a path, YAML text, a mapping, or `AgtManifest`. Paths carry their parent
directory as provenance. Other inputs must provide `base_dir` when they contain
relative bundle, data, prompt, Cedar, or `extends` references. The runtime never
falls back to the current working directory.

`AgtManifest` is a lossless typed representation of AGT-MANIFEST-1.0. It
performs structural validation and preserves policy, tool, annotator, resolver,
and host extension fields. It does not accept intent-level fields such as
`max_tokens`, `allowed_tools`, or `blocked_patterns`, and it never synthesizes
policies or bindings. Adapter compatibility is a separate
`AdapterManifestContract` preflight. Static preflight requires a resolved
manifest because an `extends` parent may supply required intervention points or
tools. Phase 2 wires preflight to the runtime's resolved manifest labels.
The model preserves the AGT `limits` section, but runtime construction rejects
it until the Python SDK can enforce those values. Silently accepting an
unenforced security limit is not allowed.

`AgtRuntime.evaluate(...)` returns the native immutable `PolicyEvaluation`.
The stable fields are `verdict`, `reason_code`, `message`,
`intervention_point`, `transform`, `evidence`, `result_labels`,
`input_identity`, and `enforced_identity`. Its audit envelope uses schema
`agt.policy_evaluation.v1`. ACS does not currently expose `policy_id` or
`rule_id` on `InterventionPointResult`, so neither field appears in this
contract and callers must not infer them from `reason_code`.
Policy-authored `message` remains restricted audit detail.
`PolicyViolationError.from_evaluation_result(...)` emits a stable sanitized
public message instead of copying policy or user content into exception text.

The existing `AgtRuntime(...)`, `evaluate_intervention_point(...)`, and
`EvaluationResult` remain temporary bridge-only compatibility surfaces. Phase 2
moves adapters to the native result. Phase 6 removes the compatibility surface.

### Adapter enforcement contract

| Concern | Native contract |
|---------|-----------------|
| Required intervention points | Every adapter declares them and calls `AgtManifest.validate_for(...)` before execution. A missing required point is a construction error, never a runtime allow fallback. |
| Tool catalog | `manifest` requires static `tools`, `host_dynamic` is synchronized by the host, and `optional` imposes no catalog requirement. |
| Transform | Each adapter declares the intervention points where it can apply a transform. The shared adapter session applies it before forwarding the payload. |
| Approval | `AgtRuntime` owns the resolver and timeout behavior. An adapter given a runtime cannot also accept competing resolver configuration. |
| Budgets | Attempted calls consume tool-call budget, including denied and failed attempts. Session counters live in the adapter session, not `AgtRuntime`. |
| Runtime sharing | One runtime may be shared when host dispatchers and approval callbacks are thread-safe. Session snapshots and counters are never stored on the runtime. |
| Fail direction | Invalid manifests, missing required bindings, dispatcher errors, and approval errors fail closed. The native path does not rewrite unknown intervention points or tools to allow. |

### GovernancePolicy field disposition

| v4 field | v5 disposition |
|----------|----------------|
| `name` | `metadata.name` |
| `version` | `metadata.policy_version` during migration only |
| `max_tokens` | ACS budget policy over snapshot token count |
| `max_tool_calls` | ACS budget policy over attempted tool-call count. Zero remains deny-all during migration. |
| `allowed_tools` | ACS `tools` catalog or host-dynamic catalog contract. Empty v4 lists migrate to no allowlist. |
| `blocked_patterns` | Explicit Rego policy bound to input, output, and tool arguments as needed |
| `require_human_approval` | Escalate verdict plus manifest `approval` and runtime resolver |
| `confidence_threshold` | Policy bound at `post_model_call` |
| `timeout_seconds` | Host execution limit, not policy language |
| `drift_threshold` | Host annotator or policy input, selected explicitly by the adapter |
| `log_all_calls` | Host audit configuration |
| `checkpoint_frequency` | Host orchestration configuration |
| `max_concurrent` | Host concurrency configuration |
| `backpressure_threshold` | Host concurrency configuration |
| detection module dictionaries | Host security module configuration, not manifest policy |
| `detection` | Host module enablement and enforcement actions |

The migration tool must either translate each policy field exactly or refuse
the conversion with a manual-review finding. Host-only fields move to explicit
host configuration and must not be silently dropped.

## Phase 2 extraction boundaries

`AdapterRuntimeSession` now owns one session's `SnapshotBuilder`, counters, and
native intervention-point calls. It reserves attempted tool calls before
execution so denied and failed attempts consume budget, records model tokens
after `post_model_call`, and serializes only counter mutation. `AgtRuntime`
remains session-free and shareable under the Phase 1 callback thread-safety
contract.

The v4 runtime bridge delegates snapshot construction and evaluation to the
native session. It retains only v4 translation, result conversion, host budget
fallbacks, approval fallbacks, and the two default-permit rewrites. Existing
adapters temporarily disable native counter charging to avoid double-counting
until Phase 3 moves them off `ExecutionContext`.

The one-way `GovernancePolicy` translator lives under `agt.cli` and has no
runtime import path. It accepts exact literal fields and exact
`PatternType.SUBSTRING`, `PatternType.REGEX`, and `PatternType.GLOB` forms.
Dynamic expressions, host-only settings, invalid patterns, unsupported fields,
and existing outputs refuse migration. The generated manifest is validated as
`AgtManifest` before an atomic write. Differential tests compare every
supported construct with the frozen runtime bridge so defaults and boundary
semantics cannot drift during the transition. REGEX and GLOB use OPA's Go RE2
validator, and GLOB uses the RE2 `\z` end anchor rather than Python's unsupported
`\Z`. Both constructor and governance-chain migrations refuse existing
manifests, bundles, and backups instead of overwriting them.

## Phase 3 adapter cutover

The 17 bridge-backed framework adapters now accept a public native `runtime`
argument and route their model, tool, stream, and output intervention points
through `NativeAdapterRuntime` and `AdapterRuntimeSession`. Agent Shield uses
`agt_runtime` because its existing positional `runtime` names the Agent Shield
SDK object. A2A, Agent Shield, Anthropic, AutoGen, Bedrock, CrewAI, Gemini,
Google ADK, Guardrails, LangChain, LlamaIndex, MAF, Mistral, OpenAI, PydanticAI,
Semantic Kernel, and Smolagents no longer import or evaluate through
`AdapterRuntimeBridge` or `BridgeResult`. Their only remaining dependency on
`_v5_runtime_bridge` is the constructor selector for the temporary policy
compatibility edge.

Native denials attach `evaluation_result` and the
`agt.policy_evaluation.v1` audit record to `PolicyViolationError`. The
temporary policy-based edge still attaches `check_result`, selected by one
shared result dispatcher. Transforms remain native objects in both paths.
The runtime owns approval configuration. An adapter may omit
`approval_resolver` or repeat the identical callback for transition code, but a
different callback is rejected at construction.

The old `policy` and private `_runtime` arguments remain only to keep the
development tree green until the single public breaking cut in Phase 6.
Convenience wrappers also accept `runtime`. Their policy path is not the native
default and is removed with the compatibility bridge. OpenAI Agents SDK and
LangGraph now expose native runtime hook paths while retaining their
checkpoint, handoff, audit, and wrapper behavior host-side.

## Phase 4 runtime cleanup

Runtime governance folder discovery has been removed. The resolver, its
contract, and its tests live only under `agt.cli._migrate_resolution`.
`AgtRuntime` no longer accepts `resolution_root`, `agt.manifest_resolution` is
not public, and the OPA scenario harness no longer synthesizes runtime policy
from `governance.yaml`. Native composition uses ACS `extends`.

The Rust core and SDK parity fixtures no longer expose migration-only
`runtime_error:resolution_*` variants. The migration command keeps equivalent
diagnostics privately for report generation.

OpenAI Agents SDK hooks evaluate input, tool calls, tool results, and output
through `NativeAdapterRuntime` when given `runtime`. LangGraph evaluates node
state and tool calls natively and fingerprints the runtime manifest plus
registered tool hashes. Their non-policy semantics such as handoff limits,
checkpoint metadata, node wrapping, and audit events remain host-owned.

## Phase 5 language and packaging rewrite

The Rust `FrameworkGovernanceAdapter` now accepts native `AgentControl`,
`Manifest`, and explicit `FrameworkHostConfig`. The removed local policy and
pattern types are no longer exported. Legacy-shaped YAML fails manifest
validation instead of receiving an in-process translation.

The Mastra package now requires the Node ACS package and delegates every tool
call to `AgentControl.runTool`. Trust and tamper-evident audit remain Mastra
middleware. Policy decisions, transforms, approval, and tool catalogs come
from the ACS manifest.

The consolidated Python core wheel declares `agt-policies` because it
force-includes the native adapter modules. A wheel inspection gate builds both
artifacts, verifies the dependency metadata, confirms native session/runtime
modules and migration Rego resources are packaged, and rejects a public
`manifest_resolution` package.
