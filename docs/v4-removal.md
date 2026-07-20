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
| runtime `governance.yaml` resolution (`resolution_root`) | `agt/manifest_resolution/` | deleted, migration flattens once |

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
