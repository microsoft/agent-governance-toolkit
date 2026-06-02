# ACS generator and guided init

The generator is useful when a host team needs a consistent ACS manifest, Rego policy, and review report from a compact threat statement. Hand-written manifests remain appropriate for low level runtime experiments. The generator is preferable for production bootstrap work because it validates the manifest schema, checks policy input references, derives tool catalog entries, and emits a report that records the chosen intervention points and verdict rules.

## Guided init

Run the guided designer with flags for repeatable automation.

```bash
acs-generate init \
  --non-interactive \
  --name "Payments Agent" \
  --points input,pre_tool_call,output \
  --tool wire_transfer:banking,payments \
  --deny-keyword password \
  --escalate-tool wire_transfer \
  --redact-output-pattern 'acct_[0-9]+' \
  --sample-test \
  --out build/acs-payments
```

The same command is also available as `acs init` after the generator package is installed. The command writes `manifest.yaml`, `policy/<slug>.rego`, `report.md`, optional `snapshots/<intervention_point>.json` files, and an optional `test_policy.py` smoke test. The output directory must be empty unless `--force` is supplied. The force mode replaces generated files and leaves unrelated files in place.

Use `--answers-file` for CI or for repeated local runs.

```bash
acs-generate init --non-interactive --answers-file examples/generator-init/answers.yaml --out build/acs-support --sample-snapshot
```

Use `--answers-file -` to read JSON or YAML from stdin. Tests can supply stdin without live LLM credentials.

Answers files support the same guided-init fields as the CLI flags: `name`, `points`, `tools`, `deny_keywords`, `escalate_tools`, and `redact_output_patterns`. Unsupported keys fail fast so CI does not silently ignore intended settings. Add custom `annotators`, provider configuration, or `extends` in a child manifest after generation.

Child manifests are best for additive composition. They can add metadata keys, policies, annotators, tools, or new intervention points. They cannot replace an existing intervention point policy, target, or `tool_name_from` unless the child repeats the same value. Conflicting duplicates fail closed during manifest loading.

File based `extends` is confined to the top level manifest root. Keep parent manifests under the child manifest root, for example `extends: ["base/manifest.yaml"]`, or load separate sibling manifests through an SDK manifest-chain constructor when the SDK exposes one.

## Validation

The init flow validates the manifest against `schema/manifest.schema.json` from the artifact kit or `spec/schema/manifest.schema.json` from a repository checkout, asks the Python SDK core loader to check semantic manifest constraints, rejects deprecated policy input keys, and uses OPA for Rego syntax and evaluation when `opa` is available. `--strict` makes missing OPA a failure. The generator wheel also carries the manifest schema and the wire request/result schemas under `acs_generator.schema` for artifact-only schema checks.

Artifact-only kits include a local Node optional OPA package. Install or extract `agent-control-specification-opa-<platform>-<version>.tgz`, then prepend its `bin` directory to `PATH` before running `acs-generate init --strict`.

```bash
npm install "$ACS_KIT"/artifacts/agent-control-specification-opa-linux-x64-0.3.1-beta.0.tgz
PATH="$PWD/node_modules/agent-control-specification-opa-linux-x64/bin:$PATH" \
  acs-generate init --strict --non-interactive --name "Payments Agent" --out build/acs-payments
```

## Fit with ACS

The generated policy remains stateless. Every rule reads only the canonical policy input for the current intervention point. Tool escalation rules match the generated `input.tool.id` and fall back to `input.tool.name`, which is projected only for tool intervention points. Effects target `$policy_target`, so effect scope stays confined to the mediated value.

Information flow control policies that use `result_labels` and later `snapshot.ifc.source_labels` are host specific. Guided init emits a general baseline, then hosts add IFC rules in a child manifest or policy overlay. See `examples/ifc_agent` for the label propagation pattern.
