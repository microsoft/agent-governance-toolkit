# AGT stock Cedar policy library

This directory ships the AGT stock policy library written in Cedar, the
sibling of the Rego library at `policy-engine/policy/lib/`. Each file
mirrors the same named Rego library so a manifest author can pick the
engine that fits the host environment and reuse the same gate semantics.
The Cedar library realises the AGT verdict surface described in
`policy-engine/spec/SPECIFICATION.md` §14 and §12.4 and
the cedar advice schema at
`policy-engine/spec/schema/cedar_advice.schema.json`.

## File catalogue

| File | Mirror | Decision shape |
| --- | --- | --- |
| `budgets.cedar` | `budgets.rego` | `forbid` on tool call count or token count thresholds |
| `patterns.cedar` | `patterns.rego` | `forbid` on `like` PII substring signatures |
| `content_hash.cedar` | `content_hash.rego` | `forbid` on tool content hash mismatch or missing observed hash |
| `egress.cedar` | `egress.rego` | `forbid` when destination host is not in the resource allowlist |
| `drift.cedar` | `drift.rego` | `permit` with `warn` advice when drift score crosses threshold |
| `confidence.cedar` | `confidence.rego` | `forbid` when confidence score is below threshold |
| `redact.cedar` | `redact.rego` | `permit` with `transform` advice replacing `$policy_target.value` wholesale |
| `approval.cedar` | `approval.rego` | `permit` with `escalate` advice for approver gated actions |
| `ifc.cedar` | `agt_ifc.rego` | `forbid` when sink clearance does not dominate every source label |
| `agt_default.cedar` | `agt_default.rego` | Composes every gate above with a baseline permit |

Each Cedar policy file has a matching `_test.json` driven by the Cedar
CLI `run-tests` subcommand. The runner script `run_tests.sh` invokes
`cedar check-parse` and `cedar run-tests` against every pair and
returns non zero on any failure.

## How the Cedar verdict shape maps to AGT verdicts

The cedar dispatcher in `policy-engine/core/src/cedar.rs` evaluates the
policy set against the request built per D3.2 and produces an AGT
verdict per D3.3.

| Cedar evaluation result | AGT verdict |
| --- | --- |
| `Deny` (any `forbid` matched) | `{decision: "deny", reason: <first contributing policy id>}` |
| `Allow` with no advice | `{decision: "allow"}` |
| `Allow` with `@advice` annotation | The advice JSON validated against `cedar_advice.schema.json` and translated to `{decision: "warn"|"escalate"|"transform", ...}` |

The `@id` annotation on each `forbid` policy is the AGT deny reason
that surfaces on the verdict. The `@advice` annotation on a `permit`
carries the cedar advice JSON payload. The schema enforces that
`advice.verdict` is one of `warn`, `escalate`, or `transform`. A
`transform` advice MUST carry a `transform.path` rooted at
`$policy_target` and a replacement `transform.value`.

## Binding a Cedar policy from an AGT manifest

The manifest binds a Cedar policy through the `cedar` type per D3.1.
Example.

```yaml
policies:
  default:
    type: cedar
    policy_path: ./policy/cedar-lib/agt_default.cedar
    entities_path: ./policy/data/resources.json
hooks:
  pre_tool_call:
    policy: default
```

The host loads the resource entity attributes that parameterise the
policy (thresholds, allowlists, clearance closures, content hashes)
through the `entities_path` field. The entity UIDs MUST match the
resource UIDs that the dispatcher constructs from the AGT snapshot per
D3.2, namely `Tool::"<name>"` for tool intervention points and
`PolicyTarget::"<kind>"` for other intervention points.

## Cedar limits compared to the Rego library

Cedar is purposely a smaller language than Rego and lacks several
operations the AGT Rego library uses. Authors who hit a limit stay on
the Rego library which exposes the full strength surface. The limits
worth knowing.

- **No regex.** Cedar only supports the `like` operator with `*`
  wildcards. The `patterns.cedar` library detects PII structural
  signatures (email substring, dash separated SSN, dash separated
  credit card) only. The Rego library `data.agt.patterns` runs the
  canonical RE2 patterns from
  `agent-os/src/agent_os/integrations/base.py::PII_PATTERNS`.
- **No URL parser.** Cedar has no host extractor, no string
  `.contains`, no `.split`. The `egress.cedar` library compares a
  bare host or domain that the host SDK or an annotator has already
  projected into `context.tool_call.args.host`,
  `context.tool_call.args.domain`, or
  `context.annotations.egress.destination`. The Rego library
  `data.agt.egress` parses URLs and applies glob style host patterns.
- **No multi span transform.** Cedar annotations are static strings.
  The `redact.cedar` library can only emit a fixed transform payload
  that wholesale replaces `$policy_target.value` with the literal
  `"[REDACTED]"`. The Rego library `data.agt.redact` runs
  `regex.replace` to substitute matched spans in place.
- **Integer scoring only.** Cedar long values are integer typed and
  cannot compare floats with `>=` without a decimal conversion.
  Confidence and drift scores in the Cedar mirror MUST be scaled to
  integer ranges (for example 0..100) before they reach the snapshot.
  The float budgets `elapsed_seconds` and `cost_usd` are not modelled
  in `budgets.cedar`.
- **No lattice agility at evaluation time.** Cedar cannot iterate
  over a set to compute lattice closures inside policy evaluation.
  The `ifc.cedar` library expects the host to precompute the closure
  into the resource entity attribute `clearance_dominated_labels`.
  The Rego library `data.agt.ifc` exposes
  `dominates_with_lattice` and `verdict_with_lattice` that take the
  lattice document at call time.

## Test runner

Install the Cedar CLI once.

```sh
cargo install cedar-policy-cli --version '^4'
```

Run the suite.

```sh
./run_tests.sh
```

The runner sets `CEDAR_BIN` from the environment when present and
falls back to `cedar` on `PATH`, then to `~/.cargo/bin/cedar`. CI
calls the runner directly.
