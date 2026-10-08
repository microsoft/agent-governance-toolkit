---
title: Rust 5.0 YAML migration
last_reviewed: 2026-09-18
owner: microsoft/agent-governance-toolkit
---

# Rust 5.0 YAML migration

This change targets the pending Rust 5.0 major release, not a 4.x patch.
The latest published `agentmesh` version checked on September 15, 2026 was
4.0.0. The workspace already declares 5.0.0. Do not republish an existing
artifact or tag to deliver this change.

## Policy contexts

Import `Context`, `Mapping` and `Value` from `agentmesh::policy_data`.
They use the JSON data model and do not expose the YAML parser.

| Previous API | Rust 5.0 API |
|---|---|
| `serde_yaml::Value` | `agentmesh::policy_data::Value` |
| `serde_yaml::Mapping` | `agentmesh::policy_data::Mapping` |
| `Value::Mapping(map)` | `Value::Object(map)` |
| `Value::Sequence(values)` | `Value::Array(values)` |
| `map.insert(Value::String(key), value)` | `map.insert(key, value)` |
| YAML error payloads | `agentmesh::policy_data::YamlError` |

`PolicyRule.conditions`, `PolicyEngine::evaluate`,
`AgentMeshClient::execute_with_governance` and protocol extractor callbacks
use these values. This changes Rust type identity. Update custom callback
signatures and map constructors along with imports. The CLI's JSON context
format is unchanged.

```rust
use agentmesh::{policy_data::Context, PolicyEngine};

let context: Context = serde_json::from_str(r#"{"environment":"production"}"#)?;
let policy_yaml = r#"
version: "1"
agent: example
policies:
  - name: production
    type: capability
    denied_actions: ["deploy.*"]
    conditions: {environment: production}
"#;
let engine = PolicyEngine::new();
engine.load_from_yaml(policy_yaml)?;
let decision = engine.evaluate("deploy.app", Some(&context));
# Ok::<(), Box<dyn std::error::Error>>(())
```

YAML and JSON policies remain supported. Conditions retain case-sensitive
equality and sequence membership. Nested string-keyed objects, arrays,
booleans, null, 64-bit integers and finite floating-point numbers are supported.
Out-of-range integers are rejected rather than rounded. Numeric and string values
remain distinct. Non-string mapping keys, non-finite numbers, duplicate keys
and unsupported tags are rejected rather than converted or ignored.
Typed string fields no longer coerce unquoted numbers, booleans or null.
In particular, write `version: "1"` or `version: "1.0"`, not `version: 1`
or `version: 1.0`. Numeric `agent` values and boolean-looking rule names also
need quotes. An empty plain value is null, not an empty string; use `""`
for an empty string. Quote canonical number-, boolean- and null-looking
mapping keys as well. Legacy forms such as
`010` and `1_000` retain their string type and are rejected in numeric fields.
YAML 1.2 boolean spellings retain their types, while mixed-case forms such as
`tRuE` remain strings. YAML aliases remain supported within
resource limits. Merge keys remain literal keys, not inherited policy fields.
Granit 1.2.1 accepts tabs after mapping colons and sequence dashes, and
accepts a tab following spaces in indentation. A tab at the start of an
indented line is still rejected. Reserved directives such as `%FOO bar`
are ignored. Space-then-tab indentation, dash-tab separation and reserved
directives are intentional parser relaxations compared with libyaml;
regressions pin their resulting values and policy decisions.
Non-specific `!` tags are rejected on scalars and collections alike.

The core shim owns one scalar-normalization pre-pass, re-exported through
the host SDK and reused by agentmesh. Both consumers retain their separate
bounded deserialization and error contracts.
Typed configurations require mappings at every struct boundary, including
policy profiles, rules and nested detector settings. Positional arrays are
rejected without replacing an already loaded policy.

`PolicyError::InvalidYaml` and `PromptInjectionError::ConfigParse` retain their
variant names but now contain `YamlError`. Its `location()` returns an optional
one-based `(line, column)` pair. Old `serde_yaml::Error` conversions and
downcasts are not preserved. Diagnostics omit source snippets.

Configuration loaders cap source size at 1 MiB, nesting at 64 levels and
parser nodes at 100,000, with additional event and retained-anchor budgets.
File reads are bounded before parsing. Invalid reloads leave the last valid
policy intact. Client construction and CLI checks propagate parse failures;
they do not substitute an allow policy. An intentionally empty engine retains
its existing allow behavior.

## Compiler and release gates

`serde-saphyr` 1.2.0 requires Rust 1.89. The Rust workspace already uses that
floor. AGT's policy-engine core, host SDK and their Rust consumers now declare
1.89 as well. The lockfiles select age-compliant `granit-parser` 1.2.1 and
`encoding_rs` 0.8.35.

The registry dependency is now `agent-control-spec 0.4.0-alpha.4`, which
includes the upstream `serde-saphyr` migration. The three consumer lockfiles
no longer contain the engine's `serde_yaml` and `unsafe-libyaml` dependencies.

AGT consumes the published engine through exact registry pins. Release the
versioned compatibility shim before its host SDK and dependent Rust packages.
No local engine patch or unpublished package is needed for this parser change.

Agentmesh requests Regorus with `regex` only. The policy-engine workspace
also supports the core shim's opt-in `rego` feature. That graph retains
`yaml_serde` and `libyaml-rs` for Regorus YAML builtins. The engine parser
migration does not disable those builtins or imply that the full dependency
graph contains no unsafe code.
