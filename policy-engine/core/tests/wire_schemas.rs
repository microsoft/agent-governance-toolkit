use jsonschema::JSONSchema;
use serde_json::{json, Value};
use std::{fs, path::Path};

fn load_json(path: &Path) -> Value {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&source)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn schema_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../spec/schema/wire")
        .canonicalize()
        .expect("schema directory exists")
}

fn compile_schema(name: &str) -> JSONSchema {
    let schema = load_json(&schema_root().join(name));
    JSONSchema::compile(&schema).unwrap_or_else(|err| panic!("failed to compile {name}: {err}"))
}

fn assert_valid(schema: &JSONSchema, instance: &Value, label: &str) {
    if let Err(errors) = schema.validate(instance) {
        let messages: Vec<_> = errors.map(|error| error.to_string()).collect();
        panic!("{label} failed schema validation: {}", messages.join("; "));
    }
}

#[test]
fn policy_input_fixtures_validate_against_wire_schemas() {
    let policy_input_schema = compile_schema("policy-input.schema.json");
    let snapshot_schema = compile_schema("snapshot.schema.json");
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policy-inputs");
    let mut paths: Vec<_> = fs::read_dir(&fixtures_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", fixtures_dir.display()))
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "policy input fixtures are present");

    for path in paths {
        let fixture = load_json(&path);
        let label = path.display().to_string();
        assert_valid(&policy_input_schema, &fixture, &label);
        assert_valid(
            &snapshot_schema,
            &fixture["snapshot"],
            &format!("{label} snapshot"),
        );
    }
}

#[test]
fn verdict_and_effect_samples_validate_against_wire_schemas() {
    let verdict_schema = compile_schema("verdict.schema.json");
    let effect_schema = compile_schema("effect.schema.json");

    // AGT D1 + D2 verdict samples. The old upstream samples that used
    // the effects[] array are no longer valid against the AGT wire
    // schema; the migration replaces them with transform decisions and
    // an evidence-bearing allow.
    let verdicts = [
        json!({"decision": "allow"}),
        json!({"decision": "deny", "reason": "policy:blocked"}),
        json!({"decision": "escalate", "reason": "policy:approval_required"}),
        json!({"decision": "warn", "reason": "policy:content_warning", "message": "Heads up."}),
        json!({"decision": "allow", "result_labels": ["confidential"]}),
        json!({
            "decision": "transform",
            "reason": "policy:redacted",
            "transform": {
                "path": "$policy_target.content",
                "value": "[REDACTED]"
            }
        }),
        json!({
            "decision": "allow",
            "evidence": {
                "artefact": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "verification_pointers": {
                    "issuer_pubkey": "https://example.com/keys/2026.pem",
                    "policy_registry": "https://example.com/policies/v1/"
                }
            }
        }),
    ];

    for (index, verdict) in verdicts.iter().enumerate() {
        assert_valid(&verdict_schema, verdict, &format!("verdict sample {index}"));
    }

    // The legacy effect-shape samples still validate against the standalone
    // effect.schema.json (the schema for the upstream effects[] entries),
    // but the verdict schema no longer permits the effects key.
    let legacy_effects = [
        json!({"type": "replace", "path": "$policy_target.flag", "value": true}),
        json!({"type": "append", "path": "$policy_target.items", "value": "tail"}),
        json!({"type": "prepend", "path": "$policy_target.items", "value": "head"}),
        json!({
            "type": "redact",
            "path": "$policy_target.content",
            "spans": [{"start": 0, "end": 6, "replacement": "[REDACTED]"}]
        }),
        json!({
            "type": "redact",
            "path": "$policy_target.content",
            "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
            "replacement": "[REDACTED]"
        }),
        json!({
            "type": "redact",
            "path": "$policy_target.content",
            "values": ["secret"],
            "replacement": "[REDACTED]"
        }),
    ];
    for (index, effect) in legacy_effects.iter().enumerate() {
        assert_valid(&effect_schema, effect, &format!("legacy effect {index}"));
    }

    // Negative: a verdict carrying the effects key (even when null or
    // empty) MUST fail validation per AGT D1.
    let rejected = [
        json!({"decision": "allow", "effects": null}),
        json!({"decision": "allow", "effects": []}),
        json!({
            "decision": "allow",
            "effects": [{"type": "replace", "path": "$policy_target.x", "value": 1}]
        }),
        json!({
            "decision": "transform"
        }),
        json!({
            "decision": "allow",
            "transform": {"path": "$policy_target.x", "value": 1}
        }),
        json!({
            "decision": "transform",
            "transform": {"path": "$snap.x", "value": 1}
        }),
    ];
    for (index, instance) in rejected.iter().enumerate() {
        assert!(
            !verdict_schema.is_valid(instance),
            "expected wire schema to REJECT verdict {index}: {instance}",
        );
    }
}

#[test]
fn tool_call_id_is_optional_in_snapshot_wire_schemas() {
    let policy_input_schema = compile_schema("policy-input.schema.json");
    let snapshot_schema = compile_schema("snapshot.schema.json");

    let pre_tool_snapshot_without_id = json!({
        "tool_call": {
            "name": "search",
            "args": {"query": "policy"}
        }
    });
    let post_tool_snapshot_without_id = json!({
        "tool_call": {
            "name": "search"
        },
        "tool_result": {"items": []}
    });
    let pre_tool_policy_input_without_id = json!({
        "intervention_point": "pre_tool_call",
        "policy_target": {
            "kind": "tool_args",
            "path": "$snap.tool_call.args",
            "value": {"query": "policy"}
        },
        "snapshot": pre_tool_snapshot_without_id,
        "annotations": {},
        "tool": {
            "name": "search"
        }
    });

    assert_valid(
        &snapshot_schema,
        &pre_tool_snapshot_without_id,
        "pre tool snapshot without id",
    );
    assert_valid(
        &snapshot_schema,
        &post_tool_snapshot_without_id,
        "post tool snapshot without id",
    );
    assert_valid(
        &policy_input_schema,
        &pre_tool_policy_input_without_id,
        "policy input with pre tool snapshot without id",
    );
}
