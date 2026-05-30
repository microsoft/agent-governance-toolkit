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
    let verdicts = [
        json!({"decision": "allow"}),
        json!({
            "decision": "warn",
            "reason": "policy:content_warning",
            "message": "Content was transformed.",
            "effects": [
                {"type": "replace", "path": "$policy_target.flag", "value": true},
                {"type": "append", "path": "$policy_target.items", "value": "tail"},
                {"type": "prepend", "path": "$policy_target.items", "value": "head"},
                {
                    "type": "redact",
                    "path": "$policy_target.content",
                    "spans": [{"start": 0, "end": 6, "replacement": "[REDACTED]"}]
                },
                {
                    "type": "redact",
                    "path": "$policy_target.content",
                    "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
                    "replacement": "[REDACTED]"
                },
                {
                    "type": "redact",
                    "path": "$policy_target.content",
                    "values": ["secret"],
                    "replacement": "[REDACTED]"
                }
            ]
        }),
        json!({"decision": "deny", "reason": "policy:blocked", "effects": null}),
        json!({"decision": "escalate", "reason": "policy:approval_required"}),
        json!({"decision": "allow", "result_labels": ["confidential"]}),
    ];

    for (index, verdict) in verdicts.iter().enumerate() {
        assert_valid(&verdict_schema, verdict, &format!("verdict sample {index}"));
        if let Some(effects) = verdict.get("effects").and_then(Value::as_array) {
            for (effect_index, effect) in effects.iter().enumerate() {
                assert_valid(
                    &effect_schema,
                    effect,
                    &format!("verdict sample {index} effect {effect_index}"),
                );
            }
        }
    }
}
