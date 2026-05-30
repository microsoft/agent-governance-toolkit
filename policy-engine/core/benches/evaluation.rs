use agent_control_specification_core::{
    build_policy_input, effects::validate_and_maybe_apply_effects, normalize_policy_output, Effect,
    InterventionPoint, Manifest,
};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use serde_json::{json, Value};
use std::hint::black_box;

const BASE_MANIFEST: &str = r#"
agent_control_specification_version: "0.3.0-alpha"
metadata:
  name: perf-harness
policies:
  shared_policy:
    type: test
  duplicate_policy:
    type: test
intervention_points:
  input:
    policy_target: "$snap.input"
    policy_target_kind: user_input
    annotations:
      base_classifier:
        from: "$policy_target.text"
    policy:
      id: shared_policy
annotators:
  base_classifier:
    type: classifier
tools:
  search:
    type: Tool
    id: search
    clearance: [public]
"#;

const MID_MANIFEST: &str = r#"
agent_control_specification_version: "0.3.0-alpha"
metadata:
  name: perf-harness
policies:
  duplicate_policy:
    type: test
intervention_points:
  output:
    policy_target: "$snap.output"
    policy_target_kind: assistant_output
    policy:
      id: shared_policy
tools:
  search:
    type: Tool
    id: search
    clearance: [public]
"#;

const CHILD_MANIFEST: &str = r#"
agent_control_specification_version: "0.3.0-alpha"
metadata:
  name: perf-harness
policies:
  child_policy:
    type: test
  duplicate_policy:
    type: test
intervention_points:
  input:
    policy_target: "$snap.input"
    policy_target_kind: user_input
    annotations:
      child_classifier:
        from: "$pi.snapshot.actor.id"
    policy:
      id: shared_policy
  pre_tool_call:
    policy_target: "$snap.tool_call.args"
    policy_target_kind: tool_args
    tool_name_from: "$snap.tool_call.name"
    policy:
      id: child_policy
annotators:
  child_classifier:
    type: endpoint
    endpoint: https://annotators.invalid/actor
tools:
  wire_transfer:
    type: Tool
    id: wire_transfer
    clearance: [banking, payments]
"#;

fn representative_snapshot() -> Value {
    json!({
        "actor": {"id": "user-314", "roles": ["analyst", "payments"]},
        "input": {
            "text": "Transfer 125.50 USD from checking to savings after reviewing account 123456789.",
            "messages": [
                {"role": "system", "content": "Use least privilege."},
                {"role": "user", "content": "Summarize recent transactions and prepare a transfer."}
            ],
            "metadata": {"channel": "cli", "trace_id": "trace-perf-0001"}
        },
        "tool_call": {
            "name": "wire_transfer",
            "args": {
                "from_account": "123456789",
                "to_account": "987654321",
                "amount": 125.50,
                "currency": "USD",
                "memo": "monthly savings"
            }
        },
        "output": {
            "text": "I reviewed account 123456789 and prepared the transfer.",
            "citations": ["ledger://transactions/2024-06"]
        }
    })
}

fn representative_annotations() -> Value {
    json!({
        "base_classifier": {"label": "financial", "confidence": 0.98},
        "child_classifier": {"label": "payment", "confidence": 0.94}
    })
}

fn representative_tool() -> Value {
    json!({
        "name": "wire_transfer",
        "type": "Tool",
        "id": "wire_transfer",
        "clearance": ["banking", "payments"]
    })
}

fn policy_target_value(snapshot: &Value) -> Value {
    snapshot["tool_call"]["args"].clone()
}

fn policy_output_with_effects() -> Value {
    json!({
        "decision": "warn",
        "reason": "sensitive_account",
        "message": "Proceed after redacting account identifiers.",
        "effects": [
            {"type": "prepend", "path": "$policy_target.items", "value": "head"},
            {"type": "append", "path": "$policy_target.items", "value": "tail"},
            {"type": "redact", "path": "$policy_target.content", "spans": [
                {"start": 8, "end": 17, "replacement": "[account]"},
                {"start": 32, "end": 41, "replacement": "[account]"}
            ]},
            {"type": "replace", "path": "$policy_target.flag", "value": true}
        ]
    })
}

fn policy_target_for_effects() -> Value {
    json!({
        "items": ["existing"],
        "content": "Account 123456789 linked to 987654321 requires review.",
        "flag": false
    })
}

fn effects_for_redaction() -> Vec<Effect> {
    normalize_policy_output(policy_output_with_effects())
        .expect("policy output should normalize")
        .effects
}

fn bench_build_policy_input(c: &mut Criterion) {
    let snapshot = representative_snapshot();
    let annotations = representative_annotations();
    let tool = representative_tool();
    let target_value = policy_target_value(&snapshot);

    c.bench_function("build_policy_input_representative_snapshot", |b| {
        b.iter_batched(
            || {
                (
                    target_value.clone(),
                    snapshot.clone(),
                    annotations.clone(),
                    tool.clone(),
                )
            },
            |(target_value, snapshot, annotations, tool)| {
                black_box(build_policy_input(
                    InterventionPoint::PreToolCall,
                    "$snap.tool_call.args",
                    Some("tool_args"),
                    target_value,
                    snapshot,
                    annotations,
                    tool,
                ))
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_manifest_parse_extends_merge(c: &mut Criterion) {
    c.bench_function("manifest_parse_extends_merge", |b| {
        b.iter(|| {
            black_box(
                Manifest::from_yaml_chain(black_box(&[
                    BASE_MANIFEST,
                    MID_MANIFEST,
                    CHILD_MANIFEST,
                ]))
                .expect("manifest chain should parse and merge"),
            )
        })
    });
}

fn bench_verdict_normalization(c: &mut Criterion) {
    c.bench_function("normalize_verdict_with_effects", |b| {
        b.iter_batched(
            policy_output_with_effects,
            |output| black_box(normalize_policy_output(output).expect("verdict should normalize")),
            BatchSize::SmallInput,
        )
    });
}

fn bench_redaction_effect_application(c: &mut Criterion) {
    let effects = effects_for_redaction();
    let target = policy_target_for_effects();

    c.bench_function("apply_redaction_effects", |b| {
        b.iter_batched(
            || target.clone(),
            |target| {
                black_box(
                    validate_and_maybe_apply_effects(&target, black_box(&effects), true)
                        .expect("effects should apply"),
                )
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_build_policy_input,
    bench_manifest_parse_extends_merge,
    bench_verdict_normalization,
    bench_redaction_effect_application
);
criterion_main!(benches);
