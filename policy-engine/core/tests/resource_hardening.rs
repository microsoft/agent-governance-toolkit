use agent_control_specification_core::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Limits, Manifest, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

struct StaticAnnotator {
    outputs: BTreeMap<String, JsonValue>,
}

impl StaticAnnotator {
    fn new(outputs: BTreeMap<String, JsonValue>) -> Arc<Self> {
        Arc::new(Self { outputs })
    }
}

impl AnnotatorDispatcher for StaticAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(self
            .outputs
            .get(annotator_name)
            .cloned()
            .unwrap_or(JsonValue::Null))
    }
}

struct ErrorAnnotator {
    error: RuntimeError,
}

impl ErrorAnnotator {
    fn new(error: RuntimeError) -> Arc<Self> {
        Arc::new(Self { error })
    }
}

impl AnnotatorDispatcher for ErrorAnnotator {
    fn dispatch(
        &self,
        _annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Err(self.error.clone())
    }
}

struct StaticPolicy;

impl PolicyDispatcher for StaticPolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        Ok(json!({"decision": "allow"}))
    }
}

struct OutputPolicy(JsonValue);

impl PolicyDispatcher for OutputPolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        Ok(self.0.clone())
    }
}

struct EchoAnnotationReasonPolicy;

impl PolicyDispatcher for EchoAnnotationReasonPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let input = invocation.policy_input().expect("test policy input");
        Ok(json!({
            "decision": "deny",
            "reason": input["annotations"]["classifier"]["reason"].clone()
        }))
    }
}

fn base_manifest(extra: &str) -> Manifest {
    let yaml = format!(
        "{}{}",
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: p
    policy_target: $snap.input
"#,
        extra
    );
    Manifest::from_yaml_str(&yaml).unwrap()
}

fn manifest_with_annotations(names: &[&str]) -> Manifest {
    let annotations = names
        .iter()
        .map(|name| format!("      {name}:\n        from: $policy_target\n"))
        .collect::<String>();
    let annotators = names
        .iter()
        .map(|name| format!("  {name}:\n    type: classifier\n"))
        .collect::<String>();
    base_manifest(&format!(
        "    annotations:\n{annotations}annotators:\n{annotators}"
    ))
}

fn runtime(
    manifest: Manifest,
    annotations: Arc<dyn AnnotatorDispatcher>,
    policy: Arc<dyn PolicyDispatcher>,
    limits: Limits,
) -> Runtime {
    Runtime::with_limits(manifest, annotations, policy, limits).unwrap()
}

fn evaluate(
    runtime: &Runtime,
    snapshot: JsonValue,
) -> agent_control_specification_core::InterventionPointResult {
    runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot,
        mode: EnforcementMode::Enforce,
    })
}

fn nested_array(depth: usize) -> Value {
    let mut value = json!("leaf");
    for _ in 0..depth {
        value = json!([value]);
    }
    value
}

#[test]
fn oversized_snapshot_fails_with_resource_limit_reason() {
    let limits = Limits {
        max_snapshot_bytes: 32,
        ..Limits::default()
    };
    let runtime = runtime(
        base_manifest(""),
        StaticAnnotator::new(BTreeMap::new()),
        Arc::new(StaticPolicy),
        limits,
    );

    let result = evaluate(&runtime, json!({"input": "abcdefghijklmnopqrstuvwxyz"}));

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:resource_limit_exceeded")
    );
}

#[test]
fn too_deep_snapshot_fails_with_resource_limit_reason() {
    let limits = Limits {
        max_policy_input_depth: 4,
        ..Limits::default()
    };
    let runtime = runtime(
        base_manifest(""),
        StaticAnnotator::new(BTreeMap::new()),
        Arc::new(StaticPolicy),
        limits,
    );

    let result = evaluate(&runtime, json!({"input": nested_array(5)}));

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:resource_limit_exceeded")
    );
}

#[test]
fn too_many_annotators_fail_with_resource_limit_reason() {
    let limits = Limits {
        max_annotators_per_point: 1,
        ..Limits::default()
    };
    let runtime = runtime(
        manifest_with_annotations(&["a", "b"]),
        StaticAnnotator::new(BTreeMap::new()),
        Arc::new(StaticPolicy),
        limits,
    );

    let result = evaluate(&runtime, json!({"input": "hello"}));

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:resource_limit_exceeded")
    );
}

#[test]
fn annotator_output_is_size_limited_as_annotation_failed() {
    let limits = Limits {
        max_annotator_output_bytes: 16,
        ..Limits::default()
    };
    let mut outputs = BTreeMap::new();
    outputs.insert(
        "classifier".to_string(),
        json!({"label": "this is too large"}),
    );
    let runtime = runtime(
        manifest_with_annotations(&["classifier"]),
        StaticAnnotator::new(outputs),
        Arc::new(StaticPolicy),
        limits,
    );

    let result = evaluate(&runtime, json!({"input": "hello"}));

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:annotation_failed")
    );
}

#[test]
fn oversized_policy_output_fails_with_resource_limit_reason() {
    let limits = Limits {
        max_policy_output_bytes: 64,
        ..Limits::default()
    };
    let runtime = runtime(
        base_manifest(""),
        StaticAnnotator::new(BTreeMap::new()),
        Arc::new(OutputPolicy(json!({
            "decision": "allow",
            "message": "x".repeat(128),
        }))),
        limits,
    );

    let result = evaluate(&runtime, json!({"input": "hello"}));

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:resource_limit_exceeded")
    );
}

#[test]
fn transformed_snapshot_size_is_limited_after_transform() {
    let limits = Limits {
        max_snapshot_bytes: 64,
        ..Limits::default()
    };
    let runtime = runtime(
        base_manifest(""),
        StaticAnnotator::new(BTreeMap::new()),
        Arc::new(OutputPolicy(json!({
            "decision": "transform",
            "transform": {"path": "$policy_target.payload", "value": "x".repeat(128)},
        }))),
        limits,
    );

    let result = evaluate(&runtime, json!({"input": {"payload": "ok"}}));

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:resource_limit_exceeded")
    );
    assert!(result.transformed_policy_target.is_none());
}

#[test]
fn annotator_output_policy_target_stays_under_annotations() {
    let mut outputs = BTreeMap::new();
    outputs.insert(
        "classifier".to_string(),
        json!({
            "policy_target": {"value": "evil"},
            "snapshot": {"input": "evil"},
            "label": "low"
        }),
    );
    let runtime = runtime(
        manifest_with_annotations(&["classifier"]),
        StaticAnnotator::new(outputs),
        Arc::new(StaticPolicy),
        Limits::default(),
    );

    let result = evaluate(&runtime, json!({"input": "original"}));
    let policy_input = result.policy_input.expect("final policy input");

    assert_eq!(result.verdict.decision, Decision::Allow);
    assert_eq!(policy_input["policy_target"]["value"], json!("original"));
    assert_eq!(policy_input["snapshot"], json!({"input": "original"}));
    assert_eq!(
        policy_input["annotations"]["classifier"]["policy_target"]["value"],
        json!("evil")
    );
}

#[test]
fn annotator_output_cannot_spoof_runtime_error_reason() {
    let mut outputs = BTreeMap::new();
    outputs.insert(
        "classifier".to_string(),
        json!({"reason": "runtime_error:path_missing"}),
    );
    let runtime = runtime(
        manifest_with_annotations(&["classifier"]),
        StaticAnnotator::new(outputs),
        Arc::new(EchoAnnotationReasonPolicy),
        Limits::default(),
    );

    let result = evaluate(&runtime, json!({"input": "hello"}));

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:annotation_failed")
    );
}

#[test]
fn annotation_failure_message_preserves_dispatch_detail() {
    let runtime = runtime(
        manifest_with_annotations(&["classifier"]),
        ErrorAnnotator::new(RuntimeError::AnnotationFailed(
            "classifier: aacs HTTP 400 {\"error\":\"content_filter\"}".to_string(),
        )),
        Arc::new(StaticPolicy),
        Limits::default(),
    );

    let result = evaluate(&runtime, json!({"input": "hello"}));

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:annotation_failed")
    );
    assert!(
        result
            .verdict
            .message
            .as_deref()
            .is_some_and(|message| message.contains("content_filter")),
        "annotation failure message should preserve the dispatcher detail"
    );
}

#[test]
fn manifest_extends_depth_limit_fails_closed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("resource-hardening-tests");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    for index in 0..4 {
        let next = if index < 3 {
            format!("extends:\n  - m{}.yaml\n", index + 1)
        } else {
            String::new()
        };
        let body = if index == 3 {
            concat!(
                "agent_control_specification_version: 0.3.1-beta\n",
                "policies:\n",
                "  p:\n",
                "    type: test\n",
                "intervention_points:\n",
                "  input:\n",
                "    policy:\n",
                "      id: p\n",
                "    policy_target: $snap.input\n",
            )
            .to_string()
        } else {
            format!("agent_control_specification_version: 0.3.1-beta\n{next}")
        };
        fs::write(root.join(format!("m{index}.yaml")), body).unwrap();
    }

    let error = Manifest::from_path_with_limits(
        root.join("m0.yaml"),
        Limits {
            max_extends_depth: 3,
            ..Limits::default()
        },
    )
    .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:resource_limit_exceeded");
}

#[test]
fn merged_manifest_size_limit_fails_closed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("resource-hardening-size-tests");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("manifest.yaml"),
        concat!(
            "agent_control_specification_version: 0.3.1-beta\n",
            "metadata:\n",
            "  large: abcdefghijklmnopqrstuvwxyz\n",
            "policies:\n",
            "  p:\n",
            "    type: test\n",
            "intervention_points:\n",
            "  input:\n",
            "    policy:\n",
            "      id: p\n",
            "    policy_target: $snap.input\n",
        ),
    )
    .unwrap();

    let error = Manifest::from_path_with_limits(
        root.join("manifest.yaml"),
        Limits {
            max_merged_manifest_bytes: 64,
            ..Limits::default()
        },
    )
    .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:resource_limit_exceeded");
}
