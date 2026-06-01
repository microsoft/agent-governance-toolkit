use agent_control_specification_core::{
    action_identity, AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode,
    InterventionPoint, InterventionPointRequest, JsonValue, Limits, Manifest, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError, TelemetryEvent, TelemetryEventType,
    TelemetrySink, Verdict,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};

struct FixtureAnnotator {
    behavior: Option<String>,
    outputs: BTreeMap<String, JsonValue>,
}

impl FixtureAnnotator {
    fn empty() -> Arc<Self> {
        Arc::new(Self {
            behavior: None,
            outputs: BTreeMap::new(),
        })
    }

    fn with_output(name: &str, output: JsonValue) -> Arc<Self> {
        Arc::new(Self {
            behavior: None,
            outputs: BTreeMap::from([(name.to_string(), output)]),
        })
    }
}

impl AnnotatorDispatcher for FixtureAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        match self.behavior.as_deref() {
            Some("error") => Err(RuntimeError::AnnotationFailed("fixture".to_string())),
            Some("timeout") => Err(RuntimeError::AnnotationTimeout("fixture".to_string())),
            _ => Ok(self
                .outputs
                .get(annotator_name)
                .cloned()
                .unwrap_or_else(|| json!({"ok": true}))),
        }
    }
}

struct FixturePolicy {
    behavior: Option<String>,
    response: JsonValue,
}

impl FixturePolicy {
    fn output(response: JsonValue) -> Arc<Self> {
        Arc::new(Self {
            behavior: None,
            response,
        })
    }
}

impl PolicyDispatcher for FixturePolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match self.behavior.as_deref() {
            Some("error") => Err(RuntimeError::PolicyInvocationFailed("fixture".to_string())),
            _ => Ok(self.response.clone()),
        }
    }
}

struct RecordingTelemetry {
    events: Arc<Mutex<Vec<TelemetryEvent>>>,
}

impl TelemetrySink for RecordingTelemetry {
    fn emit(&self, event: TelemetryEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn manifest_yaml(extra: &str) -> String {
    format!(
        "{}{}",
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: test
intervention_points:
  input:
    policy:
      id: p
    policy_target: $snap.input
"#,
        extra
    )
}

fn runtime_with_limits(
    yaml: &str,
    annotator: Arc<dyn AnnotatorDispatcher>,
    policy: Arc<dyn PolicyDispatcher>,
    limits: Limits,
) -> Runtime {
    Runtime::with_limits(
        Manifest::from_yaml_str(yaml).unwrap(),
        annotator,
        policy,
        limits,
    )
    .unwrap()
}

fn evaluate_input(
    runtime: &Runtime,
    snapshot: JsonValue,
) -> agent_control_specification_core::InterventionPointResult {
    runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot,
        mode: EnforcementMode::Enforce,
    })
}

fn assert_deny_reason(
    result: &agent_control_specification_core::InterventionPointResult,
    reason: &str,
) {
    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(result.verdict.reason.as_deref(), Some(reason));
    assert!(result.transformed_policy_target.is_none());
}

fn nested_array(depth: usize) -> JsonValue {
    let mut value = json!("leaf");
    for _ in 0..depth {
        value = json!([value]);
    }
    value
}

fn target_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(name)
}

#[test]
fn runtime_error_reason_table_matches_spec_section_15() {
    let produced: BTreeSet<_> = [
        RuntimeError::ManifestInvalid(String::new()),
        RuntimeError::InterventionPointUnknown(String::new()),
        RuntimeError::PathMissing(String::new()),
        RuntimeError::PathTypeMismatch(String::new()),
        RuntimeError::ToolUnknown(String::new()),
        RuntimeError::AnnotationFailed(String::new()),
        RuntimeError::AnnotationTimeout(String::new()),
        RuntimeError::PolicyInvocationFailed(String::new()),
        RuntimeError::PolicyOutputInvalid(String::new()),
        RuntimeError::EffectInvalid(String::new()),
        RuntimeError::EffectTargetForbidden(String::new()),
        RuntimeError::ResourceLimitExceeded(String::new()),
        RuntimeError::ApprovalActionMismatch(String::new()),
    ]
    .into_iter()
    .map(|error| error.reason())
    .collect();

    // This list is the complete reserved reason table from spec section 15.
    let expected = BTreeSet::from([
        "runtime_error:manifest_invalid",
        "runtime_error:intervention_point_unknown",
        "runtime_error:path_missing",
        "runtime_error:path_type_mismatch",
        "runtime_error:tool_unknown",
        "runtime_error:annotation_failed",
        "runtime_error:annotation_timeout",
        "runtime_error:policy_invocation_failed",
        "runtime_error:policy_output_invalid",
        "runtime_error:effect_invalid",
        "runtime_error:effect_target_forbidden",
        "runtime_error:resource_limit_exceeded",
        "runtime_error:approval_action_mismatch",
    ]);

    assert_eq!(produced, expected);
}

#[test]
fn reserved_reason_inventory_matches_producers() {
    let inventory: Value =
        serde_json::from_str(include_str!("../../spec/reserved-reasons.json")).unwrap();
    let reasons = inventory["reasons"].as_array().unwrap();

    let core_runtime_inventory: BTreeSet<_> = reasons
        .iter()
        .filter(|entry| entry["producer"] == "core-runtime")
        .map(|entry| entry["reason"].as_str().unwrap())
        .collect();

    let core_runtime_produced: BTreeSet<_> = [
        RuntimeError::ManifestInvalid(String::new()),
        RuntimeError::InterventionPointUnknown(String::new()),
        RuntimeError::PathMissing(String::new()),
        RuntimeError::PathTypeMismatch(String::new()),
        RuntimeError::ToolUnknown(String::new()),
        RuntimeError::AnnotationFailed(String::new()),
        RuntimeError::AnnotationTimeout(String::new()),
        RuntimeError::PolicyInvocationFailed(String::new()),
        RuntimeError::PolicyOutputInvalid(String::new()),
        RuntimeError::EffectInvalid(String::new()),
        RuntimeError::EffectTargetForbidden(String::new()),
        RuntimeError::ResourceLimitExceeded(String::new()),
        RuntimeError::ApprovalActionMismatch(String::new()),
    ]
    .into_iter()
    .map(|error| error.reason())
    .collect();

    // The core-runtime subset of the inventory must equal exactly the reasons the
    // core runtime can produce. This prevents drift between the enum and the spec.
    assert_eq!(core_runtime_inventory, core_runtime_produced);

    // Every reason carries the reserved prefix and a known producer.
    for entry in reasons {
        let reason = entry["reason"].as_str().unwrap();
        let producer = entry["producer"].as_str().unwrap();
        assert!(reason.starts_with("runtime_error:"), "{reason}");
        assert!(
            producer == "core-runtime"
                || producer == "sdk-approval"
                || producer == "sdk-streaming"
                || producer == "sdk-adapter"
                || producer == "sdk-wire",
            "unknown producer {producer} for {reason}"
        );
    }

    for (reason, producer) in [
        ("runtime_error:streaming_unsupported", "sdk-streaming"),
        ("runtime_error:adapter_unsupported", "sdk-adapter"),
        ("runtime_error:request_invalid", "sdk-wire"),
    ] {
        let entry = reasons
            .iter()
            .find(|entry| entry["reason"] == reason)
            .unwrap_or_else(|| panic!("{reason} reason present"));
        assert_eq!(entry["producer"], producer);
        assert!(!core_runtime_produced.contains(reason));
    }
}

#[test]
fn dispatcher_boundary_reason_constants_match_enum() {
    use agent_control_specification_core::reserved_reason;

    assert_eq!(
        reserved_reason::ANNOTATION_TIMEOUT,
        RuntimeError::AnnotationTimeout(String::new()).reason()
    );
    assert_eq!(
        reserved_reason::ANNOTATION_FAILED,
        RuntimeError::AnnotationFailed(String::new()).reason()
    );
}

#[test]
fn every_runtime_error_reason_maps_to_deny_without_effects() {
    // AGT D1 removed `effects` from the verdict surface. This test now
    // verifies that runtime-error verdicts carry no transform and no
    // mutated policy target, preserving the same fail-closed invariant
    // ("a runtime error never rewrites the policy target") under D1.
    for error in [
        RuntimeError::ManifestInvalid(String::new()),
        RuntimeError::InterventionPointUnknown(String::new()),
        RuntimeError::PathMissing(String::new()),
        RuntimeError::PathTypeMismatch(String::new()),
        RuntimeError::ToolUnknown(String::new()),
        RuntimeError::AnnotationFailed(String::new()),
        RuntimeError::AnnotationTimeout(String::new()),
        RuntimeError::PolicyInvocationFailed(String::new()),
        RuntimeError::PolicyOutputInvalid(String::new()),
        RuntimeError::EffectInvalid(String::new()),
        RuntimeError::EffectTargetForbidden(String::new()),
        RuntimeError::ResourceLimitExceeded(String::new()),
        RuntimeError::ApprovalActionMismatch(String::new()),
    ] {
        let verdict = Verdict::runtime_error(&error);
        assert_eq!(verdict.decision, Decision::Deny, "{}", error.reason());
        assert_eq!(verdict.reason.as_deref(), Some(error.reason()));
        assert!(verdict.transform.is_none(), "{}", error.reason());
    }
}

#[test]
fn executable_parity_fixture_fails_closed_for_build_and_evaluate_reasons() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/conformance/fail_closed_error_parity.json"
    ))
    .unwrap();
    let reasons: BTreeSet<_> = fixture["reserved_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reason| reason.as_str().unwrap())
        .collect();
    let covered: BTreeSet<_> = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["expected_reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons.len(), 12);
    assert_eq!(covered, reasons);

    for case in fixture["cases"].as_array().unwrap() {
        let expected_reason = case["expected_reason"].as_str().unwrap();
        let manifest_yaml = case["manifest_yaml"].as_str().unwrap();
        let annotator = Arc::new(FixtureAnnotator {
            behavior: case
                .get("annotator_behavior")
                .and_then(Value::as_str)
                .map(str::to_string),
            outputs: BTreeMap::new(),
        });
        let policy = Arc::new(FixturePolicy {
            behavior: case
                .get("policy_behavior")
                .and_then(Value::as_str)
                .map(str::to_string),
            response: case
                .get("policy_response")
                .cloned()
                .unwrap_or_else(|| json!({"decision": "allow"})),
        });
        let runtime = Manifest::from_yaml_str(manifest_yaml)
            .and_then(|manifest| Runtime::new(manifest, annotator, policy));

        if case["operation"].as_str().unwrap() == "build" {
            let error = match runtime {
                Ok(_) => panic!(
                    "{} should fail closed while building",
                    case["id"].as_str().unwrap()
                ),
                Err(error) => error,
            };
            assert_eq!(error.reason(), expected_reason);
            continue;
        }

        let runtime = runtime.unwrap();
        let result = runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::from_str(
                case["intervention_point"].as_str().unwrap(),
            )
            .unwrap(),
            snapshot: case["snapshot"].clone(),
            mode: EnforcementMode::Enforce,
        });
        assert_deny_reason(&result, expected_reason);
    }
}

#[test]
fn error_paths_never_apply_policy_effects() {
    // AGT D1 sunsets effects on verdicts. The same invariant ("a policy
    // cannot mutate state outside `$policy_target`") is now enforced on
    // the transform decision path, surfaced as `transform_target_forbidden`.
    let yaml = manifest_yaml("");
    let runtime = runtime_with_limits(
        &yaml,
        FixtureAnnotator::empty(),
        FixturePolicy::output(json!({
            "decision": "transform",
            "transform": {"path": "$snap.input.text", "value": "mutated"}
        })),
        Limits::default(),
    );

    let result = evaluate_input(&runtime, json!({"input": {"text": "original"}}));

    assert_deny_reason(&result, "runtime_error:transform_target_forbidden");
    assert_eq!(
        result.policy_input.unwrap()["policy_target"]["value"]["text"],
        "original"
    );
}

#[test]
fn extends_root_confinement_rejects_escape_and_unsupported_url_extends() {
    let root = target_dir("security-conformance-extends");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("trusted")).unwrap();
    fs::write(root.join("outside.yaml"), manifest_yaml("")).unwrap();
    fs::write(
        root.join("trusted").join("escape.yaml"),
        "agent_control_specification_version: 0.3.1-beta\nextends:\n  - ../outside.yaml\n",
    )
    .unwrap();
    fs::write(
        root.join("trusted").join("url.yaml"),
        "agent_control_specification_version: 0.3.1-beta\nextends:\n  - http://example.invalid/base.yaml\n",
    )
    .unwrap();

    let escape = Manifest::from_path(root.join("trusted").join("escape.yaml")).unwrap_err();
    assert_eq!(escape.reason(), "runtime_error:manifest_invalid");
    let url = Manifest::from_path(root.join("trusted").join("url.yaml")).unwrap_err();
    assert_eq!(url.reason(), "runtime_error:manifest_invalid");
}

#[test]
fn annotator_outputs_are_confined_and_bad_outputs_fail_closed() {
    let yaml = manifest_yaml(
        "    annotations:\n      classifier:\n        from: $policy_target\nannotators:\n  classifier:\n    type: classifier\n",
    );
    let confined_runtime = runtime_with_limits(
        &yaml,
        FixtureAnnotator::with_output(
            "classifier",
            json!({
                "snapshot": {"input": "evil"},
                "policy_target": {"value": "evil"},
                "tool": {"name": "evil"},
                "intervention_point": "evil"
            }),
        ),
        FixturePolicy::output(json!({"decision": "allow"})),
        Limits::default(),
    );
    let confined = evaluate_input(&confined_runtime, json!({"input": "original"}));
    assert_eq!(confined.verdict.decision, Decision::Allow);
    let policy_input = confined.policy_input.unwrap();
    assert_eq!(policy_input["snapshot"], json!({"input": "original"}));
    assert_eq!(policy_input["policy_target"]["value"], json!("original"));
    assert_eq!(policy_input["tool"], JsonValue::Null);
    assert_eq!(policy_input["intervention_point"], json!("input"));
    assert_eq!(
        policy_input["annotations"]["classifier"]["snapshot"]["input"],
        "evil"
    );

    for output in [
        json!({"reason": "runtime_error:path_missing"}),
        json!({"large": "abcdefghijklmnopqrstuvwxyz"}),
    ] {
        let runtime = runtime_with_limits(
            &yaml,
            FixtureAnnotator::with_output("classifier", output),
            FixturePolicy::output(json!({"decision": "allow"})),
            Limits {
                max_annotator_output_bytes: 16,
                ..Limits::default()
            },
        );
        let result = evaluate_input(&runtime, json!({"input": "original"}));
        assert_deny_reason(&result, "runtime_error:annotation_failed");
    }
}

#[test]
fn configured_resource_limits_fail_closed_with_expected_reasons() {
    let yaml = manifest_yaml("");
    let oversized_snapshot = runtime_with_limits(
        &yaml,
        FixtureAnnotator::empty(),
        FixturePolicy::output(json!({"decision": "allow"})),
        Limits {
            max_snapshot_bytes: 16,
            ..Limits::default()
        },
    );
    assert_deny_reason(
        &evaluate_input(
            &oversized_snapshot,
            json!({"input": "abcdefghijklmnopqrstuvwxyz"}),
        ),
        "runtime_error:resource_limit_exceeded",
    );

    let shallow_policy_input = runtime_with_limits(
        &yaml,
        FixtureAnnotator::empty(),
        FixturePolicy::output(json!({"decision": "allow"})),
        Limits {
            max_policy_input_depth: 1,
            ..Limits::default()
        },
    );
    assert_deny_reason(
        &evaluate_input(&shallow_policy_input, json!({"input": "x"})),
        "runtime_error:resource_limit_exceeded",
    );

    let many_annotators_yaml = manifest_yaml(
        "    annotations:\n      a:\n        from: $policy_target\n      b:\n        from: $policy_target\nannotators:\n  a:\n    type: classifier\n  b:\n    type: classifier\n",
    );
    let too_many_annotators = runtime_with_limits(
        &many_annotators_yaml,
        FixtureAnnotator::empty(),
        FixturePolicy::output(json!({"decision": "allow"})),
        Limits {
            max_annotators_per_point: 1,
            ..Limits::default()
        },
    );
    assert_deny_reason(
        &evaluate_input(&too_many_annotators, json!({"input": "x"})),
        "runtime_error:resource_limit_exceeded",
    );

    let annotation_yaml = manifest_yaml(
        "    annotations:\n      classifier:\n        from: $policy_target\nannotators:\n  classifier:\n    type: classifier\n",
    );
    let oversized_annotator_output = runtime_with_limits(
        &annotation_yaml,
        FixtureAnnotator::with_output("classifier", json!({"large": "abcdefghijklmnopqrstuvwxyz"})),
        FixturePolicy::output(json!({"decision": "allow"})),
        Limits {
            max_annotator_output_bytes: 16,
            ..Limits::default()
        },
    );
    assert_deny_reason(
        &evaluate_input(&oversized_annotator_output, json!({"input": "x"})),
        "runtime_error:annotation_failed",
    );

    let root = target_dir("security-conformance-limits");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    for index in 0..4 {
        let extends = if index < 3 {
            format!("extends:\n  - m{}.yaml\n", index + 1)
        } else {
            String::new()
        };
        fs::write(
            root.join(format!("m{index}.yaml")),
            format!("agent_control_specification_version: 0.3.1-beta\n{extends}"),
        )
        .unwrap();
    }
    let depth = Manifest::from_path_with_limits(
        root.join("m0.yaml"),
        Limits {
            max_extends_depth: 3,
            ..Limits::default()
        },
    )
    .unwrap_err();
    assert_eq!(depth.reason(), "runtime_error:resource_limit_exceeded");

    fs::write(
        root.join("large.yaml"),
        manifest_yaml("metadata:\n  large: abcdefghijklmnopqrstuvwxyz\n"),
    )
    .unwrap();
    let size = Manifest::from_path_with_limits(
        root.join("large.yaml"),
        Limits {
            max_merged_manifest_bytes: 64,
            ..Limits::default()
        },
    )
    .unwrap_err();
    assert_eq!(size.reason(), "runtime_error:resource_limit_exceeded");

    let deep_snapshot_runtime = runtime_with_limits(
        &yaml,
        FixtureAnnotator::empty(),
        FixturePolicy::output(json!({"decision": "allow"})),
        Limits::default(),
    );
    assert_deny_reason(
        &evaluate_input(&deep_snapshot_runtime, json!({"input": nested_array(65)})),
        "runtime_error:resource_limit_exceeded",
    );
}

#[test]
fn approval_invariant_has_stable_core_action_identity_and_fail_closed_reason() {
    let runtime = runtime_with_limits(
        &manifest_yaml(""),
        FixtureAnnotator::empty(),
        FixturePolicy::output(json!({"decision": "escalate"})),
        Limits::default(),
    );
    let snapshot = json!({"input": {"b": 2, "a": 1}});
    let first = evaluate_input(&runtime, snapshot.clone());
    let second = evaluate_input(&runtime, snapshot);

    assert_eq!(first.verdict.decision, Decision::Escalate);
    assert_eq!(first.action_identity, second.action_identity);
    assert_eq!(
        first.action_identity.as_deref(),
        Some(
            action_identity(first.policy_input.as_ref().unwrap())
                .unwrap()
                .as_str()
        )
    );
    let mismatch = Verdict::runtime_error(&RuntimeError::ApprovalActionMismatch(
        "approved action identity differed".to_string(),
    ));
    assert_eq!(mismatch.decision, Decision::Deny);
    assert_eq!(
        mismatch.reason.as_deref(),
        Some("runtime_error:approval_action_mismatch")
    );
}

#[test]
fn evaluate_only_records_would_be_deny_without_transforming_target() {
    // AGT D1: a deny verdict that previously rode with effects (and got
    // them rejected at the runtime layer) is now rejected at the
    // normalization layer because `effects` is no longer permitted at all.
    // The test preserves the original "deny + would-be effects do not
    // mutate state" invariant by sending the deny verdict alone and
    // confirming the policy target is untouched in evaluate-only mode.
    let events = Arc::new(Mutex::new(Vec::new()));
    let telemetry = Arc::new(RecordingTelemetry {
        events: events.clone(),
    });
    let runtime = Runtime::with_telemetry(
        Manifest::from_yaml_str(&manifest_yaml("")).unwrap(),
        FixtureAnnotator::empty(),
        FixturePolicy::output(json!({
            "decision": "deny",
            "reason": "policy_denied"
        })),
        telemetry,
    )
    .unwrap();

    let result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": "original"}),
        mode: EnforcementMode::EvaluateOnly,
    });

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(result.verdict.reason.as_deref(), Some("policy_denied"));
    assert!(result.transformed_policy_target.is_none());
    assert_eq!(
        result.policy_input.unwrap()["policy_target"]["value"],
        "original"
    );
    let decision = events
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.event_type == TelemetryEventType::Decision)
        .cloned()
        .expect("decision telemetry");
    assert_eq!(decision.decision, Some(Decision::Deny));
    assert_eq!(decision.reason_code.as_deref(), Some("policy_denied"));
    assert_eq!(
        decision.enforcement_mode,
        Some(EnforcementMode::EvaluateOnly)
    );
}
