use agent_control_specification_core::{
    normalize_policy_output, Decision, Limits, RuntimeError, TelemetryEventType,
};
use jsonschema::JSONSchema;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn fixture(name: &str) -> Value {
    let source = std::fs::read_to_string(format!("../tests/parity/{name}"))
        .unwrap_or_else(|err| panic!("failed to read {name}: {err}"));
    serde_json::from_str(&source).unwrap_or_else(|err| panic!("failed to parse {name}: {err}"))
}

fn logging_style_vocabulary() -> Value {
    let source = std::fs::read_to_string("../docs/logging-style-guide.md")
        .expect("logging style guide exists");
    let block = source
        .split("<!-- acs telemetry vocabulary start -->")
        .nth(1)
        .and_then(|tail| tail.split("<!-- acs telemetry vocabulary end -->").next())
        .expect("logging style guide contains canonical telemetry vocabulary block");
    let json_block = block
        .split("```json")
        .nth(1)
        .and_then(|tail| tail.split("```").next())
        .expect("logging style guide contains JSON telemetry vocabulary");
    serde_json::from_str(json_block).expect("logging style guide telemetry vocabulary parses")
}

fn core_telemetry_event_names() -> BTreeSet<&'static str> {
    [
        TelemetryEventType::Decision,
        TelemetryEventType::AnnotatorDispatch,
        TelemetryEventType::PolicyEvaluation,
        TelemetryEventType::EvaluationTiming,
        TelemetryEventType::InterventionPointTransformed,
        TelemetryEventType::AnnotatorFailed,
        TelemetryEventType::PolicyFailed,
    ]
    .into_iter()
    .map(TelemetryEventType::as_str)
    .collect()
}

fn runtime_errors() -> BTreeMap<&'static str, RuntimeError> {
    BTreeMap::from([
        (
            "ManifestInvalid",
            RuntimeError::ManifestInvalid(String::new()),
        ),
        (
            "InterventionPointUnknown",
            RuntimeError::InterventionPointUnknown(String::new()),
        ),
        ("PathMissing", RuntimeError::PathMissing(String::new())),
        (
            "PathTypeMismatch",
            RuntimeError::PathTypeMismatch(String::new()),
        ),
        ("ToolUnknown", RuntimeError::ToolUnknown(String::new())),
        (
            "AnnotationFailed",
            RuntimeError::AnnotationFailed(String::new()),
        ),
        (
            "AnnotationTimeout",
            RuntimeError::AnnotationTimeout(String::new()),
        ),
        (
            "PolicyInvocationFailed",
            RuntimeError::PolicyInvocationFailed(String::new()),
        ),
        (
            "PolicyOutputInvalid",
            RuntimeError::PolicyOutputInvalid(String::new()),
        ),
        (
            "ResourceLimitExceeded",
            RuntimeError::ResourceLimitExceeded(String::new()),
        ),
        (
            "ApprovalActionMismatch",
            RuntimeError::ApprovalActionMismatch(String::new()),
        ),
        (
            "ResolutionPathTraversal",
            RuntimeError::ResolutionPathTraversal(String::new()),
        ),
        (
            "ResolutionCycle",
            RuntimeError::ResolutionCycle(String::new()),
        ),
        (
            "ResolutionInvalidGovernance",
            RuntimeError::ResolutionInvalidGovernance(String::new()),
        ),
        (
            "ResolutionMergeConflict",
            RuntimeError::ResolutionMergeConflict(String::new()),
        ),
        (
            "TransformTargetForbidden",
            RuntimeError::TransformTargetForbidden(String::new()),
        ),
        (
            "TransformInvalid",
            RuntimeError::TransformInvalid(String::new()),
        ),
        (
            "ApprovalResolverMissing",
            RuntimeError::ApprovalResolverMissing(String::new()),
        ),
    ])
}

#[test]
fn canonical_resource_limits_match_core_defaults() {
    let fixture = fixture("resource_limits_canonical.json");
    let defaults = &fixture["defaults"];
    let limits = Limits::default();

    assert_eq!(defaults["max_snapshot_bytes"], limits.max_snapshot_bytes);
    assert_eq!(
        defaults["max_policy_input_depth"],
        limits.max_policy_input_depth
    );
    assert_eq!(
        defaults["max_annotators_per_point"],
        limits.max_annotators_per_point
    );
    assert_eq!(
        defaults["max_annotator_output_bytes"],
        limits.max_annotator_output_bytes
    );
    assert_eq!(
        defaults["max_policy_output_bytes"],
        limits.max_policy_output_bytes
    );
    assert_eq!(defaults["max_extends_depth"], limits.max_extends_depth);
    assert_eq!(
        defaults["max_merged_manifest_bytes"],
        limits.max_merged_manifest_bytes
    );
    assert_eq!(
        defaults["max_manifest_url_bytes"],
        limits.max_manifest_url_bytes
    );
    assert_eq!(
        defaults["manifest_url_timeout_ms"],
        limits.manifest_url_timeout_ms
    );
    assert_eq!(
        defaults["max_manifest_url_redirects"],
        limits.max_manifest_url_redirects
    );
}

#[test]
fn canonical_error_mapping_matches_core_and_spec() {
    let fixture = fixture("error_mapping_canonical.json");
    let spec = std::fs::read_to_string("../spec/SPECIFICATION.md").expect("spec exists");
    let actual = runtime_errors();
    let rows = fixture["runtime_errors"].as_array().unwrap();

    assert_eq!(rows.len(), 18);
    for row in rows {
        let variant = row["variant"].as_str().unwrap();
        let reason = row["reason"].as_str().unwrap();
        assert_eq!(actual[variant].reason(), reason, "{variant}");
        assert!(spec.contains(reason), "SPECIFICATION.md contains {reason}",);
    }
}

#[test]
fn canonical_verdict_dispatch_matches_normalization() {
    let fixture = fixture("verdict_dispatch_canonical.json");

    for row in fixture["rows"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        let output = row["input"].clone();
        let expected_error = row["expected_error_reason"].as_str();
        match expected_error {
            Some(reason) => {
                let error = normalize_policy_output(output).unwrap_err();
                assert_eq!(error.reason(), reason, "{id}");
            }
            None => {
                let verdict = normalize_policy_output(output).unwrap();
                assert_eq!(
                    verdict.decision.as_str(),
                    row["normalized_decision"].as_str().unwrap(),
                    "{id}"
                );
                assert_eq!(
                    verdict.decision.permits(),
                    row["permits"].as_bool().unwrap(),
                    "{id}"
                );
            }
        }
    }
}

#[test]
fn canonical_telemetry_redaction_matches_core_event_types() {
    let fixture = fixture("telemetry_redaction_canonical.json");
    let actual: BTreeSet<_> = [
        TelemetryEventType::Decision,
        TelemetryEventType::AnnotatorDispatch,
        TelemetryEventType::PolicyEvaluation,
        TelemetryEventType::EvaluationTiming,
        TelemetryEventType::InterventionPointTransformed,
        TelemetryEventType::AnnotatorFailed,
        TelemetryEventType::PolicyFailed,
    ]
    .into_iter()
    .map(TelemetryEventType::as_str)
    .collect();
    let fixture_names: BTreeSet<_> = fixture["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["name"].as_str().unwrap())
        .collect();

    assert_eq!(fixture_names, actual);
    for event in fixture["events"].as_array().unwrap() {
        let emitted = event["emitted_attribute_keys"].as_array().unwrap();
        assert!(emitted.contains(&json!("intervention_point")));
        assert!(emitted.contains(&json!("event_type")));
        let withheld = event["guaranteed_withheld_fields"].as_array().unwrap();
        for sensitive in [
            "policy_target.value",
            "snapshot.tool_call.args",
            "snapshot.tool_result",
            "annotations.*",
            "snapshot.messages",
            "secrets",
            "pii",
        ] {
            assert!(
                withheld.contains(&json!(sensitive)),
                "{} {sensitive}",
                event["name"]
            );
        }
    }
    let sdk_boundaries = fixture["sdk_enforcement_boundary_events"]
        .as_array()
        .unwrap();
    assert_eq!(sdk_boundaries.len(), 4);
    for event in sdk_boundaries {
        assert_eq!(event["name"], "decision");
        assert!(event["reserved_reason"]
            .as_str()
            .unwrap()
            .starts_with("runtime_error:"));
        assert!(event["safe_attribute_keys"]
            .as_array()
            .unwrap()
            .contains(&json!("action_identity")));
    }
}

#[test]
fn canonical_logging_style_guide_matches_core_telemetry_vocabulary() {
    let style = logging_style_vocabulary();
    let redaction = fixture("telemetry_redaction_canonical.json");
    let observability = std::fs::read_to_string("../docs/observability.md")
        .expect("observability documentation exists");

    let style_events = style["events"].as_array().unwrap();
    let style_names: BTreeSet<_> = style_events
        .iter()
        .map(|event| event["name"].as_str().unwrap())
        .collect();
    let redaction_names: BTreeSet<_> = redaction["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["name"].as_str().unwrap())
        .collect();

    assert_eq!(style_names, core_telemetry_event_names());
    assert_eq!(style_names, redaction_names);

    for name in &style_names {
        assert!(
            observability.contains(&format!("`{name}`")),
            "observability doc mentions {name}"
        );
    }

    for style_event in style_events {
        let name = style_event["name"].as_str().unwrap();
        let documented = style_event["documented_attribute_keys"].as_array().unwrap();
        let redaction_event = redaction["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["name"] == name)
            .unwrap();
        assert_eq!(
            documented,
            redaction_event["emitted_attribute_keys"]
                .as_array()
                .unwrap(),
            "{name} documented fields match emitted fixture fields"
        );
        for field in documented.iter().map(|field| field.as_str().unwrap()) {
            assert!(
                field.split('.').all(|part| !part.is_empty()
                    && part
                        .chars()
                        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')),
                "{name} field {field} uses snake case"
            );
        }
    }
}

#[test]
fn drift_catalog_validates_against_schema() {
    let schema = fixture("drift-catalog.schema.json");
    let catalog = fixture("drift-catalog.json");
    let compiled = JSONSchema::compile(&schema).expect("drift schema compiles");
    {
        let validation = compiled.validate(&catalog);
        if let Err(errors) = validation {
            let messages: Vec<_> = errors.map(|error| error.to_string()).collect();
            panic!(
                "drift catalog failed schema validation: {}",
                messages.join("; ")
            );
        }
    }
}

#[test]
fn decision_enum_permits_dispatch_is_closed() {
    // AGT D1 removed `effects` from the verdict surface. The remaining
    // mutating decision is `Transform`; `permits` documents which decisions
    // allow the action to proceed (after any applicable transform).
    assert!(Decision::Allow.permits());
    assert!(Decision::Warn.permits());
    assert!(Decision::Transform.permits());
    // AGT D1 + spec §13.1: deny refuses the action.
    assert!(!Decision::Deny.permits());
    // AGT D1 + spec §13.1: escalate defers to the host approval path.
    assert!(!Decision::Escalate.permits());
}
