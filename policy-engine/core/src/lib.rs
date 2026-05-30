pub type JsonValue = serde_json::Value;

pub mod annotation;
mod constants;
#[cfg(feature = "default-dispatchers")]
pub mod dispatchers;
pub mod effects;
pub mod error;
pub mod ffi;
pub mod intervention_point;
pub mod limits;
pub mod manifest;
pub mod opa;
pub mod paths;
pub mod perf_telemetry;
pub mod policy;
pub mod policy_input;
pub mod runtime;
pub mod telemetry;
pub mod tool_projection;
pub mod verdict;

pub use annotation::{
    AnnotationConfig, AnnotatorConfig, AnnotatorDispatcher, AnnotatorInvocation, AnnotatorType,
};
#[cfg(feature = "default-dispatchers")]
pub use dispatchers::{
    ClassifierAnnotator, DefaultAnnotatorDispatcher, EndpointAnnotator, LlmAnnotator,
};
pub use effects::{Effect, EffectType, RedactionSpan};
pub use error::RuntimeError;
pub use intervention_point::{EnforcementMode, InterventionPoint};
pub use limits::Limits;
pub use manifest::{
    ApprovalOnTimeout, ApprovalResolverConfig, ApprovalSection, InterventionPointConfig, Manifest,
    ToolConfig,
};
pub use opa::{OpaPolicyDispatcher, OpaRegoRunner};
pub use paths::{JsonPath, PathEnv, PathParseError, PathRoot, PathSegment};
pub use perf_telemetry::PerfTelemetry;
pub use policy::{
    CustomPolicyConfig, CustomPolicyInvocation, PolicyBinding, PolicyConfig,
    PreparedPolicyInvocation, RegoPolicyConfig, RegoPolicyInvocation, TestPolicyConfig,
    TestPolicyInvocation,
};
pub use policy_input::{action_identity, build_policy_input, canonical_json};
pub use runtime::{InterventionPointRequest, InterventionPointResult, PolicyDispatcher, Runtime};
pub use telemetry::{NoopTelemetrySink, TelemetryEvent, TelemetryEventType, TelemetrySink};
pub use verdict::{normalize_policy_output, Decision, Verdict};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct StaticAnnotator {
        output: JsonValue,
        seen: Mutex<Vec<JsonValue>>,
        error: Option<RuntimeError>,
    }

    impl AnnotatorDispatcher for StaticAnnotator {
        fn dispatch(
            &self,
            _annotator_name: &str,
            _annotator: &AnnotatorInvocation,
            preliminary_policy_input: &JsonValue,
        ) -> Result<JsonValue, RuntimeError> {
            self.seen
                .lock()
                .unwrap()
                .push(preliminary_policy_input.clone());
            if let Some(error) = &self.error {
                Err(error.clone())
            } else {
                Ok(self.output.clone())
            }
        }
    }

    struct StaticPolicy {
        output: JsonValue,
        seen: Mutex<Vec<JsonValue>>,
        error: Option<RuntimeError>,
    }

    impl StaticPolicy {
        fn allow() -> Self {
            Self {
                output: json!({"decision": "allow"}),
                seen: Mutex::new(Vec::new()),
                error: None,
            }
        }

        fn with_output(output: JsonValue) -> Self {
            Self {
                output,
                seen: Mutex::new(Vec::new()),
                error: None,
            }
        }
    }

    impl PolicyDispatcher for StaticPolicy {
        fn evaluate(
            &self,
            invocation: &PreparedPolicyInvocation,
        ) -> Result<JsonValue, RuntimeError> {
            let final_policy_input = invocation.policy_input().unwrap();
            self.seen.lock().unwrap().push(final_policy_input.clone());
            if let Some(error) = &self.error {
                Err(error.clone())
            } else {
                Ok(self.output.clone())
            }
        }
    }

    fn no_annotations() -> Arc<StaticAnnotator> {
        Arc::new(StaticAnnotator {
            output: JsonValue::Null,
            seen: Mutex::new(Vec::new()),
            error: None,
        })
    }

    fn manifest(input: &str) -> Manifest {
        Manifest::from_yaml_str(input).unwrap()
    }

    fn runtime(
        manifest: Manifest,
        annotations: Arc<StaticAnnotator>,
        policy: Arc<StaticPolicy>,
    ) -> Runtime {
        Runtime::new(manifest, annotations, policy).unwrap()
    }

    #[test]
    fn parses_and_resolves_deterministic_paths() {
        let snapshot = json!({
            "a": {"b": [{"c": 7}], "x.y": 11},
            "array": ["zero"]
        });

        let path = JsonPath::parse("$snap.a.b[0].c").unwrap();
        assert_eq!(
            path.resolve(&PathEnv::with_snap(&snapshot)).unwrap(),
            json!(7)
        );

        let literal = JsonPath::parse("$snap.a[\"x.y\"]").unwrap();
        assert_eq!(
            literal.resolve(&PathEnv::with_snap(&snapshot)).unwrap(),
            json!(11)
        );

        assert_eq!(
            JsonPath::parse("$snap.array[-1]").unwrap_err(),
            PathParseError::NegativeIndex
        );

        let missing = JsonPath::parse("$snap.array[2]").unwrap();
        assert_eq!(
            missing
                .resolve(&PathEnv::with_snap(&snapshot))
                .unwrap_err()
                .reason(),
            "runtime_error:path_missing"
        );
    }

    #[test]
    fn validates_closed_intervention_point_names_and_tool_intervention_point_constraints() {
        let unknown_intervention_point = r#"agent_control_specification_version: 0.3.0-alpha
policies:
  test_policy:
    type: test
intervention_points:
  state:
    policy_target_kind: state
    policy:
      id: test_policy
    policy_target: $snap.state"#;
        assert_eq!(
            Manifest::from_yaml_str(unknown_intervention_point)
                .unwrap_err()
                .reason(),
            "runtime_error:manifest_invalid"
        );

        let invalid_tool_name_from = r#"agent_control_specification_version: 0.3.0-alpha
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    tool_name_from: $snap.tool.name
    policy:
      id: test_policy
    policy_target: $snap.input"#;
        assert_eq!(
            Manifest::from_yaml_str(invalid_tool_name_from)
                .unwrap_err()
                .reason(),
            "runtime_error:manifest_invalid"
        );
    }

    #[test]
    fn unknown_tool_fails_closed() {
        let manifest = manifest(
            r#"agent_control_specification_version: 0.3.0-alpha
policies:
  test_policy:
    type: test
intervention_points:
  pre_tool_call:
    policy_target_kind: tool_args
    tool_name_from: $snap.tool_call.name
    policy:
      id: test_policy
    policy_target: $snap.tool_call.args"#,
        );
        let policy = Arc::new(StaticPolicy::allow());
        let runtime = runtime(manifest, no_annotations(), policy.clone());

        let result = runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::PreToolCall,
            snapshot: json!({"tool_call": {"name": "missing_tool", "args": {}}}),
            mode: EnforcementMode::Enforce,
        });

        assert_eq!(result.verdict.decision, Decision::Deny);
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:tool_unknown")
        );
        assert!(policy.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn normalizes_policy_verdicts_and_rejects_reserved_reasons() {
        let verdict = normalize_policy_output(json!({
            "decision": "warn",
            "reason": "needs_review",
            "message": "Proceeding with warning",
            "effects": []
        }))
        .unwrap();
        assert_eq!(verdict.decision, Decision::Warn);
        assert_eq!(verdict.reason.as_deref(), Some("needs_review"));

        let error = normalize_policy_output(json!({
            "decision": "allow",
            "reason": "runtime_error:path_missing"
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn evaluate_only_validates_effects_without_applying_them() {
        let manifest = manifest(
            r#"agent_control_specification_version: 0.3.0-alpha
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input"#,
        );
        let policy = Arc::new(StaticPolicy::with_output(json!({
            "decision": "allow",
            "effects": [
                {"type": "replace", "path": "$policy_target.message", "value": "changed"}
            ]
        })));
        let runtime = runtime(manifest, no_annotations(), policy);

        let result = runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Input,
            snapshot: json!({"input": {"message": "original"}}),
            mode: EnforcementMode::EvaluateOnly,
        });

        assert_eq!(result.verdict.decision, Decision::Allow);
        assert_eq!(result.transformed_policy_target, None);
        assert_eq!(
            result.policy_input.unwrap()["policy_target"]["value"],
            json!({"message": "original"})
        );
    }

    #[test]
    fn enforce_applies_policy_target_only_effects() {
        let manifest = manifest(
            r#"agent_control_specification_version: 0.3.0-alpha
policies:
  test_policy:
    type: test
intervention_points:
  output:
    policy_target_kind: assistant_output
    policy:
      id: test_policy
    policy_target: $snap.output"#,
        );
        let policy = Arc::new(StaticPolicy::with_output(json!({
            "decision": "warn",
            "effects": [
                {"type": "append", "path": "$policy_target.items", "value": 2},
                {"type": "prepend", "path": "$policy_target.items", "value": 0},
                {"type": "redact", "path": "$policy_target.content", "spans": [
                    {"start": 6, "end": 12, "replacement": "[x]"}
                ]},
                {"type": "replace", "path": "$policy_target.flag", "value": true}
            ]
        })));
        let runtime = runtime(manifest, no_annotations(), policy);

        let result = runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Output,
            snapshot: json!({
                "output": {
                    "items": [1],
                    "content": "hello secret world",
                    "flag": false
                }
            }),
            mode: EnforcementMode::Enforce,
        });

        assert_eq!(result.verdict.decision, Decision::Warn);
        assert_eq!(
            result.transformed_policy_target.unwrap(),
            json!({
                "items": [0, 1, 2],
                "content": "hello [x] world",
                "flag": true
            })
        );
    }

    #[test]
    fn annotation_dispatch_runs_before_policy_and_finalizes_policy_input() {
        let manifest = manifest(
            r#"agent_control_specification_version: 0.3.0-alpha
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      prompt_classifier:
        from: $policy_target.text
annotators:
  prompt_classifier:
    type: classifier"#,
        );
        let annotations = Arc::new(StaticAnnotator {
            output: json!({"risk": "low"}),
            seen: Mutex::new(Vec::new()),
            error: None,
        });
        let policy = Arc::new(StaticPolicy::allow());
        let runtime = runtime(manifest, annotations.clone(), policy.clone());

        let result = runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Input,
            snapshot: json!({"input": {"text": "hello"}}),
            mode: EnforcementMode::Enforce,
        });

        assert_eq!(result.verdict.decision, Decision::Allow);
        let preliminary = annotations.seen.lock().unwrap()[0].clone();
        assert_eq!(preliminary["annotations"], json!({}));
        assert_eq!(
            preliminary["policy_target"]["value"],
            json!({"text": "hello"})
        );

        let final_input = policy.seen.lock().unwrap()[0].clone();
        assert_eq!(
            final_input["annotations"]["prompt_classifier"],
            json!({"risk": "low"})
        );
        assert_eq!(result.policy_input.unwrap(), final_input);
    }

    #[test]
    fn canonical_serialization_sorts_keys_without_pretty_whitespace() {
        let value = json!({"b": 1, "a": {"d": 4, "c": 3}});
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":{"c":3,"d":4},"b":1}"#
        );
    }
}
