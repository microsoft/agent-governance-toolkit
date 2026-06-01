use agent_control_specification::{
    assemble_sse_stream_with_limits, synthesize_sse_stream, AgentControl, AnnotatorDispatcher,
    AnnotatorInvocation, Decision, InterventionPoint, JsonValue, Manifest, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError, StreamingLimits, DEFAULT_MAX_STREAM_BYTES,
    DEFAULT_MAX_STREAM_EVENTS,
};
use serde_json::json;
use std::{fs, path::PathBuf, sync::Arc};

struct NoopAnnotator;

impl AnnotatorDispatcher for NoopAnnotator {
    fn dispatch(
        &self,
        _annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(JsonValue::Null)
    }
}

struct AllowPolicy;

impl PolicyDispatcher for AllowPolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        Ok(json!({"decision": "allow"}))
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fixture_root() -> PathBuf {
    repo_root().join("tests/conformance/streaming")
}

fn read_fixture(path: &str) -> Vec<u8> {
    fs::read(fixture_root().join(path)).unwrap()
}

fn manifest_json() -> JsonValue {
    serde_json::from_slice(&fs::read(fixture_root().join("manifest.json")).unwrap()).unwrap()
}

fn model_control() -> AgentControl {
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  pre_model_call:
    policy_target_kind: model_request
    policy:
      id: test_policy
    policy_target: $snap.model_request
  post_model_call:
    policy_target_kind: model_response
    policy:
      id: test_policy
    policy_target: $snap.model_response"#,
    )
    .unwrap();
    AgentControl::new(
        Runtime::new(manifest, Arc::new(NoopAnnotator), Arc::new(AllowPolicy)).unwrap(),
    )
}

#[test]
fn assemble_cases_match_shared_manifest_and_allow_reemits_verbatim() {
    let manifest = manifest_json();
    let limits = StreamingLimits {
        max_stream_bytes: manifest["limits"]["max_stream_bytes"].as_u64().unwrap() as usize,
        max_stream_events: manifest["limits"]["max_stream_events"].as_u64().unwrap() as usize,
    };
    assert_eq!(limits.max_stream_bytes, DEFAULT_MAX_STREAM_BYTES);
    assert_eq!(limits.max_stream_events, DEFAULT_MAX_STREAM_EVENTS);

    for case in manifest["assemble"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let input = read_fixture(case["input"].as_str().unwrap());
        match case["outcome"].as_str().unwrap() {
            "ok" => {
                let assembled = assemble_sse_stream_with_limits(&input, limits)
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
                assert_eq!(assembled, case["assembled"], "{name}");

                if case["allow_reemits_input_verbatim"]
                    .as_bool()
                    .unwrap_or(false)
                {
                    let result = model_control()
                        .run_model_stream_with_options(
                            json!({"messages": []}),
                            Default::default(),
                            limits,
                            |_| input.clone(),
                        )
                        .unwrap_or_else(|error| panic!("{name}: {error}"));
                    assert_eq!(result.assembled_response, case["assembled"], "{name}");
                    assert_eq!(result.original_bytes, input, "{name}");
                    assert_eq!(result.bytes, input, "{name}");
                    assert_eq!(
                        result
                            .post_model_call_intervention_point_result
                            .verdict
                            .decision,
                        Decision::Allow,
                        "{name}"
                    );
                }
            }
            "fail_closed" => {
                let error = assemble_sse_stream_with_limits(&input, limits).unwrap_err();
                assert_eq!(
                    error.message(),
                    case["error_message"].as_str().unwrap(),
                    "{name}"
                );
            }
            other => panic!("unsupported outcome {other}"),
        }
    }
}

#[test]
fn synthesize_cases_match_shared_manifest() {
    let manifest = manifest_json();
    for case in manifest["synthesize"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let expected = read_fixture(case["expected_output"].as_str().unwrap());
        let output = synthesize_sse_stream(&case["response"], &case["template"])
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            String::from_utf8(output).unwrap(),
            String::from_utf8(expected).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn limits_fail_closed_at_byte_and_event_caps() {
    let over_bytes = vec![b' '; DEFAULT_MAX_STREAM_BYTES + 1];
    assert_eq!(
        assemble_sse_stream_with_limits(&over_bytes, StreamingLimits::default())
            .unwrap_err()
            .message(),
        "Streaming response exceeded the buffering byte limit."
    );

    let mut input = Vec::new();
    for _ in 0..2 {
        input.extend_from_slice(b"data: {\"choices\":[]}\n\n");
    }
    assert_eq!(
        assemble_sse_stream_with_limits(
            &input,
            StreamingLimits {
                max_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
                max_stream_events: 1,
            },
        )
        .unwrap_err()
        .message(),
        "Streaming response exceeded the buffered event limit."
    );
}

#[test]
fn streaming_guard_transforms_to_single_synthesized_chunk() {
    struct TransformPolicy;

    impl PolicyDispatcher for TransformPolicy {
        fn evaluate(
            &self,
            invocation: &PreparedPolicyInvocation,
        ) -> Result<JsonValue, RuntimeError> {
            let input = invocation.policy_input().unwrap();
            if input["intervention_point"] == "post_model_call" {
                Ok(json!({
                    "decision": "transform", "transform": {"path": "$policy_target.choices[0].message.content", "value": "[redacted]"}
                }))
            } else {
                Ok(json!({"decision": "allow"}))
            }
        }
    }

    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  pre_model_call:
    policy_target_kind: model_request
    policy:
      id: test_policy
    policy_target: $snap.model_request
  post_model_call:
    policy_target_kind: model_response
    policy:
      id: test_policy
    policy_target: $snap.model_response"#,
    )
    .unwrap();
    let control = AgentControl::new(
        Runtime::new(manifest, Arc::new(NoopAnnotator), Arc::new(TransformPolicy)).unwrap(),
    );
    let input = read_fixture("inputs/allow_text_only.sse");
    let expected = read_fixture("inputs/synth_text.expected.sse");

    let result = control
        .run_model_stream(json!({"messages": []}), |_| input.clone())
        .unwrap();

    assert_eq!(result.original_bytes, input);
    assert_eq!(
        String::from_utf8(result.bytes).unwrap(),
        String::from_utf8(expected).unwrap()
    );
}

#[test]
fn streaming_guard_fails_closed_on_unrepresentable_stream() {
    let input = read_fixture("inputs/fail_malformed_json.sse");
    let error = model_control()
        .run_model_stream(json!({"messages": []}), |_| input)
        .unwrap_err();

    assert_eq!(error.intervention_point(), InterventionPoint::PostModelCall);
    assert_eq!(
        error.intervention_point_result().verdict.reason.as_deref(),
        Some("runtime_error:streaming_unsupported")
    );
}
