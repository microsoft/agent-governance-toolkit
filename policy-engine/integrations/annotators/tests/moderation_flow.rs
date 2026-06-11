#![cfg(feature = "aacs")]

use agent_control_specification::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Manifest, PolicyDispatcher, PreparedPolicyInvocation,
    Runtime, RuntimeError,
};
use agent_control_specification_annotators::{
    ClassifierAnnotator, EndpointAnnotator, LlmAnnotator, StubHttpTransport, TransportResponse,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
};

struct ModerationDispatcher {
    safety: StubHttpTransport,
    judge_url: String,
    pii_url: String,
}

impl AnnotatorDispatcher for ModerationDispatcher {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        match annotator_name {
            "safety" => ClassifierAnnotator::new().dispatch_with_transport(
                annotator_name,
                annotator,
                preliminary_policy_input,
                &self.safety,
            ),
            "judge" => {
                let mut annotator = annotator.clone();
                annotator
                    .fields
                    .insert("endpoint".to_string(), json!(self.judge_url));
                LlmAnnotator::new().dispatch(annotator_name, &annotator, preliminary_policy_input)
            }
            "pii" => {
                let mut annotator = annotator.clone();
                annotator
                    .fields
                    .insert("url".to_string(), json!(self.pii_url));
                EndpointAnnotator::new().dispatch(
                    annotator_name,
                    &annotator,
                    preliminary_policy_input,
                )
            }
            other => Err(RuntimeError::AnnotationFailed(format!(
                "unexpected annotator {other}"
            ))),
        }
    }
}

struct ModerationPolicy;

impl PolicyDispatcher for ModerationPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let input = invocation.policy_input().expect("policy input");
        let annotations = &input["annotations"];
        if annotations["safety"]["flagged"].as_bool() == Some(true)
            && annotations["safety"]["label"].as_str() == Some("Violence")
        {
            return Ok(json!({"decision": "deny", "reason": "moderation.violence"}));
        }
        if annotations["judge"]["label"].as_str() == Some("self_harm") {
            return Ok(json!({"decision": "escalate", "reason": "moderation.escalate"}));
        }
        let spans = annotations["pii"]["spans"].clone();
        if spans.as_array().is_some_and(|items| !items.is_empty()) {
            // AGT D1.3: multi-span redaction moves to annotators. The
            // annotator (or the policy on top of its data) computes the
            // final redacted text, and the policy returns a single
            // transform replacement instead of an effects array.
            let text = input["policy_target"]["value"]["text"]
                .as_str()
                .unwrap_or("");
            let chars: Vec<char> = text.chars().collect();
            let mut out = String::new();
            let mut idx = 0usize;
            let spans_arr = spans.as_array().unwrap();
            // Spans are byte-offset but in this test fixture they are
            // also character-offset because the test text is ASCII.
            for span in spans_arr {
                let start = span["start"].as_u64().unwrap_or(0) as usize;
                let end = span["end"].as_u64().unwrap_or(0) as usize;
                let replacement = span["replacement"].as_str().unwrap_or("[redacted]");
                while idx < start && idx < chars.len() {
                    out.push(chars[idx]);
                    idx += 1;
                }
                out.push_str(replacement);
                idx = end;
            }
            while idx < chars.len() {
                out.push(chars[idx]);
                idx += 1;
            }
            return Ok(json!({
                "decision": "transform",
                "reason": "moderation.redacted",
                "transform": {"path": "$policy_target.text", "value": out}
            }));
        }
        Ok(json!({"decision": "allow"}))
    }
}

fn manifest() -> Manifest {
    Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  moderation:
    type: test
intervention_points:
  output:
    policy_target_kind: assistant_output
    policy:
      id: moderation
    policy_target: $snap.output
    annotations:
      safety:
        from: $policy_target.text
      judge:
        from: $policy_target.text
      pii:
        from: $policy_target.text
annotators:
  safety:
    type: classifier
    provider: aacs
    endpoint: https://example.cognitiveservices.azure.com
    api_key_env: ACS_AACS_FLOW_TEST_KEY
    category_thresholds:
      Violence: 0.5
  judge:
    type: llm
    model: judge-model
    prompt: Classify support risk as JSON.
    api_key_env: ACS_LLM_FLOW_TEST_KEY
  pii:
    type: endpoint"#,
    )
    .unwrap()
}

fn runtime(safety_body: &'static str, judge_body: &'static str, pii_body: &'static str) -> Runtime {
    std::env::set_var("ACS_AACS_FLOW_TEST_KEY", "test-key");
    std::env::set_var("ACS_LLM_FLOW_TEST_KEY", "test-key");
    let dispatcher = ModerationDispatcher {
        safety: StubHttpTransport::with_response(200, safety_body),
        judge_url: server("200 OK", judge_body.to_string()),
        pii_url: server("200 OK", pii_body.to_string()),
    };
    Runtime::new(manifest(), Arc::new(dispatcher), Arc::new(ModerationPolicy)).unwrap()
}

fn evaluate(runtime: &Runtime, text: &str) -> agent_control_specification::InterventionPointResult {
    runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Output,
        snapshot: json!({"output": {"text": text}}),
        mode: EnforcementMode::Enforce,
    })
}

#[test]
fn realistic_support_moderation_annotations_drive_policy_and_redaction() {
    let runtime = runtime(
        r#"{"categoriesAnalysis":[{"category":"Violence","severity":0}]}"#,
        r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#,
        r#"{"spans":[{"start":6,"end":12,"replacement":"[redacted]"}]}"#,
    );

    let result = evaluate(&runtime, "hello secret world");

    assert_eq!(result.verdict.decision, Decision::Transform);
    assert_eq!(
        result.transformed_policy_target,
        Some(json!({"text": "hello [redacted] world"}))
    );
    let input = result.policy_input.expect("policy input");
    assert_eq!(
        input["annotations"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec!["judge", "pii", "safety"]
    );
    assert_eq!(input["annotations"]["safety"]["verdict"], json!("allow"));
    assert_eq!(input["annotations"]["judge"]["label"], json!("safe"));
    assert_eq!(
        input["annotations"]["pii"]["spans"][0]["replacement"],
        json!("[redacted]")
    );
}

#[test]
fn realistic_support_moderation_can_deny_and_escalate_from_annotations() {
    let violent = runtime(
        r#"{"categoriesAnalysis":[{"category":"Violence","severity":6}]}"#,
        r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#,
        r#"{"spans":[]}"#,
    );
    let denied = evaluate(&violent, "violent threat");
    assert_eq!(denied.verdict.decision, Decision::Deny);
    assert_eq!(
        denied.verdict.reason.as_deref(),
        Some("moderation.violence")
    );

    let self_harm = runtime(
        r#"{"categoriesAnalysis":[{"category":"Violence","severity":0}]}"#,
        r#"{"choices":[{"message":{"content":"{\"label\":\"self_harm\"}"}}]}"#,
        r#"{"spans":[]}"#,
    );
    let escalated = evaluate(&self_harm, "support escalation");
    assert_eq!(escalated.verdict.decision, Decision::Escalate);
    assert_eq!(
        escalated.verdict.reason.as_deref(),
        Some("moderation.escalate")
    );
}

#[test]
fn bundled_aacs_failures_fail_closed_with_diagnostics() {
    let cases = [
        (
            Err("HTTP request failed: timed out".to_string()),
            "timed out",
        ),
        (
            Ok(TransportResponse {
                status: 429,
                body: "rate limited by content safety".to_string(),
            }),
            "rate limited",
        ),
        (
            Ok(TransportResponse {
                status: 200,
                body: "not-json".to_string(),
            }),
            "JSON parse failed",
        ),
        (
            Ok(TransportResponse {
                status: 200,
                body: String::new(),
            }),
            "JSON parse failed",
        ),
    ];
    for (response, expected) in cases {
        std::env::set_var("ACS_AACS_FLOW_TEST_KEY", "test-key");
        let transport = StubHttpTransport::with_responses([response]);
        let annotator = invocation(&[
            ("type", json!("classifier")),
            ("provider", json!("aacs")),
            (
                "endpoint",
                json!("https://example.cognitiveservices.azure.com"),
            ),
            ("api_key_env", json!("ACS_AACS_FLOW_TEST_KEY")),
            ("category_thresholds", json!({"Violence": 0.5})),
            ("from", json!("$policy_target.text")),
        ]);

        let error = ClassifierAnnotator::new()
            .dispatch_with_transport("safety", &annotator, &input("hello"), &transport)
            .expect_err("classifier failure should fail closed");

        assert_eq!(error.reason(), "runtime_error:annotation_failed");
        assert!(
            error.to_string().contains(expected),
            "expected {expected} in {error}"
        );
    }
}

#[test]
fn bad_endpoint_config_reserved_reason_and_oversize_outputs_fail_closed() {
    let missing_url = invocation(&[
        ("type", json!("endpoint")),
        ("from", json!("$policy_target.text")),
    ]);
    let missing_url_error = EndpointAnnotator::new()
        .dispatch("pii", &missing_url, &input("hello"))
        .expect_err("missing URL should fail closed");
    assert!(missing_url_error
        .to_string()
        .contains("missing required field 'endpoint' or 'url'"));

    let reserved = runtime(
        r#"{"categoriesAnalysis":[{"category":"Violence","severity":0}]}"#,
        r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#,
        r#"{"reason":"runtime_error:path_missing"}"#,
    );
    let reserved_result = evaluate(&reserved, "hello");
    assert_eq!(reserved_result.verdict.decision, Decision::Deny);
    assert_eq!(
        reserved_result.verdict.reason.as_deref(),
        Some("runtime_error:annotation_failed")
    );

    let large = format!("{{\"blob\":\"{}\"}}", "x".repeat(300_000));
    let oversized = runtime(
        r#"{"categoriesAnalysis":[{"category":"Violence","severity":0}]}"#,
        r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#,
        Box::leak(large.into_boxed_str()),
    );
    let oversized_result = evaluate(&oversized, "hello");
    assert_eq!(oversized_result.verdict.decision, Decision::Deny);
    assert!(oversized_result
        .verdict
        .message
        .as_deref()
        .is_some_and(|message| message.contains("serialized size")));
}

#[test]
fn malformed_llm_judge_and_missing_aacs_config_fail_closed() {
    std::env::set_var("ACS_LLM_FLOW_TEST_KEY", "test-key");
    let malformed_url = server(
        "200 OK",
        r#"{"choices":[{"message":{"content":"not-json"}}]}"#.to_string(),
    );
    let judge = invocation(&[
        ("type", json!("llm")),
        ("from", json!("$policy_target.text")),
        ("endpoint", json!(malformed_url)),
        ("api_key_env", json!("ACS_LLM_FLOW_TEST_KEY")),
    ]);
    let judge_error = LlmAnnotator::new()
        .dispatch("judge", &judge, &input("hello"))
        .expect_err("malformed judge output should fail closed");
    assert!(judge_error
        .to_string()
        .contains("model content was not valid JSON"));

    let missing_endpoint = invocation(&[
        ("type", json!("classifier")),
        ("provider", json!("aacs")),
        ("api_key_env", json!("ACS_AACS_FLOW_TEST_KEY")),
        ("from", json!("$policy_target.text")),
    ]);
    std::env::set_var("ACS_AACS_FLOW_TEST_KEY", "test-key");
    let config_error = ClassifierAnnotator::new()
        .dispatch_with_transport(
            "safety",
            &missing_endpoint,
            &input("hello"),
            &StubHttpTransport::with_response(200, "{}"),
        )
        .expect_err("missing endpoint should fail closed");
    assert!(config_error
        .to_string()
        .contains("aacs endpoint is required"));
}

#[test]
fn concurrent_stubbed_classifier_dispatch_has_isolated_requests() {
    std::env::set_var("ACS_AACS_FLOW_TEST_KEY", "test-key");
    let transport = Arc::new(StubHttpTransport::with_responses((0..8).map(|_| {
        Ok(TransportResponse {
            status: 200,
            body: r#"{"categoriesAnalysis":[{"category":"Violence","severity":0}]}"#.to_string(),
        })
    })));
    let mut handles = Vec::new();
    for index in 0..8 {
        let transport = Arc::clone(&transport);
        handles.push(thread::spawn(move || {
            let annotator = invocation(&[
                ("type", json!("classifier")),
                ("provider", json!("aacs")),
                (
                    "endpoint",
                    json!("https://example.cognitiveservices.azure.com"),
                ),
                ("api_key_env", json!("ACS_AACS_FLOW_TEST_KEY")),
                ("category_thresholds", json!({"Violence": 0.5})),
                ("from", json!("$policy_target.text")),
            ]);
            let text = format!("message {index}");
            ClassifierAnnotator::new()
                .dispatch_with_transport("safety", &annotator, &input(&text), transport.as_ref())
                .expect("concurrent classifier succeeds");
        }));
    }
    for handle in handles {
        handle.join().expect("worker joins");
    }

    let mut texts = transport
        .requests()
        .into_iter()
        .map(|request| request.body["text"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    texts.sort();
    assert_eq!(
        texts,
        (0..8)
            .map(|index| format!("message {index}"))
            .collect::<Vec<_>>()
    );
}

fn invocation(fields: &[(&str, JsonValue)]) -> AnnotatorInvocation {
    AnnotatorInvocation {
        fields: fields
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn input(text: &str) -> JsonValue {
    json!({"policy_target": {"value": {"text": text}}, "snapshot": {"output": {"text": text}}, "annotations": {}})
}

fn server(status: &str, body: String) -> String {
    let status = status.to_string();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let url = format!("http://{}", listener.local_addr().expect("server address"));
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        read_request(&mut stream);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });
    url
}

fn read_request(stream: &mut std::net::TcpStream) {
    let mut buffer = Vec::new();
    let mut chunk = [0; 512];
    loop {
        let read = stream.read(&mut chunk).expect("read request");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let content_length = content_length(&buffer[..header_end]).unwrap_or(0);
            if buffer.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }
}

fn content_length(headers: &[u8]) -> Option<usize> {
    std::str::from_utf8(headers).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())?
    })
}
