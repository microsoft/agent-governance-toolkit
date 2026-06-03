use agent_control_specification::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue};
use agent_control_specification_annotators::{
    ClassifierAnnotator, EndpointAnnotator, LlmAnnotator,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    thread,
};

fn server(status: &str, body: &'static str) -> String {
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
        if let Some(header_end) = find_header_end(&buffer) {
            let content_length = content_length(&buffer[..header_end]).unwrap_or(0);
            if buffer.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &[u8]) -> Option<usize> {
    std::str::from_utf8(headers).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())?
    })
}

fn invocation(fields: &[(&str, JsonValue)]) -> AnnotatorInvocation {
    AnnotatorInvocation {
        fields: fields
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn input() -> JsonValue {
    json!({"policy_target": {"value": {"text": "hello"}}, "snapshot": {}})
}

#[test]
fn endpoint_returns_json_response() {
    let url = server("200 OK", r#"{"risk":"low"}"#);
    let annotator = invocation(&[
        ("type", json!("endpoint")),
        ("from", json!("$policy_target.text")),
        ("url", json!(url)),
    ]);

    let output = EndpointAnnotator::new()
        .dispatch("metadata", &annotator, &input())
        .expect("endpoint succeeds");

    assert_eq!(output, json!({"risk": "low"}));
}

#[test]
fn endpoint_rejects_non_success_status() {
    let url = server("500 Internal Server Error", r#"{"error":"bad"}"#);
    let annotator = invocation(&[
        ("type", json!("endpoint")),
        ("from", json!("$policy_target.text")),
        ("url", json!(url)),
    ]);

    let error = EndpointAnnotator::new()
        .dispatch("metadata", &annotator, &input())
        .expect_err("status errors fail closed");

    assert_eq!(error.reason(), "runtime_error:annotation_failed");
}

#[test]
fn endpoint_rejects_unresolvable_from_path() {
    let annotator = invocation(&[
        ("type", json!("endpoint")),
        ("from", json!("$policy_target.missing")),
        ("url", json!("http://127.0.0.1:1")),
    ]);

    assert!(EndpointAnnotator::new()
        .dispatch("metadata", &annotator, &input())
        .is_err());
}

#[test]
fn classifier_returns_json_response() {
    let url = server("200 OK", r#"{"labels":[{"label":"safe","score":0.9}]}"#);
    let annotator = invocation(&[
        ("type", json!("classifier")),
        ("from", json!("$policy_target.text")),
        ("url", json!(url)),
        ("api_key_env", json!("ACS_CLASSIFIER_TEST_KEY")),
    ]);
    std::env::set_var("ACS_CLASSIFIER_TEST_KEY", "dummy");

    let output = ClassifierAnnotator::new()
        .dispatch("classifier", &annotator, &input())
        .expect("classifier succeeds");

    assert_eq!(output["labels"][0]["label"], json!("safe"));
}

#[test]
fn classifier_rejects_malformed_json() {
    let url = server("200 OK", "not-json");
    let annotator = invocation(&[
        ("type", json!("classifier")),
        ("from", json!("$policy_target.text")),
        ("url", json!(url)),
    ]);

    assert!(ClassifierAnnotator::new()
        .dispatch("classifier", &annotator, &input())
        .is_err());
}

#[test]
fn classifier_rejects_unresolvable_from_path() {
    let annotator = invocation(&[
        ("type", json!("classifier")),
        ("from", json!("$policy_target.missing")),
        ("url", json!("http://127.0.0.1:1")),
    ]);

    assert!(ClassifierAnnotator::new()
        .dispatch("classifier", &annotator, &input())
        .is_err());
}

#[test]
fn llm_returns_label_and_raw_content() {
    let url = server(
        "200 OK",
        r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#,
    );
    let annotator = invocation(&[
        ("type", json!("llm")),
        ("from", json!("$policy_target.text")),
        ("endpoint", json!(url)),
        ("model", json!("test-model")),
        ("prompt", json!("judge")),
        ("api_key_env", json!("ACS_LLM_TEST_KEY")),
    ]);
    std::env::set_var("ACS_LLM_TEST_KEY", "dummy");

    let output = LlmAnnotator::new()
        .dispatch("judge", &annotator, &input())
        .expect("llm succeeds");

    assert_eq!(
        output,
        json!({"label": "safe", "raw": "{\"label\":\"safe\"}"})
    );
}

#[test]
fn llm_rejects_malformed_model_content() {
    let url = server(
        "200 OK",
        r#"{"choices":[{"message":{"content":"not-json"}}]}"#,
    );
    let annotator = invocation(&[
        ("type", json!("llm")),
        ("from", json!("$policy_target.text")),
        ("endpoint", json!(url)),
        ("api_key_env", json!("ACS_LLM_MALFORMED_TEST_KEY")),
    ]);
    std::env::set_var("ACS_LLM_MALFORMED_TEST_KEY", "dummy");

    assert!(LlmAnnotator::new()
        .dispatch("judge", &annotator, &input())
        .is_err());
}

#[test]
fn llm_rejects_unresolvable_from_path() {
    let annotator = invocation(&[
        ("type", json!("llm")),
        ("from", json!("$policy_target.missing")),
        ("endpoint", json!("http://127.0.0.1:1")),
        ("api_key_env", json!("ACS_LLM_MISSING_PATH_TEST_KEY")),
    ]);
    std::env::set_var("ACS_LLM_MISSING_PATH_TEST_KEY", "dummy");

    assert!(LlmAnnotator::new()
        .dispatch("judge", &annotator, &input())
        .is_err());
}

fn capturing_server(
    status: &str,
    body: &'static str,
) -> (String, std::sync::mpsc::Receiver<String>) {
    let status = status.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let url = format!("http://{}", listener.local_addr().expect("server address"));
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let raw = read_request_raw(&mut stream);
        let _ = tx.send(raw);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });
    (url, rx)
}

fn read_request_raw(stream: &mut std::net::TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0; 512];
    loop {
        let read = stream.read(&mut chunk).expect("read request");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = find_header_end(&buffer) {
            let content_length = content_length(&buffer[..header_end]).unwrap_or(0);
            if buffer.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&buffer).to_string()
}

#[test]
fn error_status_surfaces_response_body() {
    let url = server(
        "400 Bad Request",
        r#"{"error":{"code":"content_filter","message":"blocked"}}"#,
    );
    let annotator = invocation(&[
        ("type", json!("endpoint")),
        ("from", json!("$policy_target.text")),
        ("url", json!(url)),
    ]);

    let error = EndpointAnnotator::new()
        .dispatch("metadata", &annotator, &input())
        .expect_err("status errors fail closed");

    assert!(
        error.to_string().contains("content_filter"),
        "error should carry the response body, got: {error}"
    );
}

#[test]
fn classifier_uses_custom_auth_header() {
    let (url, rx) = capturing_server("200 OK", r#"{"label":"safe"}"#);
    std::env::set_var("ACS_CLASSIFIER_HEADER_TEST_KEY", "secret-token");
    let annotator = invocation(&[
        ("type", json!("classifier")),
        ("from", json!("$policy_target.text")),
        ("url", json!(url)),
        ("api_key_env", json!("ACS_CLASSIFIER_HEADER_TEST_KEY")),
        ("api_key_header", json!("Ocp-Apim-Subscription-Key")),
    ]);

    ClassifierAnnotator::new()
        .dispatch("classifier", &annotator, &input())
        .expect("classifier succeeds");

    let raw = rx.recv().expect("server captured request").to_lowercase();
    assert!(
        raw.contains("ocp-apim-subscription-key: secret-token"),
        "custom auth header should be sent verbatim, got: {raw}"
    );
    assert!(
        !raw.contains("authorization: bearer"),
        "custom header must replace the default Bearer auth"
    );
}
