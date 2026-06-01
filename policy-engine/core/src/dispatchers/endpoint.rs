use crate::dispatchers::{constants::*, http, resolve};
use crate::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue, RuntimeError};

#[derive(Debug, Default, Clone, Copy)]
pub struct EndpointAnnotator;

impl EndpointAnnotator {
    pub fn new() -> Self {
        Self
    }
}

impl AnnotatorDispatcher for EndpointAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        if annotator.field(ANNOTATOR_TYPE).and_then(JsonValue::as_str) != Some(TYPE_ENDPOINT) {
            return Err(resolve::failed(
                annotator_name,
                "endpoint dispatcher received a non-endpoint annotator",
            ));
        }
        let url = http::optional_string_field(&annotator.fields, FIELD_ENDPOINT)
            .or_else(|| http::optional_string_field(&annotator.fields, FIELD_URL))
            .ok_or_else(|| {
                resolve::failed(annotator_name, "missing required field 'endpoint' or 'url'")
            })?;
        let timeout_ms = http::timeout_ms(annotator_name, &annotator.fields)?;
        let policy_target =
            resolve::policy_target_text(annotator_name, annotator, preliminary_policy_input)?;
        let output = http::post_json(
            annotator_name,
            url,
            http::endpoint_payload(policy_target, &annotator.fields),
            None,
            timeout_ms,
        )?;
        if !output.is_object() {
            return Err(resolve::failed(
                annotator_name,
                "endpoint annotator response must be a JSON object",
            ));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    #[test]
    fn endpoint_annotator_accepts_endpoint_field() {
        let (url, request) = json_server(r#"{"label":"safe"}"#);
        let annotator = AnnotatorInvocation {
            fields: BTreeMap::from([
                (ANNOTATOR_TYPE.to_string(), json!(TYPE_ENDPOINT)),
                (FIELD_ENDPOINT.to_string(), json!(url)),
                (FIELD_FROM.to_string(), json!("$policy_target")),
                (FIELD_TIMEOUT_MS.to_string(), json!(1000)),
                ("purpose".to_string(), json!("probe")),
            ]),
        };

        let output = EndpointAnnotator
            .dispatch(
                "endpoint_scan",
                &annotator,
                &json!({"policy_target": {"value": "hello endpoint"}}),
            )
            .unwrap();

        assert_eq!(output, json!({"label": "safe"}));
        let request = request.join().unwrap();
        assert!(request.starts_with("POST / HTTP/1.1"));
        assert!(request.contains(r#""input":"hello endpoint""#));
        assert!(request.contains(r#""purpose":"probe""#));
        assert!(!request.contains(r#""endpoint":"#));
    }

    #[test]
    fn endpoint_payload_excludes_transport_and_credentials() {
        let (url, request) = json_server(r#"{"label":"safe"}"#);
        let annotator = AnnotatorInvocation {
            fields: BTreeMap::from([
                (ANNOTATOR_TYPE.to_string(), json!(TYPE_ENDPOINT)),
                (FIELD_ENDPOINT.to_string(), json!(url)),
                (FIELD_FROM.to_string(), json!("$policy_target")),
                (FIELD_TIMEOUT_MS.to_string(), json!(1000)),
                (FIELD_API_KEY.to_string(), json!("secret-key")),
                (FIELD_API_KEY_ENV.to_string(), json!("ACS_SECRET_KEY")),
                (FIELD_API_KEY_HEADER.to_string(), json!("X-Api-Key")),
                (
                    FIELD_HEADERS.to_string(),
                    json!({"Authorization": "Bearer secret"}),
                ),
                (FIELD_AWS_ACCESS_KEY_ID.to_string(), json!("AKIAFAKE")),
                (FIELD_AWS_SECRET_ACCESS_KEY.to_string(), json!("secret")),
                (FIELD_AWS_SESSION_TOKEN.to_string(), json!("token")),
                ("purpose".to_string(), json!("probe")),
            ]),
        };

        let output = EndpointAnnotator
            .dispatch(
                "endpoint_scan",
                &annotator,
                &json!({"policy_target": {"value": "hello endpoint"}}),
            )
            .unwrap();

        assert_eq!(output, json!({"label": "safe"}));
        let request = request.join().unwrap();
        assert!(request.contains(r#""purpose":"probe""#));
        for forbidden in [
            "secret-key",
            "ACS_SECRET_KEY",
            "X-Api-Key",
            "Authorization",
            "AKIAFAKE",
            "secret",
            "token",
            r#""headers""#,
        ] {
            assert!(
                !request.contains(forbidden),
                "endpoint payload leaked {forbidden}: {request}"
            );
        }
    }

    #[test]
    fn endpoint_annotator_rejects_non_object_json_response() {
        let (url, _request) = json_server(r#""safe""#);
        let annotator = AnnotatorInvocation {
            fields: BTreeMap::from([
                (ANNOTATOR_TYPE.to_string(), json!(TYPE_ENDPOINT)),
                (FIELD_ENDPOINT.to_string(), json!(url)),
                (FIELD_FROM.to_string(), json!("$policy_target")),
                (FIELD_TIMEOUT_MS.to_string(), json!(1000)),
            ]),
        };

        let error = EndpointAnnotator
            .dispatch(
                "endpoint_scan",
                &annotator,
                &json!({"policy_target": {"value": "hello endpoint"}}),
            )
            .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:annotation_failed");
        assert!(error
            .detail()
            .contains("endpoint annotator response must be a JSON object"));
    }

    fn json_server(response_body: &'static str) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buffer = Vec::new();
            let mut chunk = [0; 1024];
            loop {
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if request_body_complete(&buffer) {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8(buffer).unwrap()
        });
        (url, handle)
    }

    fn request_body_complete(buffer: &[u8]) -> bool {
        let Some(headers_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let body_start = headers_end + 4;
        let headers = String::from_utf8_lossy(&buffer[..headers_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        buffer.len().saturating_sub(body_start) >= content_length
    }
}
