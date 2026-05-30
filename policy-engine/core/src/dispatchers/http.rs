use crate::dispatchers::{
    bundled::{TransportRequest, TransportResponse},
    constants::*,
    resolve::failed,
};
use crate::{JsonValue, RuntimeError};
use serde_json::json;
use std::{collections::BTreeMap, env, io::Read, time::Duration};

/// An authorization header to attach to an annotator HTTP request.
///
/// Defaults to `Authorization: Bearer <key>` (OpenAI-style), but the header
/// name can be overridden via the `api_key_header` field so Azure-family
/// services work too (`api-key` for Azure OpenAI, `Ocp-Apim-Subscription-Key`
/// for Azure AI Content Safety).
pub struct Authorization {
    pub header: String,
    pub value: String,
}

pub fn post_json(
    annotator_name: &str,
    url: &str,
    payload: JsonValue,
    authorization: Option<Authorization>,
) -> Result<JsonValue, RuntimeError> {
    let agent = ureq::AgentBuilder::new().build();
    let mut request = agent
        .post(url)
        .set(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON)
        .set(HEADER_ACCEPT, CONTENT_TYPE_JSON);
    if let Some(authorization) = &authorization {
        request = request.set(&authorization.header, &authorization.value);
    }
    let response = request.send_json(payload).map_err(|error| match error {
        ureq::Error::Status(code, response) => {
            let status_text = response.status_text().to_string();
            let body = read_error_body(response);
            if body.is_empty() {
                failed(
                    annotator_name,
                    format!("HTTP request failed with status {code}: {status_text}"),
                )
            } else {
                failed(
                    annotator_name,
                    format!("HTTP request failed with status {code} ({status_text}): {body}"),
                )
            }
        }
        ureq::Error::Transport(error) => {
            failed(annotator_name, format!("HTTP request failed: {error}"))
        }
    })?;
    parse_response(annotator_name, response)
}

/// Reads a bounded slice of an error response body so failures stay diagnosable
/// (e.g. an Azure `content_filter` rejection carries its reason in the body).
fn read_error_body(response: ureq::Response) -> String {
    let mut body = String::new();
    let _ = response
        .into_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_string(&mut body);
    body.trim().to_string()
}

fn parse_response(
    annotator_name: &str,
    response: ureq::Response,
) -> Result<JsonValue, RuntimeError> {
    let body = read_response_body(response).map_err(|error| failed(annotator_name, error))?;
    serde_json::from_str(&body).map_err(|error| {
        failed(
            annotator_name,
            format!("HTTP response was not valid JSON: {error}"),
        )
    })
}

pub fn read_response_body(response: ureq::Response) -> Result<String, String> {
    let mut body = String::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|error| format!("HTTP response read failed: {error}"))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("HTTP response exceeded size limit".to_string());
    }
    Ok(body)
}

pub fn send_transport_request(request: TransportRequest) -> Result<TransportResponse, String> {
    if request.method != "POST" {
        return Err(format!("unsupported HTTP method '{}'", request.method));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(request.timeout_ms))
        .build();
    let mut outbound = agent.post(&request.url);
    for (name, value) in &request.headers {
        outbound = outbound.set(name, value);
    }
    match outbound.send_json(request.body) {
        Ok(response) => Ok(TransportResponse {
            status: response.status(),
            body: read_response_body(response)?,
        }),
        Err(ureq::Error::Status(status, response)) => Ok(TransportResponse {
            status,
            body: read_response_body(response)?,
        }),
        Err(ureq::Error::Transport(error)) => Err(format!("HTTP request failed: {error}")),
    }
}

pub fn required_string_field<'a>(
    annotator_name: &str,
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, RuntimeError> {
    fields
        .get(name)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| failed(annotator_name, format!("missing required field '{name}'")))
}

pub fn optional_string_field<'a>(
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Option<&'a str> {
    fields
        .get(name)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
}

pub fn env_api_key(
    annotator_name: &str,
    fields: &BTreeMap<String, JsonValue>,
) -> Result<Option<Authorization>, RuntimeError> {
    let Some(env_name) = optional_string_field(fields, FIELD_API_KEY_ENV) else {
        return Ok(None);
    };
    let key = env::var(env_name).map_err(|_| {
        failed(
            annotator_name,
            format!("API key environment variable '{env_name}' is not set"),
        )
    })?;
    Ok(Some(authorization(fields, key)))
}

pub fn required_env_api_key(
    annotator_name: &str,
    fields: &BTreeMap<String, JsonValue>,
) -> Result<Authorization, RuntimeError> {
    let env_name =
        optional_string_field(fields, FIELD_API_KEY_ENV).unwrap_or(DEFAULT_OPENAI_API_KEY_ENV);
    let key = env::var(env_name).map_err(|_| {
        failed(
            annotator_name,
            format!("API key environment variable '{env_name}' is not set"),
        )
    })?;
    Ok(authorization(fields, key))
}

/// Builds the authorization header for a request. Uses `api_key_header` when
/// present (raw key value), otherwise the OpenAI-style `Authorization: Bearer`.
fn authorization(fields: &BTreeMap<String, JsonValue>, key: String) -> Authorization {
    match optional_string_field(fields, FIELD_API_KEY_HEADER) {
        Some(header) => Authorization {
            header: header.to_string(),
            value: key,
        },
        None => Authorization {
            header: HEADER_AUTHORIZATION.to_string(),
            value: format!("{AUTH_BEARER_PREFIX}{key}"),
        },
    }
}

pub fn configured_fields(
    fields: &BTreeMap<String, JsonValue>,
    transport_fields: &[&str],
) -> JsonValue {
    let mut config = serde_json::Map::new();
    for (key, value) in fields {
        if !transport_fields.contains(&key.as_str()) {
            config.insert(key.clone(), value.clone());
        }
    }
    JsonValue::Object(config)
}

pub fn endpoint_payload(input: String, fields: &BTreeMap<String, JsonValue>) -> JsonValue {
    json!({
        REQUEST_INPUT: input,
        REQUEST_FIELDS: configured_fields(fields, &[ANNOTATOR_TYPE, FIELD_FROM, FIELD_INPUT_FROM, FIELD_URL]),
    })
}
