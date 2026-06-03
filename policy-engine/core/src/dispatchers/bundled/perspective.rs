use super::{
    fold_score_verdict, BundledClassifierProvider, ClassifierVerdict, HttpTransport,
    ResolvedClassifierConfig, TransportRequest,
};
use crate::dispatchers::constants::*;
use crate::JsonValue;
use serde_json::json;
use std::collections::BTreeMap;

const DEFAULT_ENDPOINT: &str = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze";
const DEFAULT_ATTRIBUTES: &[&str] = &["TOXICITY"];

#[derive(Debug, Default, Clone, Copy)]
pub struct PerspectiveProvider;

impl BundledClassifierProvider for PerspectiveProvider {
    fn classify(
        &self,
        cfg: &ResolvedClassifierConfig,
        subject: &str,
        transport: &dyn HttpTransport,
    ) -> Result<ClassifierVerdict, String> {
        let api_key = cfg
            .api_key
            .as_deref()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| "perspective api key is required".to_string())?;
        let attributes = attributes(cfg)?;
        let body = json!({
            "comment": { "text": subject },
            "requestedAttributes": requested_attributes(&attributes),
        });
        let mut request = TransportRequest::post(analyze_url(&cfg.endpoint, api_key))
            .header(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON)
            .header(HEADER_ACCEPT, CONTENT_TYPE_JSON)
            .json(body)
            .timeout_ms(cfg.timeout_ms);
        for (name, value) in &cfg.extra_headers {
            request = request.header(name, value);
        }

        let response = transport.send(request)?;
        if !(200..300).contains(&response.status) {
            return Err(format!(
                "perspective HTTP {} {}",
                response.status, response.body
            ));
        }
        parse_response(cfg, &response.body, &attributes)
    }
}

fn analyze_url(endpoint: &str, api_key: &str) -> String {
    let base = if endpoint.is_empty() {
        DEFAULT_ENDPOINT
    } else {
        endpoint
    };
    if base.contains("?key=") || base.contains("&key=") {
        base.to_string()
    } else if base.contains('?') {
        format!("{base}&key={api_key}")
    } else {
        format!("{base}?key={api_key}")
    }
}

fn attributes(cfg: &ResolvedClassifierConfig) -> Result<Vec<String>, String> {
    if !cfg.category_thresholds.is_empty() {
        return Ok(cfg.category_thresholds.keys().cloned().collect());
    }
    if let Some(values) = cfg
        .provider_config
        .get("attributes")
        .and_then(JsonValue::as_array)
    {
        let attributes = values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|text| !text.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| {
                        "perspective provider_config attributes must be strings".to_string()
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if attributes.is_empty() {
            return Err("perspective attributes must not be empty".to_string());
        }
        return Ok(attributes);
    }
    Ok(DEFAULT_ATTRIBUTES
        .iter()
        .map(|value| value.to_string())
        .collect())
}

fn requested_attributes(attributes: &[String]) -> JsonValue {
    let mut object = serde_json::Map::new();
    for attribute in attributes {
        object.insert(attribute.clone(), json!({}));
    }
    JsonValue::Object(object)
}

fn parse_response(
    cfg: &ResolvedClassifierConfig,
    body: &str,
    expected_attributes: &[String],
) -> Result<ClassifierVerdict, String> {
    let value: JsonValue = serde_json::from_str(body)
        .map_err(|error| format!("perspective JSON parse failed {error}"))?;
    let attribute_scores = value
        .get("attributeScores")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| "perspective response missing attributeScores".to_string())?;
    if attribute_scores.is_empty() {
        return Err("perspective response attributeScores was empty".to_string());
    }

    let mut scores = BTreeMap::new();
    for attribute in expected_attributes {
        let score = attribute_scores
            .get(attribute)
            .ok_or_else(|| format!("perspective response missing attribute {attribute}"))?
            .get("summaryScore")
            .and_then(|value| value.get("value"))
            .and_then(JsonValue::as_f64)
            .ok_or_else(|| format!("perspective response attribute {attribute} missing score"))?;
        scores.insert(attribute.clone(), score);
    }

    Ok(fold_score_verdict(cfg, &scores))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatchers::bundled::StubHttpTransport;

    fn cfg() -> ResolvedClassifierConfig {
        let mut thresholds = BTreeMap::new();
        thresholds.insert("TOXICITY".to_string(), 0.5);
        ResolvedClassifierConfig {
            provider: "perspective".to_string(),
            endpoint: "".to_string(),
            api_key: Some("test-key".to_string()),
            timeout_ms: 1000,
            threshold: 0.5,
            category_thresholds: thresholds,
            extra_headers: BTreeMap::new(),
            provider_config: JsonValue::Null,
        }
    }

    #[test]
    fn allow_when_score_is_low() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"attributeScores":{"TOXICITY":{"summaryScore":{"value":0.1}}}}"#,
        );
        let verdict = PerspectiveProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap();
        assert!(!verdict.is_failure());
    }

    #[test]
    fn block_when_score_is_high() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"attributeScores":{"TOXICITY":{"summaryScore":{"value":0.9}}}}"#,
        );
        let verdict = PerspectiveProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap();
        assert!(verdict.is_failure());
        assert_eq!(verdict.label.as_deref(), Some("TOXICITY"));
    }

    #[test]
    fn http_429_fails_closed() {
        let transport = StubHttpTransport::with_response(429, "rate limited");
        let error = PerspectiveProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap_err();
        assert!(error.contains("HTTP 429"));
    }

    #[test]
    fn malformed_body_fails_closed() {
        let transport = StubHttpTransport::with_response(200, r#"{"unexpected":true}"#);
        let error = PerspectiveProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap_err();
        assert!(error.contains("missing attributeScores"));
    }

    #[test]
    fn request_uses_api_key_query_and_body() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"attributeScores":{"TOXICITY":{"summaryScore":{"value":0.1}}}}"#,
        );
        let _ = PerspectiveProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap();
        let request = transport.last_request().unwrap();
        assert_eq!(
            request.url,
            "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key=test-key"
        );
        assert_eq!(
            request.body,
            json!({
                "comment": { "text": "hello" },
                "requestedAttributes": { "TOXICITY": {} },
            })
        );
    }

    #[test]
    fn request_preserves_existing_query_parameters() {
        let mut cfg = cfg();
        cfg.endpoint = "https://example.test/analyze?prettyPrint=false".to_string();
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"attributeScores":{"TOXICITY":{"summaryScore":{"value":0.1}}}}"#,
        );

        let _ = PerspectiveProvider
            .classify(&cfg, "hello", &transport)
            .unwrap();

        assert_eq!(
            transport.last_request().unwrap().url,
            "https://example.test/analyze?prettyPrint=false&key=test-key"
        );
    }

    #[test]
    fn provider_config_attributes_are_requested() {
        let mut cfg = cfg();
        cfg.category_thresholds.clear();
        cfg.provider_config = json!({ "attributes": ["INSULT"] });
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"attributeScores":{"INSULT":{"summaryScore":{"value":0.9}}}}"#,
        );

        let verdict = PerspectiveProvider
            .classify(&cfg, "hello", &transport)
            .unwrap();

        assert!(verdict.is_failure());
        assert_eq!(verdict.label.as_deref(), Some("INSULT"));
    }
}
