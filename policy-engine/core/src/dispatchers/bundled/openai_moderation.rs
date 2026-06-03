use super::{
    fold_score_verdict, BundledClassifierProvider, ClassifierVerdict, HttpTransport,
    ResolvedClassifierConfig, TransportRequest,
};
use crate::dispatchers::constants::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const DEFAULT_ENDPOINT: &str = "https://api.openai.com/v1/moderations";
const DEFAULT_MODEL: &str = "omni-moderation-latest";

#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiModerationProvider;

impl BundledClassifierProvider for OpenAiModerationProvider {
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
            .ok_or_else(|| "openai_moderation api key is required".to_string())?;
        let endpoint = if cfg.endpoint.is_empty() {
            DEFAULT_ENDPOINT
        } else {
            cfg.endpoint.as_str()
        };
        let model = cfg
            .provider_config
            .get(FIELD_MODEL)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_MODEL);
        let body = json!({
            REQUEST_INPUT: subject,
            REQUEST_MODEL: model,
        });
        let mut request = TransportRequest::post(endpoint)
            .header(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON)
            .header(HEADER_ACCEPT, CONTENT_TYPE_JSON)
            .header(
                HEADER_AUTHORIZATION,
                format!("{AUTH_BEARER_PREFIX}{api_key}"),
            )
            .json(body)
            .timeout_ms(cfg.timeout_ms);
        for (name, value) in &cfg.extra_headers {
            request = request.header(name, value);
        }

        let response = transport.send(request)?;
        if !(200..300).contains(&response.status) {
            return Err(format!(
                "openai_moderation HTTP {} {}",
                response.status, response.body
            ));
        }
        parse_response(cfg, &response.body)
    }
}

fn parse_response(cfg: &ResolvedClassifierConfig, body: &str) -> Result<ClassifierVerdict, String> {
    let value: Value = serde_json::from_str(body)
        .map_err(|error| format!("openai_moderation JSON parse failed {error}"))?;
    let result = value
        .get("results")
        .and_then(Value::as_array)
        .and_then(|results| results.first())
        .ok_or_else(|| "openai_moderation response missing results[0]".to_string())?;
    let native_flagged = result
        .get("flagged")
        .and_then(Value::as_bool)
        .ok_or_else(|| "openai_moderation response missing flagged".to_string())?;
    let category_scores = result
        .get("category_scores")
        .and_then(Value::as_object)
        .ok_or_else(|| "openai_moderation response missing category_scores".to_string())?;
    if category_scores.is_empty() {
        return Err("openai_moderation response category_scores was empty".to_string());
    }

    let mut scores = BTreeMap::new();
    for (category, score) in category_scores {
        let score = score.as_f64().ok_or_else(|| {
            format!("openai_moderation response score {category} is not a number")
        })?;
        scores.insert(category.clone(), score);
    }

    let mut verdict = fold_score_verdict(cfg, &scores);
    if native_flagged && cfg.category_thresholds.is_empty() {
        verdict.flagged = true;
    }
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatchers::bundled::StubHttpTransport;

    fn cfg() -> ResolvedClassifierConfig {
        ResolvedClassifierConfig {
            provider: "openai_moderation".to_string(),
            endpoint: String::new(),
            api_key: Some("test-key".to_string()),
            timeout_ms: 1000,
            threshold: 0.5,
            category_thresholds: BTreeMap::new(),
            extra_headers: BTreeMap::new(),
            provider_config: Value::Null,
        }
    }

    #[test]
    fn allow_when_low_score() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"results":[{"flagged":false,"category_scores":{"hate":0.01,"violence":0.02}}]}"#,
        );
        let verdict = OpenAiModerationProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap();
        assert!(!verdict.is_failure());
    }

    #[test]
    fn block_when_high_score() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"results":[{"flagged":true,"category_scores":{"hate":0.91,"violence":0.02}}]}"#,
        );
        let verdict = OpenAiModerationProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap();
        assert!(verdict.is_failure());
        assert_eq!(verdict.label.as_deref(), Some("hate"));
    }

    #[test]
    fn http_429_fails_closed() {
        let transport = StubHttpTransport::with_response(429, "rate limited");
        let error = OpenAiModerationProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap_err();
        assert!(error.contains("HTTP 429"));
    }

    #[test]
    fn malformed_body_fails_closed() {
        let transport = StubHttpTransport::with_response(200, r#"{"results":[{"flagged":false}]}"#);
        let error = OpenAiModerationProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap_err();
        assert!(error.contains("missing category_scores"));
    }

    #[test]
    fn request_uses_default_endpoint_and_model() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"results":[{"flagged":false,"category_scores":{"hate":0.01}}]}"#,
        );
        let _ = OpenAiModerationProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap();
        let request = transport.last_request().unwrap();
        assert_eq!(request.url, DEFAULT_ENDPOINT);
        assert_eq!(
            request
                .headers
                .get(HEADER_AUTHORIZATION)
                .map(String::as_str),
            Some("Bearer test-key")
        );
        assert_eq!(
            request.body.get(REQUEST_MODEL).and_then(Value::as_str),
            Some(DEFAULT_MODEL)
        );
        assert_eq!(
            request.body.get(REQUEST_INPUT).and_then(Value::as_str),
            Some("hello")
        );
    }
}
