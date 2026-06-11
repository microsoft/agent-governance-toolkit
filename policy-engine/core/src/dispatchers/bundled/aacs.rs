use super::{
    fold_score_verdict, BundledClassifierProvider, ClassifierVerdict, HttpTransport,
    ResolvedClassifierConfig, TransportRequest,
};
use crate::dispatchers::constants::*;
use serde_json::json;
use std::collections::BTreeMap;

const DEFAULT_API_VERSION: &str = "2024-09-01";
const DEFAULT_CATEGORIES: &[&str] = &["Hate", "SelfHarm", "Sexual", "Violence"];

#[derive(Debug, Default, Clone, Copy)]
pub struct AacsProvider;

impl BundledClassifierProvider for AacsProvider {
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
            .ok_or_else(|| "aacs api key is required".to_string())?;
        if cfg.endpoint.is_empty() {
            return Err("aacs endpoint is required".to_string());
        }

        let api_version = cfg
            .provider_config
            .get("api_version")
            .and_then(|value| value.as_str())
            .unwrap_or(DEFAULT_API_VERSION);
        let categories = categories(cfg)?;
        let body = json!({
            "text": subject,
            "categories": categories,
            "outputType": "FourSeverityLevels",
        });
        let mut request = TransportRequest::post(analyze_url(&cfg.endpoint, api_version))
            .header(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON)
            .header(HEADER_ACCEPT, CONTENT_TYPE_JSON)
            .header("Ocp-Apim-Subscription-Key", api_key)
            .json(body)
            .timeout_ms(cfg.timeout_ms);
        for (name, value) in &cfg.extra_headers {
            request = request.header(name, value);
        }

        let response = transport.send(request)?;
        if !(200..300).contains(&response.status) {
            return Err(format!("aacs HTTP {} {}", response.status, response.body));
        }
        parse_response(cfg, &response.body, &categories)
    }
}

fn analyze_url(endpoint: &str, api_version: &str) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    if endpoint.contains("/contentsafety/") {
        if endpoint.contains("api-version=") {
            endpoint.to_string()
        } else if endpoint.contains('?') {
            format!("{endpoint}&api-version={api_version}")
        } else {
            format!("{endpoint}?api-version={api_version}")
        }
    } else {
        format!("{endpoint}/contentsafety/text:analyze?api-version={api_version}")
    }
}

fn categories(cfg: &ResolvedClassifierConfig) -> Result<Vec<String>, String> {
    if !cfg.category_thresholds.is_empty() {
        return Ok(cfg.category_thresholds.keys().cloned().collect());
    }
    if let Some(values) = cfg
        .provider_config
        .get("categories")
        .and_then(|value| value.as_array())
    {
        let categories = values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|text| !text.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| "aacs provider_config categories must be strings".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if categories.is_empty() {
            return Err("aacs categories must not be empty".to_string());
        }
        return Ok(categories);
    }
    Ok(DEFAULT_CATEGORIES
        .iter()
        .map(|value| value.to_string())
        .collect())
}

fn parse_response(
    cfg: &ResolvedClassifierConfig,
    body: &str,
    expected_categories: &[String],
) -> Result<ClassifierVerdict, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| format!("aacs JSON parse failed {error}"))?;
    let analysis = value
        .get("categoriesAnalysis")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "aacs response missing categoriesAnalysis".to_string())?;
    if analysis.is_empty() {
        return Err("aacs response categoriesAnalysis was empty".to_string());
    }

    let mut scores = BTreeMap::new();
    for item in analysis {
        let category = item
            .get("category")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "aacs response item missing category".to_string())?;
        let severity = item
            .get("severity")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| "aacs response item missing severity".to_string())?;
        if !matches!(severity, 0 | 2 | 4 | 6) {
            return Err(format!("aacs response severity {severity} is invalid"));
        }
        scores.insert(category.to_string(), severity as f64 / 6.0);
    }
    for category in expected_categories {
        if !scores.contains_key(category) {
            return Err(format!("aacs response missing category {category}"));
        }
    }

    Ok(fold_score_verdict(cfg, &scores))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatchers::bundled::StubHttpTransport;

    fn cfg() -> ResolvedClassifierConfig {
        let mut thresholds = BTreeMap::new();
        thresholds.insert("Hate".to_string(), 0.5);
        ResolvedClassifierConfig {
            provider: "aacs".to_string(),
            endpoint: "https://example.cognitiveservices.azure.com".to_string(),
            api_key: Some("test-key".to_string()),
            timeout_ms: 1000,
            threshold: 0.5,
            category_thresholds: thresholds,
            extra_headers: BTreeMap::new(),
            provider_config: serde_json::Value::Null,
        }
    }

    #[test]
    fn allow_when_severity_is_zero() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":0}]}"#,
        );
        let verdict = AacsProvider.classify(&cfg(), "hello", &transport).unwrap();
        assert!(!verdict.is_failure());
    }

    #[test]
    fn block_when_severity_is_high() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":6}]}"#,
        );
        let verdict = AacsProvider.classify(&cfg(), "hello", &transport).unwrap();
        assert!(verdict.is_failure());
        assert_eq!(verdict.label.as_deref(), Some("Hate"));
    }

    #[test]
    fn http_429_fails_closed() {
        let transport = StubHttpTransport::with_response(429, "rate limited");
        let error = AacsProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap_err();
        assert!(error.contains("HTTP 429"));
    }

    #[test]
    fn malformed_body_fails_closed() {
        let transport = StubHttpTransport::with_response(200, r#"{"unexpected":true}"#);
        let error = AacsProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap_err();
        assert!(error.contains("missing categoriesAnalysis"));
    }

    #[test]
    fn request_uses_aacs_header_and_url() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":0}]}"#,
        );
        let _ = AacsProvider.classify(&cfg(), "hello", &transport).unwrap();
        let request = transport.last_request().unwrap();
        assert_eq!(
            request
                .headers
                .get("Ocp-Apim-Subscription-Key")
                .map(String::as_str),
            Some("test-key")
        );
        assert_eq!(
            request.url,
            "https://example.cognitiveservices.azure.com/contentsafety/text:analyze?api-version=2024-09-01"
        );
    }

    #[test]
    fn request_preserves_existing_query_parameters() {
        let mut cfg = cfg();
        cfg.endpoint =
            "https://example.cognitiveservices.azure.com/contentsafety/text:analyze?logging=off"
                .to_string();
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":0}]}"#,
        );

        let _ = AacsProvider.classify(&cfg, "hello", &transport).unwrap();

        assert_eq!(
            transport.last_request().unwrap().url,
            "https://example.cognitiveservices.azure.com/contentsafety/text:analyze?logging=off&api-version=2024-09-01"
        );
    }

    #[test]
    fn request_does_not_duplicate_existing_api_version() {
        let mut cfg = cfg();
        cfg.endpoint = "https://example.cognitiveservices.azure.com/contentsafety/text:analyze?logging=off&api-version=2023-10-01"
            .to_string();
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":0}]}"#,
        );

        let _ = AacsProvider.classify(&cfg, "hello", &transport).unwrap();

        assert_eq!(
            transport.last_request().unwrap().url,
            "https://example.cognitiveservices.azure.com/contentsafety/text:analyze?logging=off&api-version=2023-10-01"
        );
    }
}
