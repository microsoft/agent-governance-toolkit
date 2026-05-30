use super::{
    BundledClassifierProvider, ClassifierVerdict, HttpTransport, ResolvedClassifierConfig,
    TransportRequest,
};
use crate::dispatchers::constants::*;
use serde_json::json;
use std::collections::BTreeMap;

const DEFAULT_MODEL: &str = "meta-llama/Llama-Guard-3-8B";

#[derive(Debug, Default, Clone, Copy)]
pub struct LlamaGuardProvider;

impl BundledClassifierProvider for LlamaGuardProvider {
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
            .ok_or_else(|| "llama_guard api key is required".to_string())?;
        if cfg.endpoint.is_empty() {
            return Err("llama_guard endpoint is required".to_string());
        }

        let model = cfg
            .provider_config
            .get("model")
            .and_then(|value| value.as_str())
            .unwrap_or(DEFAULT_MODEL);
        let body = json!({
            "model": model,
            "messages": [{"role": "user", "content": subject}],
        });
        let mut request = TransportRequest::post(&cfg.endpoint)
            .header(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON)
            .header(HEADER_ACCEPT, CONTENT_TYPE_JSON)
            .header("Authorization", format!("Bearer {api_key}"))
            .json(body)
            .timeout_ms(cfg.timeout_ms);
        for (name, value) in &cfg.extra_headers {
            request = request.header(name, value);
        }

        let response = transport.send(request)?;
        if !(200..300).contains(&response.status) {
            return Err(format!(
                "llama_guard HTTP {} {}",
                response.status, response.body
            ));
        }
        parse_response(cfg, &response.body)
    }
}

fn parse_response(cfg: &ResolvedClassifierConfig, body: &str) -> Result<ClassifierVerdict, String> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| format!("llama_guard JSON parse failed {error}"))?;
    let content = value
        .get("choices")
        .and_then(|value| value.as_array())
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .ok_or_else(|| "llama_guard response missing choices[0].message.content".to_string())?;

    let mut lines = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let verdict = lines
        .next()
        .ok_or_else(|| "llama_guard response content was empty".to_string())?;
    let unsafe_verdict = verdict.eq_ignore_ascii_case("unsafe");
    if !unsafe_verdict && !verdict.eq_ignore_ascii_case("safe") {
        return Err(format!(
            "llama_guard response first line was not safe or unsafe {verdict}"
        ));
    }

    let categories = if unsafe_verdict {
        lines.next().map(parse_categories).unwrap_or_default()
    } else {
        Vec::new()
    };
    let category_scores = categories
        .iter()
        .map(|category| (category.clone(), 1.0))
        .collect::<BTreeMap<_, _>>();
    let label = if unsafe_verdict {
        categories
            .first()
            .cloned()
            .or_else(|| Some("unsafe".to_string()))
    } else {
        Some("safe".to_string())
    };

    Ok(ClassifierVerdict {
        flagged: unsafe_verdict,
        score: if unsafe_verdict { 1.0 } else { 0.0 },
        threshold: cfg.threshold,
        label,
        reason: (unsafe_verdict && !categories.is_empty()).then(|| categories.join(",")),
        category_scores,
    })
}

fn parse_categories(line: &str) -> Vec<String> {
    line.split(|character: char| character == ',' || character.is_whitespace())
        .map(str::trim)
        .filter(|category| !category.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatchers::bundled::StubHttpTransport;

    fn cfg() -> ResolvedClassifierConfig {
        ResolvedClassifierConfig {
            provider: "llama_guard".to_string(),
            endpoint: "https://llama.example/v1/chat/completions".to_string(),
            api_key: Some("test-key".to_string()),
            timeout_ms: 1000,
            threshold: 0.5,
            category_thresholds: BTreeMap::new(),
            extra_headers: BTreeMap::new(),
            provider_config: serde_json::Value::Null,
        }
    }

    #[test]
    fn safe_response_allows_with_safe_label() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"choices":[{"message":{"content":"safe\n"}}]}"#,
        );
        let verdict = LlamaGuardProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap();
        assert!(!verdict.is_failure());
        assert_eq!(verdict.label.as_deref(), Some("safe"));
        assert!(verdict.category_scores.is_empty());
    }

    #[test]
    fn unsafe_response_blocks_with_category_reason() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"choices":[{"message":{"content":"unsafe\nS1,S5"}}]}"#,
        );
        let verdict = LlamaGuardProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap();
        assert!(verdict.is_failure());
        assert_eq!(verdict.score, 1.0);
        assert_eq!(verdict.label.as_deref(), Some("S1"));
        assert!(verdict.reason.as_deref().unwrap().contains("S1"));
        assert!(verdict.reason.as_deref().unwrap().contains("S5"));
        assert_eq!(verdict.category_scores.get("S1"), Some(&1.0));
        assert_eq!(verdict.category_scores.get("S5"), Some(&1.0));
    }

    #[test]
    fn http_500_fails_closed() {
        let transport = StubHttpTransport::with_response(500, "server error");
        let error = LlamaGuardProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap_err();
        assert!(error.contains("llama_guard HTTP 500 server error"));
    }

    #[test]
    fn malformed_response_fails_closed() {
        let transport = StubHttpTransport::with_response(200, r#"{"unexpected":true}"#);
        let error = LlamaGuardProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap_err();
        assert!(error.contains("missing choices[0].message.content"));
    }

    #[test]
    fn request_uses_chat_completions_shape() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"choices":[{"message":{"content":"safe"}}]}"#,
        );
        let _ = LlamaGuardProvider
            .classify(&cfg(), "hello", &transport)
            .unwrap();
        let request = transport.last_request().unwrap();
        assert_eq!(request.url, "https://llama.example/v1/chat/completions");
        assert_eq!(
            request.headers.get("Authorization").map(String::as_str),
            Some("Bearer test-key")
        );
        assert_eq!(request.body["model"], DEFAULT_MODEL);
        assert_eq!(request.body["messages"][0]["role"], "user");
        assert_eq!(request.body["messages"][0]["content"], "hello");
    }

    #[test]
    fn custom_model_is_supported() {
        let mut cfg = cfg();
        cfg.provider_config = json!({"model": "custom-guard"});
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"choices":[{"message":{"content":"safe"}}]}"#,
        );
        let _ = LlamaGuardProvider
            .classify(&cfg, "hello", &transport)
            .unwrap();
        assert_eq!(
            transport.last_request().unwrap().body["model"],
            "custom-guard"
        );
    }
}
