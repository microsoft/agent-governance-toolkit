use super::{
    BundledClassifierProvider, ClassifierVerdict, HttpTransport, ResolvedClassifierConfig,
};

/// Deterministic selector that resolves a concrete bundled classifier provider from
/// the annotator configuration and delegates to it. The selection is stateless and
/// derives only from the resolved config, so it returns the same provider for the
/// same input. Resolution order is an explicit `provider` hint in `provider_config`
/// first, then inference from the endpoint URL. When no provider can be resolved the
/// auto provider fails closed with a descriptive error rather than guessing.
pub struct AutoProvider;

/// Maps common provider aliases onto the canonical underscore provider names that the
/// bundled dispatcher recognizes. Names that are already canonical pass through.
fn canonical_provider_name(name: &str) -> String {
    match name.trim().to_ascii_lowercase().as_str() {
        "aacs" | "azure_content_safety" | "azure-content-safety" | "content_safety" | "acs" => {
            "aacs".to_string()
        }
        "openai_moderation" | "openai-moderation" | "openai" | "moderation"
        | "openai_moderations" => "openai_moderation".to_string(),
        "perspective" | "perspective_api" | "perspective-api" => "perspective".to_string(),
        "llama_guard" | "llama-guard" | "llamaguard" | "llama_guard_3" => "llama_guard".to_string(),
        "lakera_guard" | "lakera-guard" | "lakera" => "lakera_guard".to_string(),
        other => other.to_string(),
    }
}

/// Infers a canonical provider name from an endpoint URL. Returns None when no known
/// provider signature matches the endpoint.
fn provider_from_endpoint(endpoint: &str) -> Option<String> {
    let url = endpoint.to_ascii_lowercase();
    if url.contains("/contentsafety/") || url.contains("cognitiveservices") {
        Some("aacs".to_string())
    } else if url.contains("commentanalyzer") || url.contains("comments:analyze") {
        Some("perspective".to_string())
    } else if url.contains("lakera") {
        Some("lakera_guard".to_string())
    } else if url.contains("/moderations") {
        Some("openai_moderation".to_string())
    } else if url.contains("/chat/completions") {
        Some("llama_guard".to_string())
    } else {
        None
    }
}

/// Resolves the concrete provider name the auto provider will delegate to. An explicit
/// `provider` string under `provider_config` takes precedence over endpoint inference.
fn resolve_target(cfg: &ResolvedClassifierConfig) -> Result<String, String> {
    if let Some(hint) = cfg
        .provider_config
        .get("provider")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
    {
        let target = canonical_provider_name(hint);
        if target == "auto" {
            return Err(
                "auto classifier provider_config.provider cannot itself be 'auto'".to_string(),
            );
        }
        return Ok(target);
    }

    provider_from_endpoint(&cfg.endpoint).ok_or_else(|| {
        "auto classifier could not determine a provider from the endpoint; set \
         provider_config.provider to one of aacs, openai_moderation, perspective, \
         llama_guard, lakera_guard"
            .to_string()
    })
}

impl BundledClassifierProvider for AutoProvider {
    fn classify(
        &self,
        cfg: &ResolvedClassifierConfig,
        subject: &str,
        transport: &dyn HttpTransport,
    ) -> Result<ClassifierVerdict, String> {
        let target = resolve_target(cfg)?;
        let mut resolved = cfg.clone();
        resolved.provider = target;
        super::classify(&resolved, subject, transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatchers::bundled::StubHttpTransport;
    use crate::JsonValue;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn cfg(endpoint: &str, provider_config: JsonValue) -> ResolvedClassifierConfig {
        ResolvedClassifierConfig {
            provider: "auto".to_string(),
            endpoint: endpoint.to_string(),
            api_key: Some("test-key".to_string()),
            timeout_ms: 1000,
            threshold: 0.5,
            category_thresholds: BTreeMap::new(),
            extra_headers: BTreeMap::new(),
            provider_config,
        }
    }

    #[test]
    fn explicit_hint_takes_precedence_and_normalizes_aliases() {
        let resolved = resolve_target(&cfg(
            "https://example.test/",
            json!({"provider": "azure_content_safety"}),
        ))
        .unwrap();
        assert_eq!(resolved, "aacs");
    }

    #[test]
    fn endpoint_inference_matches_known_signatures() {
        assert_eq!(
            resolve_target(&cfg(
                "https://aacsesdktest.cognitiveservices.azure.com/contentsafety/text:analyze",
                JsonValue::Null
            ))
            .unwrap(),
            "aacs"
        );
        assert_eq!(
            resolve_target(&cfg("https://api.lakera.ai/v1/guard", JsonValue::Null)).unwrap(),
            "lakera_guard"
        );
        assert_eq!(
            resolve_target(&cfg(
                "https://api.openai.com/v1/moderations",
                JsonValue::Null
            ))
            .unwrap(),
            "openai_moderation"
        );
    }

    #[test]
    fn undeterminable_endpoint_fails_closed() {
        let error =
            resolve_target(&cfg("https://unknown.test/v1/score", JsonValue::Null)).unwrap_err();
        assert!(error.contains("could not determine a provider"));
    }

    #[test]
    fn nested_auto_hint_is_rejected() {
        let error =
            resolve_target(&cfg("https://example.test/", json!({"provider": "auto"}))).unwrap_err();
        assert!(error.contains("cannot itself be 'auto'"));
    }

    #[cfg(feature = "lakera_guard")]
    #[test]
    fn dispatches_to_resolved_provider() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"results":[{"flagged":false,"category_scores":{"prompt_injection":0.02}}]}"#,
        );
        let verdict = AutoProvider
            .classify(
                &cfg("https://api.lakera.ai/v1/guard", JsonValue::Null),
                "hello",
                &transport,
            )
            .unwrap();
        assert!(!verdict.is_failure());
        assert_eq!(verdict.score, 0.02);
    }
}
