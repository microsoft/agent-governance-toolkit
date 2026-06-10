use crate::dispatchers::{constants::*, http};
use crate::JsonValue;
use serde_json::json;
use std::{collections::BTreeMap, sync::Mutex};

#[cfg(feature = "aacs")]
mod aacs;
#[cfg(feature = "auto")]
mod auto;
#[cfg(feature = "lakera_guard")]
mod lakera_guard;
#[cfg(feature = "llama_guard")]
mod llama_guard;
#[cfg(feature = "openai_moderation")]
mod openai_moderation;
#[cfg(feature = "perspective")]
mod perspective;

#[cfg(feature = "aacs")]
pub use aacs::AacsProvider;
#[cfg(feature = "auto")]
pub use auto::AutoProvider;
#[cfg(feature = "lakera_guard")]
pub use lakera_guard::LakeraGuardProvider;
#[cfg(feature = "llama_guard")]
pub use llama_guard::LlamaGuardProvider;
#[cfg(feature = "openai_moderation")]
pub use openai_moderation::OpenAiModerationProvider;
#[cfg(feature = "perspective")]
pub use perspective::PerspectiveProvider;

pub trait BundledClassifierProvider {
    fn classify(
        &self,
        cfg: &ResolvedClassifierConfig,
        subject: &str,
        transport: &dyn HttpTransport,
    ) -> Result<ClassifierVerdict, String>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassifierVerdict {
    pub flagged: bool,
    pub score: f64,
    pub threshold: f64,
    pub label: Option<String>,
    pub reason: Option<String>,
    pub category_scores: BTreeMap<String, f64>,
}

impl ClassifierVerdict {
    pub fn is_failure(&self) -> bool {
        self.flagged
    }

    pub fn to_json(&self) -> JsonValue {
        json!({
            "verdict": if self.flagged { "block" } else { "allow" },
            "flagged": self.flagged,
            "score": self.score,
            "threshold": self.threshold,
            "label": self.label,
            "reason": self.reason,
            "category_scores": self.category_scores,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedClassifierConfig {
    pub provider: String,
    pub endpoint: String,
    pub api_key: Option<String>,
    pub timeout_ms: u64,
    pub threshold: f64,
    pub category_thresholds: BTreeMap<String, f64>,
    pub extra_headers: BTreeMap<String, String>,
    pub provider_config: JsonValue,
}

impl ResolvedClassifierConfig {
    pub fn from_fields(fields: &BTreeMap<String, JsonValue>) -> Result<Self, String> {
        let provider = http::optional_string_field(fields, FIELD_PROVIDER)
            .ok_or_else(|| "missing required field 'provider'".to_string())?
            .to_ascii_lowercase();
        let endpoint = http::optional_string_field(fields, FIELD_ENDPOINT)
            .or_else(|| http::optional_string_field(fields, FIELD_BASE_URL))
            .or_else(|| http::optional_string_field(fields, FIELD_URL))
            .unwrap_or_default()
            .to_string();
        let api_key = match http::optional_string_field(fields, FIELD_API_KEY_ENV) {
            Some(env_name) => Some(
                std::env::var(env_name)
                    .map_err(|_| format!("API key environment variable '{env_name}' is not set"))?,
            ),
            None => None,
        };
        let threshold = optional_f64_field(fields, FIELD_THRESHOLD).unwrap_or(0.5);
        validate_threshold(FIELD_THRESHOLD, threshold)?;
        let category_thresholds = optional_f64_map(fields, FIELD_CATEGORY_THRESHOLDS)?;
        for (category, threshold) in &category_thresholds {
            validate_threshold(
                &format!("{FIELD_CATEGORY_THRESHOLDS}.{category}"),
                *threshold,
            )?;
        }
        Ok(Self {
            provider,
            endpoint,
            api_key,
            timeout_ms: optional_u64_field(fields, FIELD_TIMEOUT_MS).unwrap_or(10_000),
            threshold,
            category_thresholds,
            extra_headers: optional_string_map(fields, FIELD_HEADERS)?,
            provider_config: fields
                .get(FIELD_PROVIDER_CONFIG)
                .cloned()
                .unwrap_or(JsonValue::Null),
        })
    }
}

fn optional_u64_field(fields: &BTreeMap<String, JsonValue>, name: &str) -> Option<u64> {
    fields.get(name).and_then(JsonValue::as_u64)
}

fn optional_f64_field(fields: &BTreeMap<String, JsonValue>, name: &str) -> Option<f64> {
    fields.get(name).and_then(JsonValue::as_f64)
}

fn validate_threshold(name: &str, threshold: f64) -> Result<(), String> {
    if (0.0..=1.0).contains(&threshold) {
        Ok(())
    } else {
        Err(format!("field '{name}' must be between 0 and 1"))
    }
}

fn optional_f64_map(
    fields: &BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<BTreeMap<String, f64>, String> {
    let Some(value) = fields.get(name) else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| format!("field '{name}' must be an object"))?;
    object
        .iter()
        .map(|(key, value)| {
            value
                .as_f64()
                .map(|number| (key.clone(), number))
                .ok_or_else(|| format!("field '{name}.{key}' must be a number"))
        })
        .collect()
}

fn optional_string_map(
    fields: &BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<BTreeMap<String, String>, String> {
    let Some(value) = fields.get(name) else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| format!("field '{name}' must be an object"))?;
    object
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|text| (key.clone(), text.to_string()))
                .ok_or_else(|| format!("field '{name}.{key}' must be a string"))
        })
        .collect()
}

pub fn fold_score_verdict(
    cfg: &ResolvedClassifierConfig,
    category_scores: &BTreeMap<String, f64>,
) -> ClassifierVerdict {
    let mut flagged = false;
    let mut top_label = None;
    let mut top_score = 0.0;
    let mut threshold = cfg.threshold;
    let mut reasons = Vec::new();

    if cfg.category_thresholds.is_empty() {
        for (category, score) in category_scores {
            if *score > top_score {
                top_score = *score;
                top_label = Some(category.clone());
            }
        }
        flagged = top_score >= cfg.threshold;
    } else {
        for (category, category_threshold) in &cfg.category_thresholds {
            let Some(score) = category_scores.get(category) else {
                continue;
            };
            if *score >= *category_threshold {
                flagged = true;
                reasons.push(format!("{category} {score:.3} >= {category_threshold:.3}"));
            }
            if *score > top_score {
                top_score = *score;
                top_label = Some(category.clone());
                threshold = *category_threshold;
            }
        }
    }

    ClassifierVerdict {
        flagged,
        score: top_score,
        threshold,
        label: top_label,
        reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
        category_scores: category_scores.clone(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransportRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: JsonValue,
    pub timeout_ms: u64,
}

impl TransportRequest {
    pub fn post(url: impl Into<String>) -> Self {
        Self {
            method: "POST",
            url: url.into(),
            headers: BTreeMap::new(),
            body: JsonValue::Null,
            timeout_ms: 10_000,
        }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.insert(name.to_string(), value.into());
        self
    }

    pub fn json(mut self, body: JsonValue) -> Self {
        self.body = body;
        self
    }

    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportResponse {
    pub status: u16,
    pub body: String,
}

pub trait HttpTransport: Send + Sync {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UreqHttpTransport;

impl HttpTransport for UreqHttpTransport {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, String> {
        http::send_transport_request(request)
    }
}

#[derive(Debug, Default)]
pub struct StubHttpTransport {
    inner: Mutex<StubInner>,
}

#[derive(Debug, Default)]
struct StubInner {
    responses: Vec<Result<TransportResponse, String>>,
    requests: Vec<TransportRequest>,
}

impl StubHttpTransport {
    pub fn with_response(status: u16, body: impl Into<String>) -> Self {
        Self::with_responses([Ok(TransportResponse {
            status,
            body: body.into(),
        })])
    }

    pub fn with_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<TransportResponse, String>>,
    {
        Self {
            inner: Mutex::new(StubInner {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
            }),
        }
    }

    pub fn last_request(&self) -> Option<TransportRequest> {
        self.inner.lock().ok()?.requests.last().cloned()
    }

    pub fn requests(&self) -> Vec<TransportRequest> {
        self.inner
            .lock()
            .map(|inner| inner.requests.clone())
            .unwrap_or_default()
    }
}

impl HttpTransport for StubHttpTransport {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "stub transport lock poisoned".to_string())?;
        inner.requests.push(request);
        if inner.responses.is_empty() {
            return Err("stub transport response queue exhausted".to_string());
        }
        inner.responses.remove(0)
    }
}

pub fn classify(
    cfg: &ResolvedClassifierConfig,
    _subject: &str,
    _transport: &dyn HttpTransport,
) -> Result<ClassifierVerdict, String> {
    match cfg.provider.as_str() {
        #[cfg(feature = "aacs")]
        "aacs" => AacsProvider.classify(cfg, _subject, _transport),
        #[cfg(feature = "openai_moderation")]
        "openai_moderation" => OpenAiModerationProvider.classify(cfg, _subject, _transport),
        #[cfg(feature = "perspective")]
        "perspective" => PerspectiveProvider.classify(cfg, _subject, _transport),
        #[cfg(feature = "llama_guard")]
        "llama_guard" => LlamaGuardProvider.classify(cfg, _subject, _transport),
        #[cfg(feature = "lakera_guard")]
        "lakera_guard" => LakeraGuardProvider.classify(cfg, _subject, _transport),
        #[cfg(feature = "auto")]
        "auto" => AutoProvider.classify(cfg, _subject, _transport),
        provider => Err(format!("unsupported classifier provider '{provider}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(thresholds: &[(&str, f64)], global: f64) -> ResolvedClassifierConfig {
        ResolvedClassifierConfig {
            provider: "test".to_string(),
            endpoint: "https://example.test".to_string(),
            api_key: None,
            timeout_ms: 1000,
            threshold: global,
            category_thresholds: thresholds
                .iter()
                .map(|(key, value)| ((*key).to_string(), *value))
                .collect(),
            extra_headers: BTreeMap::new(),
            provider_config: JsonValue::Null,
        }
    }

    #[test]
    fn global_threshold_blocks_on_max_score() {
        let mut scores = BTreeMap::new();
        scores.insert("Hate".to_string(), 0.7);
        let verdict = fold_score_verdict(&cfg(&[], 0.5), &scores);
        assert!(verdict.is_failure());
    }

    #[test]
    fn category_thresholds_ignore_unlisted_scores() {
        let mut scores = BTreeMap::new();
        scores.insert("Hate".to_string(), 1.0);
        scores.insert("Sexual".to_string(), 0.1);
        let verdict = fold_score_verdict(&cfg(&[("Sexual", 0.5)], 0.5), &scores);
        assert!(!verdict.is_failure());
    }

    #[test]
    fn all_zero_scores_carry_no_label() {
        let mut scores = BTreeMap::new();
        scores.insert("Hate".to_string(), 0.0);
        scores.insert("Sexual".to_string(), 0.0);
        scores.insert("Violence".to_string(), 0.0);
        let verdict = fold_score_verdict(&cfg(&[], 0.5), &scores);
        assert!(!verdict.is_failure());
        assert_eq!(verdict.label, None);
        assert_eq!(verdict.score, 0.0);
    }

    #[test]
    fn top_label_is_the_highest_scoring_category() {
        let mut scores = BTreeMap::new();
        scores.insert("Hate".to_string(), 0.2);
        scores.insert("Sexual".to_string(), 0.0);
        scores.insert("Violence".to_string(), 0.9);
        let verdict = fold_score_verdict(&cfg(&[], 0.5), &scores);
        assert!(verdict.is_failure());
        assert_eq!(verdict.label.as_deref(), Some("Violence"));
        assert_eq!(verdict.score, 0.9);
    }
}
