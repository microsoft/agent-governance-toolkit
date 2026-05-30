use crate::dispatchers::{constants::*, http, resolve};
use crate::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue, RuntimeError};
use serde_json::json;

#[derive(Debug, Default, Clone, Copy)]
pub struct LlmAnnotator;

impl LlmAnnotator {
    pub fn new() -> Self {
        Self
    }
}

impl AnnotatorDispatcher for LlmAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        if annotator.field(ANNOTATOR_TYPE).and_then(JsonValue::as_str) != Some(TYPE_LLM) {
            return Err(resolve::failed(
                annotator_name,
                "LLM dispatcher received a non-LLM annotator",
            ));
        }
        let url = http::optional_string_field(&annotator.fields, FIELD_ENDPOINT)
            .or_else(|| http::optional_string_field(&annotator.fields, FIELD_BASE_URL))
            .unwrap_or(DEFAULT_OPENAI_CHAT_COMPLETIONS_URL);
        let model =
            http::optional_string_field(&annotator.fields, FIELD_MODEL).unwrap_or(DEFAULT_MODEL);
        let prompt = http::optional_string_field(&annotator.fields, FIELD_SYSTEM_PROMPT)
            .or_else(|| http::optional_string_field(&annotator.fields, FIELD_PROMPT))
            .unwrap_or(DEFAULT_SYSTEM_PROMPT);
        let policy_target =
            resolve::policy_target_text(annotator_name, annotator, preliminary_policy_input)?;
        let api_key = http::required_env_api_key(annotator_name, &annotator.fields)?;
        let response = http::post_json(
            annotator_name,
            url,
            json!({
                REQUEST_MODEL: model,
                REQUEST_MESSAGES: [
                    { REQUEST_ROLE: ROLE_SYSTEM, REQUEST_CONTENT: prompt },
                    { REQUEST_ROLE: ROLE_USER, REQUEST_CONTENT: policy_target },
                ],
                REQUEST_RESPONSE_FORMAT: { REQUEST_RESPONSE_FORMAT_TYPE: RESPONSE_FORMAT_JSON_OBJECT },
            }),
            Some(api_key),
        )?;
        annotation_from_chat_response(annotator_name, &annotator.fields, response)
    }
}

fn annotation_from_chat_response(
    annotator_name: &str,
    fields: &std::collections::BTreeMap<String, JsonValue>,
    response: JsonValue,
) -> Result<JsonValue, RuntimeError> {
    let raw = response
        .get(RESPONSE_CHOICES)
        .and_then(JsonValue::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get(RESPONSE_MESSAGE))
        .and_then(|message| message.get(RESPONSE_CONTENT))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| resolve::failed(annotator_name, "chat response missing message content"))?;
    let label_field =
        http::optional_string_field(fields, FIELD_LABEL_FIELD).unwrap_or(DEFAULT_LABEL_FIELD);
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
