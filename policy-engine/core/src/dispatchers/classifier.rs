use crate::dispatchers::{
    bundled::{self, HttpTransport, ResolvedClassifierConfig, UreqHttpTransport},
    constants::*,
    http, resolve,
};
use crate::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue, RuntimeError};
use serde_json::json;

#[derive(Debug, Default, Clone, Copy)]
pub struct ClassifierAnnotator;

impl ClassifierAnnotator {
    pub fn new() -> Self {
        Self
    }

    pub fn dispatch_with_transport(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
        transport: &dyn HttpTransport,
    ) -> Result<JsonValue, RuntimeError> {
        if annotator.field(ANNOTATOR_TYPE).and_then(JsonValue::as_str) != Some(TYPE_CLASSIFIER) {
            return Err(resolve::failed(
                annotator_name,
                "classifier dispatcher received a non-classifier annotator",
            ));
        }
        let policy_target =
            resolve::policy_target_text(annotator_name, annotator, preliminary_policy_input)?;
        if http::optional_string_field(&annotator.fields, FIELD_PROVIDER).is_none() {
            return Err(resolve::failed(
                annotator_name,
                "custom transport requires a bundled classifier provider",
            ));
        }
        dispatch_bundled_with_transport(annotator_name, annotator, &policy_target, transport)
    }
}

impl AnnotatorDispatcher for ClassifierAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        if annotator.field(ANNOTATOR_TYPE).and_then(JsonValue::as_str) != Some(TYPE_CLASSIFIER) {
            return Err(resolve::failed(
                annotator_name,
                "classifier dispatcher received a non-classifier annotator",
            ));
        }
        let policy_target =
            resolve::policy_target_text(annotator_name, annotator, preliminary_policy_input)?;
        if http::optional_string_field(&annotator.fields, FIELD_PROVIDER).is_some() {
            return dispatch_bundled_with_transport(
                annotator_name,
                annotator,
                &policy_target,
                &UreqHttpTransport,
            );
        }
        dispatch_generic(annotator_name, annotator, policy_target)
    }
}

fn dispatch_generic(
    annotator_name: &str,
    annotator: &AnnotatorInvocation,
    policy_target: String,
) -> Result<JsonValue, RuntimeError> {
    let url = http::required_string_field(annotator_name, &annotator.fields, FIELD_URL)?;
    let input_field = http::optional_string_field(&annotator.fields, FIELD_INPUT_FIELD)
        .unwrap_or(DEFAULT_INPUT_FIELD);
    let api_key = http::env_api_key(annotator_name, &annotator.fields)?;
    let timeout_ms = http::timeout_ms(annotator_name, &annotator.fields)?;
    let response = http::post_json(
        annotator_name,
        url,
        json!({ input_field: policy_target }),
        api_key,
        timeout_ms,
    )?;
    match http::optional_string_field(&annotator.fields, FIELD_RESPONSE_FIELD) {
        Some(field) => response.get(field).cloned().ok_or_else(|| {
            resolve::failed(annotator_name, format!("response missing field '{field}'"))
        }),
        None => Ok(response),
    }
}

fn dispatch_bundled_with_transport(
    annotator_name: &str,
    annotator: &AnnotatorInvocation,
    policy_target: &str,
    transport: &dyn HttpTransport,
) -> Result<JsonValue, RuntimeError> {
    let cfg = ResolvedClassifierConfig::from_fields(&annotator.fields)
        .map_err(|error| resolve::failed(annotator_name, error))?;
    bundled::classify(&cfg, policy_target, transport)
        .map(|verdict| verdict.to_json())
        .map_err(|error| resolve::failed(annotator_name, error))
}

#[cfg(all(test, feature = "aacs"))]
mod tests {
    use super::*;
    use crate::dispatchers::bundled::StubHttpTransport;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn provider_field_routes_to_bundled_classifier() {
        std::env::set_var("ACS_AACS_TEST_KEY", "test-key");
        let annotator = AnnotatorInvocation {
            fields: BTreeMap::from([
                (ANNOTATOR_TYPE.to_string(), json!(TYPE_CLASSIFIER)),
                (FIELD_PROVIDER.to_string(), json!("aacs")),
                (FIELD_ENDPOINT.to_string(), json!("https://example.test")),
                (FIELD_API_KEY_ENV.to_string(), json!("ACS_AACS_TEST_KEY")),
            ]),
        };
        let transport = StubHttpTransport::with_response(
            200,
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":0},{"category":"SelfHarm","severity":0},{"category":"Sexual","severity":0},{"category":"Violence","severity":0}]}"#,
        );

        let output = dispatch_bundled_with_transport("classifier", &annotator, "hello", &transport)
            .expect("provider succeeds");

        assert_eq!(output["verdict"], json!("allow"));
        assert_eq!(output["flagged"], json!(false));
    }
}
