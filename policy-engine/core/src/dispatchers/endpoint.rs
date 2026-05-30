use crate::dispatchers::{constants::*, http, resolve};
use crate::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue, RuntimeError};

#[derive(Debug, Default, Clone, Copy)]
pub struct EndpointAnnotator;

impl EndpointAnnotator {
    pub fn new() -> Self {
        Self
    }
}

impl AnnotatorDispatcher for EndpointAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        if annotator.field(ANNOTATOR_TYPE).and_then(JsonValue::as_str) != Some(TYPE_ENDPOINT) {
            return Err(resolve::failed(
                annotator_name,
                "endpoint dispatcher received a non-endpoint annotator",
            ));
        }
        let url = http::required_string_field(annotator_name, &annotator.fields, FIELD_URL)?;
        let policy_target =
            resolve::policy_target_text(annotator_name, annotator, preliminary_policy_input)?;
        http::post_json(
            annotator_name,
            url,
            http::endpoint_payload(policy_target, &annotator.fields),
            None,
        )
    }
}
