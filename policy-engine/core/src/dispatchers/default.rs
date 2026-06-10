use super::constants::{ANNOTATOR_TYPE, TYPE_CLASSIFIER, TYPE_ENDPOINT, TYPE_LLM};
use super::{resolve, ClassifierAnnotator, EndpointAnnotator, LlmAnnotator};
use crate::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue, RuntimeError};

/// Zero-config annotator dispatcher that routes an annotator invocation to the
/// matching bundled reference dispatcher based on its declared `type`. Backs the
/// FFI builder default so a host can run a manifest whose annotators carry their
/// own endpoint configuration without wiring a dispatcher by hand.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAnnotatorDispatcher;

impl DefaultAnnotatorDispatcher {
    pub fn new() -> Self {
        Self
    }
}

impl AnnotatorDispatcher for DefaultAnnotatorDispatcher {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        match annotator.field(ANNOTATOR_TYPE).and_then(JsonValue::as_str) {
            Some(TYPE_CLASSIFIER) => {
                ClassifierAnnotator.dispatch(annotator_name, annotator, preliminary_policy_input)
            }
            Some(TYPE_LLM) => {
                LlmAnnotator.dispatch(annotator_name, annotator, preliminary_policy_input)
            }
            Some(TYPE_ENDPOINT) => {
                EndpointAnnotator.dispatch(annotator_name, annotator, preliminary_policy_input)
            }
            Some(other) => Err(resolve::failed(
                annotator_name,
                format!("default annotator dispatcher does not support type '{other}'"),
            )),
            None => Err(resolve::failed(
                annotator_name,
                "annotator is missing a 'type' field",
            )),
        }
    }
}
