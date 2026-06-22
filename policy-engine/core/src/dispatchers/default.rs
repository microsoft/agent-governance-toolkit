use super::constants::{ANNOTATOR_TYPE, TYPE_CLASSIFIER, TYPE_ENDPOINT, TYPE_LLM};
use super::{resolve, ClassifierAnnotator, EndpointAnnotator, LlmAnnotator};
use crate::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue, Limits, RuntimeError};

/// Zero-config annotator dispatcher that routes an annotator invocation to the
/// matching bundled reference dispatcher based on its declared `type`. Backs the
/// host builders so a manifest whose annotators carry their own endpoint
/// configuration runs without a hand wired dispatcher. Carries the host
/// effective `Limits` for dispatch time fetches and the manifest `url_sourced`
/// provenance, so a bundled `llm` annotator on an untrusted URL sourced manifest
/// never falls back to a host environment credential. Construct it only through
/// [`crate::dispatchers::default_annotator_dispatcher_for`], which derives both
/// values from the manifest. There is deliberately no provenance free
/// constructor, so a caller cannot accidentally build a dispatcher that reads
/// host credentials for a URL sourced manifest.
#[derive(Debug, Clone, Copy)]
pub struct DefaultAnnotatorDispatcher {
    limits: Limits,
    url_sourced: bool,
}

impl DefaultAnnotatorDispatcher {
    /// Build a dispatcher bound to the host effective `limits` and to the
    /// manifest `url_sourced` provenance. When `url_sourced` is true the bundled
    /// `llm` annotator never reads a host environment credential, including a
    /// provider default credential variable, so an untrusted remote manifest
    /// cannot exfiltrate a host secret to an endpoint it also controls.
    pub fn with_limits_and_source(limits: Limits, url_sourced: bool) -> Self {
        Self {
            limits,
            url_sourced,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_url_sourced(&self) -> bool {
        self.url_sourced
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
            Some(TYPE_LLM) => LlmAnnotator::new()
                .with_limits(self.limits)
                .with_url_sourced(self.url_sourced)
                .dispatch(annotator_name, annotator, preliminary_policy_input),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_stores_url_sourced_provenance() {
        // Regression: the host factory derives this from the manifest, so the
        // constructor must store it faithfully. A dropped provenance would let a
        // URL sourced manifest read host credentials at dispatch.
        assert!(
            DefaultAnnotatorDispatcher::with_limits_and_source(Limits::default(), true)
                .is_url_sourced()
        );
        assert!(
            !DefaultAnnotatorDispatcher::with_limits_and_source(Limits::default(), false)
                .is_url_sourced()
        );
    }
}
