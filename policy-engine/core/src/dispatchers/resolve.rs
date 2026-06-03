use crate::dispatchers::constants::{FIELD_FROM, FIELD_INPUT_FROM, POLICY_INPUT_SNAPSHOT};
use crate::{AnnotatorInvocation, JsonPath, JsonValue, PathEnv, RuntimeError};

pub fn policy_target_text(
    annotator_name: &str,
    annotator: &AnnotatorInvocation,
    preliminary_policy_input: &JsonValue,
) -> Result<String, RuntimeError> {
    let input_from = annotator
        .input_from()
        .or_else(|| annotator.field(FIELD_FROM).and_then(JsonValue::as_str))
        .or_else(|| {
            annotator
                .field(FIELD_INPUT_FROM)
                .and_then(JsonValue::as_str)
        })
        .ok_or_else(|| failed(annotator_name, "missing from path"))?;
    let path = JsonPath::parse_with_snapshot_alias(input_from)
        .map_err(|error| failed(annotator_name, format!("invalid from path: {error}")))?;
    let env = preliminary_policy_input
        .get(POLICY_INPUT_SNAPSHOT)
        .map_or_else(
            || PathEnv::with_pi(preliminary_policy_input),
            |snapshot| PathEnv::with_pi_and_snap(preliminary_policy_input, snapshot),
        );
    let value = path
        .resolve(&env)
        .map_err(|error| failed(annotator_name, format!("from path failed: {error}")))?;
    value
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| failed(annotator_name, "from path did not resolve to a string"))
}

pub fn failed(annotator_name: &str, detail: impl Into<String>) -> RuntimeError {
    RuntimeError::AnnotationFailed(format!("{annotator_name}: {}", detail.into()))
}
