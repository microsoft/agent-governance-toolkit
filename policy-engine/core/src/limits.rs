use crate::{policy_input::canonical_json, JsonValue, RuntimeError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_snapshot_bytes: usize,
    pub max_policy_input_depth: usize,
    pub max_annotators_per_point: usize,
    pub max_annotator_output_bytes: usize,
    pub max_policy_output_bytes: usize,
    pub max_extends_depth: usize,
    pub max_merged_manifest_bytes: usize,
    pub max_manifest_url_bytes: usize,
    pub manifest_url_timeout_ms: u64,
    pub max_manifest_url_redirects: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_snapshot_bytes: 1_048_576,
            max_policy_input_depth: 64,
            max_annotators_per_point: 16,
            max_annotator_output_bytes: 262_144,
            max_policy_output_bytes: 262_144,
            max_extends_depth: 16,
            max_merged_manifest_bytes: 1_048_576,
            max_manifest_url_bytes: 1_048_576,
            manifest_url_timeout_ms: 30_000,
            max_manifest_url_redirects: 5,
        }
    }
}

impl Limits {
    pub fn validate_json_depth(self, value: &JsonValue, context: &str) -> Result<(), RuntimeError> {
        validate_json_depth(value, 0, self.max_policy_input_depth, context)
    }

    pub fn validate_snapshot(self, snapshot: &JsonValue) -> Result<(), RuntimeError> {
        self.validate_json_depth(snapshot, "snapshot")?;
        let bytes = canonical_json(snapshot).map_err(|err| {
            RuntimeError::ResourceLimitExceeded(format!(
                "failed to serialize snapshot for resource limit check: {err}"
            ))
        })?;
        if bytes.len() > self.max_snapshot_bytes {
            return Err(RuntimeError::ResourceLimitExceeded(format!(
                "snapshot serialized size {} exceeds limit {}",
                bytes.len(),
                self.max_snapshot_bytes
            )));
        }
        Ok(())
    }

    pub fn validate_policy_input(self, policy_input: &JsonValue) -> Result<(), RuntimeError> {
        self.validate_json_depth(policy_input, "policy input")
    }

    pub fn validate_policy_output(self, policy_output: &JsonValue) -> Result<(), RuntimeError> {
        self.validate_json_depth(policy_output, "policy output")?;
        let bytes = canonical_json(policy_output).map_err(|err| {
            RuntimeError::ResourceLimitExceeded(format!(
                "failed to serialize policy output for resource limit check: {err}"
            ))
        })?;
        if bytes.len() > self.max_policy_output_bytes {
            return Err(RuntimeError::ResourceLimitExceeded(format!(
                "policy output serialized size {} exceeds limit {}",
                bytes.len(),
                self.max_policy_output_bytes
            )));
        }
        Ok(())
    }

    pub fn validate_annotator_output(
        self,
        annotator_name: &str,
        output: &JsonValue,
    ) -> Result<(), RuntimeError> {
        self.validate_json_depth(output, "annotator output")
            .map_err(|err| RuntimeError::AnnotationFailed(format!("{annotator_name}: {err}")))?;
        reject_reserved_reason(output)
            .map_err(|err| RuntimeError::AnnotationFailed(format!("{annotator_name}: {err}")))?;
        let bytes = canonical_json(output).map_err(|err| {
            RuntimeError::AnnotationFailed(format!(
                "{annotator_name}: failed to serialize annotator output: {err}"
            ))
        })?;
        if bytes.len() > self.max_annotator_output_bytes {
            return Err(RuntimeError::AnnotationFailed(format!(
                "{annotator_name}: annotator output serialized size {} exceeds limit {}",
                bytes.len(),
                self.max_annotator_output_bytes
            )));
        }
        Ok(())
    }
}

fn validate_json_depth(
    value: &JsonValue,
    depth: usize,
    max_depth: usize,
    context: &str,
) -> Result<(), RuntimeError> {
    match value {
        JsonValue::Array(items) => {
            let next_depth = depth + 1;
            if next_depth > max_depth {
                return Err(RuntimeError::ResourceLimitExceeded(format!(
                    "{context} JSON nesting depth exceeds limit {max_depth}"
                )));
            }
            for item in items {
                validate_json_depth(item, next_depth, max_depth, context)?;
            }
        }
        JsonValue::Object(map) => {
            let next_depth = depth + 1;
            if next_depth > max_depth {
                return Err(RuntimeError::ResourceLimitExceeded(format!(
                    "{context} JSON nesting depth exceeds limit {max_depth}"
                )));
            }
            for item in map.values() {
                validate_json_depth(item, next_depth, max_depth, context)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_reserved_reason(value: &JsonValue) -> Result<(), String> {
    match value {
        JsonValue::Array(items) => {
            for item in items {
                reject_reserved_reason(item)?;
            }
        }
        JsonValue::Object(map) => {
            if let Some(JsonValue::String(reason)) = map.get("reason") {
                if reason.starts_with("runtime_error:") {
                    return Err(
                        "annotator output reason must not use reserved runtime_error prefix"
                            .to_string(),
                    );
                }
            }
            for item in map.values() {
                reject_reserved_reason(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}
