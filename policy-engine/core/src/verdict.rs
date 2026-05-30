use crate::{effects::Effect, JsonValue, RuntimeError};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Warn,
    Escalate,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Warn => "warn",
            Self::Escalate => "escalate",
        }
    }

    pub fn applies_effects(self) -> bool {
        matches!(self, Self::Allow | Self::Warn | Self::Escalate)
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Decision {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "warn" => Ok(Self::Warn),
            "escalate" => Ok(Self::Escalate),
            other => Err(format!("unsupported decision '{other}'")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<Effect>,
    /// Policy-supplied information-flow labels describing the data produced at
    /// this sink. The core stores nothing and propagates nothing; it returns
    /// these verbatim so the host can persist them with the produced data and
    /// supply them as `snapshot.ifc.source_labels` on subsequent evaluations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_labels: Vec<String>,
}

impl Verdict {
    pub fn runtime_error(error: &RuntimeError) -> Self {
        let message = match error {
            RuntimeError::AnnotationFailed(detail) if !detail.is_empty() => {
                format!("Request blocked by Agent Control Specification. {detail}")
            }
            _ => "Request blocked by Agent Control Specification.".to_string(),
        };
        Self {
            decision: Decision::Deny,
            reason: Some(error.reason().to_string()),
            message: Some(message),
            effects: Vec::new(),
            result_labels: Vec::new(),
        }
    }
}

pub fn normalize_policy_output(output: JsonValue) -> Result<Verdict, RuntimeError> {
    let object = output.as_object().ok_or_else(|| {
        RuntimeError::PolicyOutputInvalid("policy output must be an object".to_string())
    })?;

    let decision = object
        .get("decision")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid("policy output decision is required".to_string())
        })?
        .parse::<Decision>()
        .map_err(RuntimeError::PolicyOutputInvalid)?;

    let reason = match object.get("reason") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::String(reason)) => {
            if reason.starts_with("runtime_error:") {
                return Err(RuntimeError::PolicyOutputInvalid(
                    "policy reasons must not use reserved runtime_error:* prefix".to_string(),
                ));
            }
            Some(reason.clone())
        }
        _ => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "policy output reason must be a string".to_string(),
            ))
        }
    };

    let message = match object.get("message") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::String(message)) => Some(message.clone()),
        _ => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "policy output message must be a string".to_string(),
            ))
        }
    };

    let effects = match object.get("effects") {
        None | Some(JsonValue::Null) => Vec::new(),
        Some(JsonValue::Array(items)) => items
            .iter()
            .map(Effect::from_value)
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "policy output effects must be an array".to_string(),
            ))
        }
    };

    let result_labels = match object.get("result_labels") {
        None | Some(JsonValue::Null) => Vec::new(),
        Some(JsonValue::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_string).ok_or_else(|| {
                    RuntimeError::PolicyOutputInvalid(
                        "policy output result_labels must be an array of strings".to_string(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "policy output result_labels must be an array".to_string(),
            ))
        }
    };

    Ok(Verdict {
        decision,
        reason,
        message,
        effects,
        result_labels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn result_labels_default_to_empty_and_are_omitted_when_serialized() {
        let verdict = normalize_policy_output(json!({"decision": "allow"})).unwrap();
        assert!(verdict.result_labels.is_empty());
        let serialized = serde_json::to_value(&verdict).unwrap();
        assert!(serialized.get("result_labels").is_none());
    }

    #[test]
    fn result_labels_round_trip_when_policy_supplies_them() {
        let verdict = normalize_policy_output(json!({
            "decision": "allow",
            "result_labels": ["internal", "confidential"]
        }))
        .unwrap();
        assert_eq!(verdict.result_labels, vec!["internal", "confidential"]);
        let serialized = serde_json::to_value(&verdict).unwrap();
        assert_eq!(
            serialized["result_labels"],
            json!(["internal", "confidential"])
        );
    }

    #[test]
    fn null_result_labels_normalize_to_empty() {
        let verdict =
            normalize_policy_output(json!({"decision": "allow", "result_labels": null})).unwrap();
        assert!(verdict.result_labels.is_empty());
    }

    #[test]
    fn non_array_result_labels_fail_closed() {
        let error =
            normalize_policy_output(json!({"decision": "allow", "result_labels": "secret"}))
                .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn non_string_result_label_entries_fail_closed() {
        let error =
            normalize_policy_output(json!({"decision": "allow", "result_labels": ["ok", 7]}))
                .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }
}
