use crate::{paths::PathRoot, JsonPath, JsonValue, RuntimeError};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Verdict decision. The four values `Allow`, `Deny`, `Warn`, and `Escalate`
/// match upstream ACS §13.1. The fifth value `Transform` is the AGT addition
/// per `policy-engine/spec/SPECIFICATION.md` §13.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Warn,
    Escalate,
    Transform,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Warn => "warn",
            Self::Escalate => "escalate",
            Self::Transform => "transform",
        }
    }

    /// Whether this decision permits the action to proceed (after any
    /// applicable transform). Per AGT D1, effects no longer exist on the
    /// verdict; the only value-changing decision is `Transform`.
    pub fn permits(self) -> bool {
        matches!(self, Self::Allow | Self::Warn | Self::Transform)
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
            "transform" => Ok(Self::Transform),
            other => Err(format!("unsupported decision '{other}'")),
        }
    }
}

/// Single-target replacement returned by a `Transform` verdict per
/// `policy-engine/spec/SPECIFICATION.md` §14.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Transform {
    /// Path rooted at `$policy_target`.
    pub path: String,
    /// New value to set at `path`.
    pub value: JsonValue,
}

impl Transform {
    pub fn from_value(value: &JsonValue) -> Result<Self, RuntimeError> {
        let object = value.as_object().ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid("transform must be an object".to_string())
        })?;
        let path = object
            .get("path")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                RuntimeError::PolicyOutputInvalid(
                    "transform.path is required when decision is transform".to_string(),
                )
            })?;
        let parsed = JsonPath::parse(path).map_err(|err| {
            RuntimeError::PolicyOutputInvalid(format!("transform.path invalid: {err}"))
        })?;
        if parsed.root() != PathRoot::PolicyTarget {
            return Err(RuntimeError::TransformTargetForbidden(path.to_string()));
        }
        let value = object.get("value").cloned().ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid(
                "transform.value is required when decision is transform".to_string(),
            )
        })?;
        Ok(Self {
            path: path.to_string(),
            value,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// AGT D1.1 single-target replacement payload. Present only when
    /// `decision` is `Transform`. Forbidden on every other decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<Transform>,
    /// AGT D2 opaque evidence object that high-assurance dispatchers MAY
    /// attach to the verdict. The runtime propagates the value verbatim and
    /// performs no semantic validation on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
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
            transform: None,
            evidence: None,
            result_labels: Vec::new(),
        }
    }
}

/// AGT D2 evidence payload that high-assurance dispatchers MAY attach to a
/// verdict. The runtime stores the payload verbatim and propagates it to
/// telemetry events per AGT-EVIDENCE-1.0.
///
/// Total serialized size is bounded; oversized payloads MUST be rejected by
/// the dispatcher boundary before reaching the verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Content address or URI of an offline-verifiable proof artefact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artefact: Option<String>,
    /// Named pointers an auditor MAY consult to re-verify the decision.
    #[serde(
        default,
        rename = "verification_pointers",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub verification_pointers: std::collections::BTreeMap<String, String>,
}

impl Evidence {
    /// AGT-EVIDENCE-1.0 §2: total serialized evidence MUST NOT exceed
    /// 4 KiB. A dispatcher that produces a larger payload is treated as
    /// having failed.
    pub const MAX_SERIALIZED_BYTES: usize = 4 * 1024;

    pub fn from_value(value: &JsonValue) -> Result<Self, RuntimeError> {
        let object = value.as_object().ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid("evidence must be an object".to_string())
        })?;

        // Bound the serialized size BEFORE we look at the fields, so that
        // a dispatcher cannot ship a 1 MiB pointer URL or a huge artefact
        // string and have it propagate verbatim through telemetry/audit.
        if let Ok(serialized) = serde_json::to_string(value) {
            if serialized.len() > Self::MAX_SERIALIZED_BYTES {
                return Err(RuntimeError::PolicyOutputInvalid(format!(
                    "evidence object exceeds {} bytes when serialized",
                    Self::MAX_SERIALIZED_BYTES
                )));
            }
        }

        let artefact = match object.get("artefact") {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::String(value)) => Some(value.clone()),
            _ => {
                return Err(RuntimeError::PolicyOutputInvalid(
                    "evidence.artefact must be a string".to_string(),
                ))
            }
        };

        let verification_pointers = match object.get("verification_pointers") {
            None | Some(JsonValue::Null) => std::collections::BTreeMap::new(),
            Some(JsonValue::Object(map)) => {
                let mut out = std::collections::BTreeMap::new();
                for (key, value) in map.iter() {
                    let url = value.as_str().ok_or_else(|| {
                        RuntimeError::PolicyOutputInvalid(format!(
                            "evidence.verification_pointers.{key} must be a string"
                        ))
                    })?;
                    out.insert(key.clone(), url.to_string());
                }
                out
            }
            _ => {
                return Err(RuntimeError::PolicyOutputInvalid(
                    "evidence.verification_pointers must be an object of strings".to_string(),
                ))
            }
        };

        Ok(Self {
            artefact,
            verification_pointers,
        })
    }

    /// Sorted list of verification pointer keys, used as low-cardinality
    /// telemetry metadata per AGT-EVIDENCE-1.0 §3.
    pub fn pointer_keys(&self) -> Vec<String> {
        self.verification_pointers.keys().cloned().collect()
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

    // AGT D1: the `effects` array on a verdict MUST be rejected. The
    // earlier "accept empty[] / null for back-compat" carve-out is
    // removed because D1 specifies a strict reject on any presence of
    // the key, not just on non-empty arrays. Dispatchers in the middle
    // of migrating away from upstream ACS effects MUST drop the key
    // entirely; multi-step transformation moves to annotators per D1.3.
    if object.contains_key("effects") {
        return Err(RuntimeError::PolicyOutputInvalid(
            "verdict 'effects' is no longer supported; remove the effects key and \
             use the transform decision per SPECIFICATION.md §14. Migrate \
             multi-step rewriting to an annotator"
                .to_string(),
        ));
    }

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

    let transform = match (decision, object.get("transform")) {
        (Decision::Transform, None | Some(JsonValue::Null)) => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "transform decision requires a transform object".to_string(),
            ))
        }
        (Decision::Transform, Some(value)) => Some(Transform::from_value(value)?),
        (_, Some(JsonValue::Null)) | (_, None) => None,
        (_, Some(_)) => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "transform is only permitted on the transform decision".to_string(),
            ))
        }
    };

    let evidence = match object.get("evidence") {
        None | Some(JsonValue::Null) => None,
        Some(value) => Some(Evidence::from_value(value)?),
    };

    Ok(Verdict {
        decision,
        reason,
        message,
        transform,
        evidence,
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

    // ── AGT D1 effects rejection ──────────────────────────────────────

    #[test]
    fn non_empty_effects_array_fails_closed_per_agt_d1() {
        let error = normalize_policy_output(json!({
            "decision": "allow",
            "effects": [
                {"type": "replace", "path": "$policy_target.body", "value": "x"}
            ]
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
        assert!(
            error.detail().contains("transform decision"),
            "rejection message must point at the AGT D1 transform path: {}",
            error.detail()
        );
    }

    #[test]
    fn empty_effects_array_now_fails_closed_per_strict_agt_d1() {
        // Round-2 review tightened the AGT D1 reading: any presence of
        // the effects key MUST be rejected, including empty arrays and
        // explicit nulls. Dispatchers that historically emitted
        // `effects: []` MUST drop the key.
        let error = normalize_policy_output(json!({
            "decision": "allow",
            "effects": []
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn null_effects_now_fails_closed_per_strict_agt_d1() {
        let error = normalize_policy_output(json!({
            "decision": "allow",
            "effects": null
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn non_array_effects_still_reports_policy_output_invalid() {
        let error = normalize_policy_output(json!({
            "decision": "allow",
            "effects": "not-an-array"
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    // ── AGT D1 transform decision ─────────────────────────────────────

    #[test]
    fn transform_decision_round_trips() {
        let verdict = normalize_policy_output(json!({
            "decision": "transform",
            "transform": {
                "path": "$policy_target.body",
                "value": "[REDACTED]"
            }
        }))
        .unwrap();
        assert_eq!(verdict.decision, Decision::Transform);
        let transform = verdict.transform.as_ref().expect("transform present");
        assert_eq!(transform.path, "$policy_target.body");
        assert_eq!(transform.value, json!("[REDACTED]"));
    }

    #[test]
    fn transform_decision_without_body_fails_closed() {
        let error = normalize_policy_output(json!({"decision": "transform"})).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn transform_path_outside_policy_target_fails_closed() {
        let error = normalize_policy_output(json!({
            "decision": "transform",
            "transform": {"path": "$snap.tool_call.args", "value": "x"}
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:transform_target_forbidden");
    }

    #[test]
    fn transform_on_non_transform_decision_fails_closed() {
        let error = normalize_policy_output(json!({
            "decision": "allow",
            "transform": {"path": "$policy_target.x", "value": 1}
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn transform_value_null_is_accepted() {
        // null is a valid JSON value; transform.value = null sets the target
        // to null, not a missing field. AGT D1.1 says value is required and
        // valid JSON; null is required-and-valid.
        let verdict = normalize_policy_output(json!({
            "decision": "transform",
            "transform": {"path": "$policy_target.field", "value": null}
        }))
        .unwrap();
        assert_eq!(
            verdict.transform.as_ref().unwrap().value,
            serde_json::Value::Null
        );
    }

    // ── AGT D2 evidence ───────────────────────────────────────────────

    #[test]
    fn evidence_round_trips() {
        let verdict = normalize_policy_output(json!({
            "decision": "allow",
            "evidence": {
                "artefact": "sha256:abcd",
                "verification_pointers": {
                    "issuer_pubkey": "https://x/keys",
                    "policy_registry": "https://x/policies/v1/"
                }
            }
        }))
        .unwrap();
        let evidence = verdict.evidence.as_ref().expect("evidence present");
        assert_eq!(evidence.artefact.as_deref(), Some("sha256:abcd"));
        assert_eq!(
            evidence.pointer_keys(),
            vec!["issuer_pubkey", "policy_registry"]
        );
    }

    #[test]
    fn evidence_missing_is_none() {
        let verdict = normalize_policy_output(json!({"decision": "allow"})).unwrap();
        assert!(verdict.evidence.is_none());
    }

    #[test]
    fn evidence_non_object_fails_closed() {
        let error = normalize_policy_output(json!({"decision": "allow", "evidence": "sha256:bad"}))
            .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn evidence_artefact_non_string_fails_closed() {
        let error = normalize_policy_output(json!({
            "decision": "allow",
            "evidence": {"artefact": 42}
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn evidence_pointer_value_must_be_string() {
        let error = normalize_policy_output(json!({
            "decision": "allow",
            "evidence": {
                "verification_pointers": {"issuer_pubkey": 42}
            }
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn evidence_over_4kib_fails_closed() {
        let huge = "x".repeat(5000);
        let error = normalize_policy_output(json!({
            "decision": "allow",
            "evidence": {"artefact": huge}
        }))
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    // ── AGT D1.4 permits() helper ─────────────────────────────────────

    #[test]
    fn decision_permits_correctly() {
        assert!(Decision::Allow.permits());
        assert!(Decision::Warn.permits());
        assert!(Decision::Transform.permits());
        assert!(!Decision::Deny.permits());
        assert!(!Decision::Escalate.permits());
    }

    // ── AGT D6 reserved reasons present in error.rs ───────────────────

    #[test]
    fn agt_reserved_reasons_exist() {
        let reasons = [
            RuntimeError::TransformTargetForbidden(String::new()).reason(),
            RuntimeError::TransformInvalid(String::new()).reason(),
            RuntimeError::ApprovalResolverMissing(String::new()).reason(),
            RuntimeError::ResolutionPathTraversal(String::new()).reason(),
            RuntimeError::ResolutionCycle(String::new()).reason(),
            RuntimeError::ResolutionInvalidGovernance(String::new()).reason(),
            RuntimeError::ResolutionMergeConflict(String::new()).reason(),
        ];
        assert_eq!(
            reasons,
            [
                "runtime_error:transform_target_forbidden",
                "runtime_error:transform_invalid",
                "runtime_error:approval_resolver_missing",
                "runtime_error:resolution_path_traversal",
                "runtime_error:resolution_cycle",
                "runtime_error:resolution_invalid_governance",
                "runtime_error:resolution_merge_conflict"
            ]
        );
    }
}
