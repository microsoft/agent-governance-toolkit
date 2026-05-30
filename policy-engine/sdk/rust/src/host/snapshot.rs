use super::{
    AgentControlBlocked, AgentControlInterruption, AgentControlSuspended, ApprovalOutcome,
    ApprovalResolver,
};
use crate::{
    action_identity, Decision, EnforcementMode, InterventionPoint, InterventionPointResult,
    JsonValue, RuntimeError, Verdict,
};
use serde_json::Map;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub(super) fn enforce(
    intervention_point: InterventionPoint,
    intervention_point_result: &InterventionPointResult,
    mode: EnforcementMode,
    resolver: Option<&ApprovalResolver>,
) -> Result<(), AgentControlInterruption> {
    if mode != EnforcementMode::Enforce {
        return Ok(());
    }
    match intervention_point_result.verdict.decision {
        Decision::Allow | Decision::Warn => Ok(()),
        Decision::Deny => Err(blocked(intervention_point, intervention_point_result)),
        Decision::Escalate => {
            let Some(resolver) = resolver else {
                return Err(blocked(intervention_point, intervention_point_result));
            };
            let original_identity = intervention_point_result.action_identity.clone();
            let resolution = match catch_unwind(AssertUnwindSafe(|| {
                resolver(intervention_point, intervention_point_result)
            })) {
                Ok(resolution) => resolution,
                Err(_) => {
                    let error_result = approval_resolver_failed_result();
                    return Err(blocked(intervention_point, &error_result));
                }
            };
            let current_identity = current_action_identity(intervention_point_result);
            match resolution.outcome {
                ApprovalOutcome::Allow => {
                    if approved_identity_matches(
                        original_identity.as_deref(),
                        current_identity.as_deref(),
                        resolution.action_identity.as_deref(),
                    ) {
                        Ok(())
                    } else {
                        let error_result = approval_action_mismatch_result();
                        Err(blocked(intervention_point, &error_result))
                    }
                }
                ApprovalOutcome::Deny => {
                    Err(blocked(intervention_point, intervention_point_result))
                }
                ApprovalOutcome::Suspend => {
                    if approved_identity_matches(
                        original_identity.as_deref(),
                        current_identity.as_deref(),
                        resolution.action_identity.as_deref(),
                    ) {
                        Err(AgentControlInterruption::Suspended(
                            AgentControlSuspended::new(
                                intervention_point,
                                intervention_point_result.clone(),
                                resolution.handle,
                            ),
                        ))
                    } else {
                        let error_result = approval_action_mismatch_result();
                        Err(blocked(intervention_point, &error_result))
                    }
                }
            }
        }
    }
}

fn current_action_identity(intervention_point_result: &InterventionPointResult) -> Option<String> {
    intervention_point_result
        .policy_input
        .as_ref()
        .and_then(|policy_input| action_identity(policy_input).ok())
}

fn approved_identity_matches(
    original_identity: Option<&str>,
    current_identity: Option<&str>,
    approved_identity: Option<&str>,
) -> bool {
    original_identity.is_some()
        && current_identity.is_some()
        && approved_identity.is_some()
        && original_identity == current_identity
        && current_identity == approved_identity
}

fn approval_action_mismatch_result() -> InterventionPointResult {
    let error = RuntimeError::ApprovalActionMismatch(
        "approved action identity did not match the current action identity".to_string(),
    );
    InterventionPointResult {
        verdict: Verdict::runtime_error(&error),
        transformed_policy_target: None,
        policy_input: None,
        action_identity: None,
    }
}

fn approval_resolver_failed_result() -> InterventionPointResult {
    InterventionPointResult {
        verdict: Verdict {
            decision: Decision::Deny,
            reason: Some("runtime_error:approval_resolver_failed".to_string()),
            message: Some("Approval resolver failed closed.".to_string()),
            effects: Vec::new(),
            result_labels: Vec::new(),
        },
        transformed_policy_target: None,
        policy_input: None,
        action_identity: None,
    }
}

fn blocked(
    intervention_point: InterventionPoint,
    intervention_point_result: &InterventionPointResult,
) -> AgentControlInterruption {
    AgentControlInterruption::Blocked(AgentControlBlocked::new(
        intervention_point,
        intervention_point_result.clone(),
    ))
}

pub(super) fn effective_policy_target(
    raw: JsonValue,
    intervention_point_result: &InterventionPointResult,
    mode: EnforcementMode,
) -> JsonValue {
    if mode == EnforcementMode::Enforce
        && intervention_point_result.verdict.decision.applies_effects()
    {
        intervention_point_result
            .transformed_policy_target
            .clone()
            .unwrap_or(raw)
    } else {
        raw
    }
}

pub(super) fn snapshot_with_value(
    ambient: &Map<String, JsonValue>,
    key: &str,
    value: JsonValue,
) -> JsonValue {
    snapshot_with_values(ambient, [(key, value)])
}

pub(super) fn snapshot_with_values<'a>(
    ambient: &Map<String, JsonValue>,
    values: impl IntoIterator<Item = (&'a str, JsonValue)>,
) -> JsonValue {
    let mut snapshot = ambient.clone();
    for (key, value) in values {
        snapshot.insert(key.to_string(), value);
    }
    JsonValue::Object(snapshot)
}

pub(super) fn tool_call_snapshot(
    tool_name: &str,
    args: JsonValue,
    tool_call_id: Option<&str>,
) -> JsonValue {
    let mut tool_call = Map::new();
    tool_call.insert("name".to_string(), JsonValue::String(tool_name.to_string()));
    tool_call.insert("args".to_string(), args);
    if let Some(id) = tool_call_id {
        tool_call.insert("id".to_string(), JsonValue::String(id.to_string()));
    }
    JsonValue::Object(tool_call)
}

pub(super) fn model_call_snapshot(
    ambient: &Map<String, JsonValue>,
    model_request: JsonValue,
    model_response: Option<JsonValue>,
) -> JsonValue {
    let values = [
        ("model_request", Some(model_request)),
        ("model_response", model_response),
    ];
    snapshot_with_values(
        ambient,
        values
            .into_iter()
            .filter_map(|(key, value)| value.map(|value| (key, value))),
    )
}
