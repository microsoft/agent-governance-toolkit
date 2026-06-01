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
        // AGT D1: transform permits the action; the runtime has already
        // applied the transform to the policy target before reaching
        // here. The host MUST use `transformed_policy_target` if present.
        Decision::Allow | Decision::Warn | Decision::Transform => Ok(()),
        Decision::Deny => Err(blocked(intervention_point, intervention_point_result)),
        Decision::Escalate => {
            let Some(resolver) = resolver else {
                return Err(blocked(intervention_point, intervention_point_result));
            };
            // AGT D1.4: approval binding pins to `enforced_identity` so
            // the approver consents to the action that will execute, not
            // to the pre-transform proposal. `action_identity` is the
            // backwards-compatible alias the SDK already exposes; the
            // runtime guarantees it equals `enforced_identity`.
            let original_identity = intervention_point_result
                .enforced_identity
                .clone()
                .or_else(|| intervention_point_result.action_identity.clone());
            let resolution = match catch_unwind(AssertUnwindSafe(|| {
                resolver(intervention_point, intervention_point_result)
            })) {
                Ok(resolution) => resolution,
                Err(_) => {
                    let error_result = approval_resolver_failed_result();
                    return Err(blocked(intervention_point, &error_result));
                }
            };
            let current_identity = current_enforced_identity(intervention_point_result);
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

fn current_enforced_identity(
    intervention_point_result: &InterventionPointResult,
) -> Option<String> {
    // AGT D1.4: recompute `enforced_identity` from the live policy input
    // and any transformed policy target so a late-arriving approval is
    // checked against what the host will actually execute. Falls back to
    // the input identity when no transform was emitted.
    let policy_input = intervention_point_result.policy_input.as_ref()?;
    if let Some(transformed) = intervention_point_result.transformed_policy_target.as_ref() {
        let mut enforced_input = policy_input.clone();
        if let Some(value_slot) = enforced_input
            .get_mut("policy_target")
            .and_then(JsonValue::as_object_mut)
            .and_then(|object| object.get_mut("value"))
        {
            *value_slot = transformed.clone();
        }
        action_identity(&enforced_input).ok()
    } else {
        action_identity(policy_input).ok()
    }
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
        input_identity: None,
        enforced_identity: None,
    }
}

fn approval_resolver_failed_result() -> InterventionPointResult {
    InterventionPointResult {
        verdict: Verdict {
            decision: Decision::Deny,
            reason: Some("runtime_error:approval_resolver_failed".to_string()),
            message: Some("Approval resolver failed closed.".to_string()),
            transform: None,
            evidence: None,
            result_labels: Vec::new(),
        },
        transformed_policy_target: None,
        policy_input: None,
        action_identity: None,
        input_identity: None,
        enforced_identity: None,
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
    // AGT D1 retires `applies_effects`; the only value-changing decision
    // is `Transform`. Surface the transformed policy target when present.
    if mode == EnforcementMode::Enforce
        && intervention_point_result.verdict.decision == Decision::Transform
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
        assert!(
            !id.is_empty(),
            "tool_call_id must be a non-empty string when provided"
        );
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
