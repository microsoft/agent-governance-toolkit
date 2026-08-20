// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host side evaluation result.
//!
//! Under AGENT-HOOKS-0.1 the policy plane returns a verdict and nothing
//! else. Transform application, `evaluate_only` handling, and context
//! identity are host obligations under sections 8 through 10, so the
//! engine no longer reports `transformed_policy_target` or the identity
//! trio. This module is where AGT discharges those obligations and
//! rebuilds the richer result the SDK surfaces to callers.

use agent_control_spec::{
    Decision, EnforcementMode, EvaluationResult, InterceptionPoint, JsonValue, Limits,
};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Evaluation outcome enriched with the values the host computes.
#[derive(Debug, Clone, PartialEq)]
pub struct HostEvaluation {
    /// The agent-hooks verdict the host must honour.
    pub verdict: agent_control_spec::Verdict,
    /// The final policy input the dispatcher evaluated.
    pub policy_input: Option<JsonValue>,
    /// Policy target after the host applied a `transform` verdict. `None`
    /// in `EvaluateOnly` mode and for every non transform decision.
    pub transformed_policy_target: Option<JsonValue>,
    /// Backwards compatible alias for `enforced_identity`.
    pub action_identity: Option<String>,
    /// SHA-256 of the canonical policy input as the policy saw it.
    pub input_identity: Option<String>,
    /// SHA-256 of the canonical policy input with the transform applied.
    /// Equal to `input_identity` for non transform decisions and for
    /// evaluate only transforms.
    pub enforced_identity: Option<String>,
}

impl HostEvaluation {
    /// Discharge the host obligations over a raw engine result.
    /// Errors carry an `agent_hooks::HostError` rather than a
    /// `RuntimeError`. Every failure reachable here is the host rejecting an
    /// interceptor verdict, which the contract puts in the `host_error:*`
    /// namespace; the engine's own failures already arrived as fail-closed
    /// deny verdicts inside `result`. Relabelling these as `runtime_error:*`
    /// attributed host work to the engine.
    pub fn from_engine(
        point: InterceptionPoint,
        result: EvaluationResult,
        mode: EnforcementMode,
    ) -> Result<Self, (agent_hooks::HostError, String)> {
        Self::from_engine_with_limits(point, result, mode, Limits::default())
    }

    /// As [`from_engine`](Self::from_engine), but revalidates the transformed
    /// policy target against `limits`.
    ///
    /// The engine checks the snapshot it was given, before the transform
    /// existed. Applying one is host work, so a transform that grows the
    /// target past `max_snapshot_bytes` would otherwise leave the host
    /// carrying a value the engine would have refused.
    pub fn from_engine_with_limits(
        point: InterceptionPoint,
        result: EvaluationResult,
        mode: EnforcementMode,
        limits: Limits,
    ) -> Result<Self, (agent_hooks::HostError, String)> {
        let EvaluationResult {
            verdict,
            policy_input,
        } = result;

        let input_identity = policy_input.as_ref().and_then(|input| identity(input).ok());

        // AGENT-HOOKS-0.1 section 8. A transform is not permitted at
        // every point, and one arriving where it is forbidden must fail
        // closed rather than being silently permitted.
        if verdict.decision == Decision::Transform && !point.transform_permitted() {
            return Err((
                agent_hooks::HostError::TransformTargetForbidden,
                format!("a transform is not permitted at interception point {point}"),
            ));
        }

        // Applied only under enforcement, but validated in both modes.
        // Withholding validation in evaluate-only is the promotion
        // hazard that mode exists to catch: a policy whose transform
        // cannot resolve would look clean in shadow and fail closed on
        // the first enforced request.
        let transformed_policy_target = match verdict.decision {
            Decision::Transform => {
                let transform = verdict.transform.as_ref().ok_or_else(|| {
                    (
                        agent_hooks::HostError::TransformInvalid,
                        "transform decision missing transform body after normalization".to_string(),
                    )
                })?;
                let target = policy_input
                    .as_ref()
                    .and_then(|input| input.get("policy_target"))
                    .and_then(|slot| slot.get("value"))
                    .cloned()
                    .unwrap_or(JsonValue::Null);
                let applied = agent_hooks::apply_transform_path(
                    target,
                    &transform.path,
                    transform.value.clone(),
                )
                .map_err(|error| match error {
                    agent_hooks::HostError::TransformTargetForbidden => (
                        error,
                        format!(
                            "transform path '{}' is outside the policy target",
                            transform.path
                        ),
                    ),
                    other => (
                        agent_hooks::HostError::TransformInvalid,
                        format!(
                            "transform at '{}' is not applicable: {other:?}",
                            transform.path
                        ),
                    ),
                })?;
                if mode == EnforcementMode::Enforce {
                    limits.validate_snapshot(&applied).map_err(|error| {
                        (
                            agent_hooks::HostError::TransformInvalid,
                            format!("transform result exceeds the configured limits: {error}"),
                        )
                    })?;
                    Some(applied)
                } else {
                    None
                }
            }
            _ => None,
        };

        let enforced_identity = match (&transformed_policy_target, &policy_input) {
            (Some(transformed), Some(input)) => {
                identity(&with_transformed_target(input, transformed)).ok()
            }
            _ => input_identity.clone(),
        };

        Ok(Self {
            verdict,
            policy_input,
            transformed_policy_target,
            action_identity: enforced_identity.clone(),
            input_identity,
            enforced_identity,
        })
    }
}

/// Rebuild a policy input with the transformed policy target substituted.
pub fn with_transformed_target(input: &JsonValue, transformed: &JsonValue) -> JsonValue {
    let mut enforced = input.clone();
    if let Some(slot) = enforced
        .get_mut("policy_target")
        .and_then(JsonValue::as_object_mut)
        .and_then(|object| object.get_mut("value"))
    {
        *slot = transformed.clone();
    }
    enforced
}

/// SHA-256 over the canonical JSON encoding, prefixed `sha256:`.
pub fn identity(value: &JsonValue) -> Result<String, serde_json::Error> {
    let canonical = agent_control_spec::canonical_json(value)?;
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256:");
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn engine_result(
        decision: Decision,
        transform: Option<agent_control_spec::Transform>,
    ) -> EvaluationResult {
        EvaluationResult {
            verdict: agent_control_spec::Verdict {
                decision,
                reason: None,
                message: None,
                warnings: Vec::new(),
                approval: None,
                transform,
                evidence: None,
                result_labels: Vec::new(),
            },
            policy_input: Some(json!({"policy_target": {"value": {"text": "secret"}}})),
        }
    }

    #[test]
    fn allow_leaves_identities_equal() {
        let host = HostEvaluation::from_engine(
            InterceptionPoint::Input,
            engine_result(Decision::Allow, None),
            EnforcementMode::Enforce,
        )
        .unwrap();
        assert!(host.transformed_policy_target.is_none());
        assert_eq!(host.input_identity, host.enforced_identity);
        assert_eq!(host.action_identity, host.enforced_identity);
    }

    #[test]
    fn enforced_transform_applies_and_shifts_identity() {
        let transform = agent_control_spec::Transform {
            path: "$target.text".to_string(),
            value: json!("[REDACTED]"),
        };
        let host = HostEvaluation::from_engine(
            InterceptionPoint::Input,
            engine_result(Decision::Transform, Some(transform)),
            EnforcementMode::Enforce,
        )
        .unwrap();
        assert_eq!(
            host.transformed_policy_target,
            Some(json!({"text": "[REDACTED]"}))
        );
        assert_ne!(host.input_identity, host.enforced_identity);
    }

    #[test]
    fn evaluate_only_does_not_apply_the_transform() {
        let transform = agent_control_spec::Transform {
            path: "$target.text".to_string(),
            value: json!("[REDACTED]"),
        };
        let host = HostEvaluation::from_engine(
            InterceptionPoint::Input,
            engine_result(Decision::Transform, Some(transform)),
            EnforcementMode::EvaluateOnly,
        )
        .unwrap();
        assert!(host.transformed_policy_target.is_none());
        assert_eq!(host.input_identity, host.enforced_identity);
    }

    #[test]
    fn a_transform_at_a_lifecycle_point_fails_closed() {
        // AGENT-HOOKS-0.1 section 8 forbids a transform at agent_startup
        // and agent_shutdown. Permitting one silently would let a policy
        // mutate a payload the contract says is not transformable.
        let transform = agent_control_spec::Transform {
            path: "$target.text".to_string(),
            value: json!("[REDACTED]"),
        };
        for point in [
            InterceptionPoint::AgentStartup,
            InterceptionPoint::AgentShutdown,
        ] {
            let err = HostEvaluation::from_engine(
                point,
                engine_result(Decision::Transform, Some(transform.clone())),
                EnforcementMode::Enforce,
            )
            .unwrap_err();
            assert_eq!(err.0.to_string(), "host_error:transform_target_forbidden");
        }
    }

    #[test]
    fn evaluate_only_validates_the_transform_it_does_not_apply() {
        // The point of shadow mode is to surface a policy that would
        // fail closed under enforcement. A transform that cannot resolve
        // must be reported in both modes, applied in neither.
        let bad = agent_control_spec::Transform {
            path: "$snap.somewhere_else".to_string(),
            value: json!("x"),
        };
        for mode in [EnforcementMode::Enforce, EnforcementMode::EvaluateOnly] {
            let err = HostEvaluation::from_engine(
                InterceptionPoint::Input,
                engine_result(Decision::Transform, Some(bad.clone())),
                mode,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err.0,
                    agent_hooks::HostError::TransformInvalid
                        | agent_hooks::HostError::TransformTargetForbidden
                ),
                "{mode:?} gave {}",
                err.0
            );
        }
    }

    #[test]
    fn a_transform_past_the_snapshot_limit_fails_closed() {
        // The engine validated the pre-transform snapshot. Applying the
        // transform is host work, so growing the target past the budget has
        // to be caught here or not at all.
        let big = "x".repeat(4096);
        let transform = agent_hooks::Transform {
            path: "$target.text".to_string(),
            value: json!(big),
        };
        let limits = Limits {
            max_snapshot_bytes: 256,
            ..Limits::default()
        };
        let err = HostEvaluation::from_engine_with_limits(
            InterceptionPoint::Output,
            engine_result(Decision::Transform, Some(transform.clone())),
            EnforcementMode::Enforce,
            limits,
        )
        .unwrap_err();
        assert!(matches!(err.0, agent_hooks::HostError::TransformInvalid));

        // The same transform under the default budget is fine, so the
        // rejection is the limit and not the transform.
        HostEvaluation::from_engine_with_limits(
            InterceptionPoint::Output,
            engine_result(Decision::Transform, Some(transform)),
            EnforcementMode::Enforce,
            Limits::default(),
        )
        .expect("default limits admit it");
    }

    #[test]
    fn legacy_policy_target_root_still_resolves() {
        // agent-hooks path::parse accepts `$policy_target` as a deprecated
        // alias for `$target` on transform paths. Note this alias exists
        // only for transform paths; the ACS manifest grammar rejects the
        // old root outright.
        let transform = agent_control_spec::Transform {
            path: "$policy_target.text".to_string(),
            value: json!("[REDACTED]"),
        };
        let host = HostEvaluation::from_engine(
            InterceptionPoint::Input,
            engine_result(Decision::Transform, Some(transform)),
            EnforcementMode::Enforce,
        )
        .unwrap();
        assert_eq!(
            host.transformed_policy_target,
            Some(json!({"text": "[REDACTED]"}))
        );
    }
}
