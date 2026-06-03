use agent_control_specification::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Manifest, PolicyDispatcher, PreparedPolicyInvocation,
    Runtime, RuntimeError,
};
use serde_json::json;
use std::sync::Arc;

struct MockAnnotator;

impl AnnotatorDispatcher for MockAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        let text = preliminary_policy_input["policy_target"]["value"]["text"]
            .as_str()
            .unwrap_or_default();

        Ok(json!({
            "annotator": annotator_name,
            "contains_account_number": text.contains("1234")
        }))
    }
}

struct MockPolicy;

impl PolicyDispatcher for MockPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let final_policy_input = invocation.policy_input().ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "basic host example expects a policy input based invocation".to_string(),
            )
        })?;
        let contains_account_number = final_policy_input["annotations"]["prompt_classifier"]
            ["contains_account_number"]
            .as_bool()
            .unwrap_or(false);

        if contains_account_number {
            Ok(json!({
                "decision": "transform",
                "reason": "account_number_redacted",
                "message": "Account number was redacted before continuing.",
                "transform": {
                    "path": "$policy_target.text",
                    "value": "Please summarize account [REDACTED]."
                }
            }))
        } else {
            Ok(json!({ "decision": "allow" }))
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
metadata:
  name: basic-host-example
policies:
  input_custom_policy:
    type: custom
    adapter: basic_host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input
    annotations:
      prompt_classifier:
        from: $.input.text
annotators:
  prompt_classifier:
    type: classifier"#,
    )?;

    let runtime = Runtime::new(manifest, Arc::new(MockAnnotator), Arc::new(MockPolicy))?;
    let result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({
            "input": {"text": "Please summarize account 1234."},
            "actor": {"id": "user-123"},
            "transport": {"kind": "api_gateway", "route": "/chat"}
        }),
        mode: EnforcementMode::Enforce,
    });

    println!("decision: {}", result.verdict.decision);
    if let Some(reason) = &result.verdict.reason {
        println!("reason: {reason}");
    }

    let transformed = result
        .transformed_policy_target
        .clone()
        .unwrap_or_else(|| result.policy_input.as_ref().unwrap()["policy_target"]["value"].clone());
    println!("policy_target used by host: {transformed}");

    assert_eq!(result.verdict.decision, Decision::Transform);
    assert_eq!(
        transformed,
        json!({"text": "Please summarize account [REDACTED]."})
    );

    Ok(())
}
