use agent_control_specification::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode, InterventionPoint,
    JsonValue, Manifest, PolicyDispatcher, PreparedPolicyInvocation, Runtime, RuntimeError,
};
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::PathBuf, str::FromStr, sync::Arc};

struct FixtureAnnotator {
    behavior: Option<String>,
}

impl AnnotatorDispatcher for FixtureAnnotator {
    fn dispatch(
        &self,
        _annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        match self.behavior.as_deref() {
            Some("error") => Err(RuntimeError::AnnotationFailed("fixture".to_string())),
            Some("timeout") => Err(RuntimeError::AnnotationTimeout("fixture".to_string())),
            _ => Ok(serde_json::json!({"ok": true})),
        }
    }
}

struct FixturePolicy {
    behavior: Option<String>,
    response: Value,
}

impl PolicyDispatcher for FixturePolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match self.behavior.as_deref() {
            Some("error") => Err(RuntimeError::PolicyInvocationFailed("fixture".to_string())),
            _ => Ok(self.response.clone()),
        }
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/conformance/fail_closed_error_parity.json")
}

fn extract_reason(error: &RuntimeError) -> &str {
    error.reason()
}

#[test]
fn sdk_fail_closed_errors_match_shared_fixture() {
    let fixture: Value =
        serde_json::from_str(&fs::read_to_string(fixture_path()).unwrap()).unwrap();
    let reasons: BTreeSet<_> = fixture["reserved_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reason| reason.as_str().unwrap())
        .collect();
    let cases = fixture["cases"].as_array().unwrap();
    let covered_reasons: BTreeSet<_> = cases
        .iter()
        .map(|case| case["expected_reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons.len(), 12);
    assert_eq!(covered_reasons, reasons);

    for case in cases {
        let id = case["id"].as_str().unwrap();
        let expected_reason = case["expected_reason"].as_str().unwrap();
        let manifest_yaml = case["manifest_yaml"].as_str().unwrap();
        let response = case
            .get("policy_response")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"decision": "allow"}));
        let policy = Arc::new(FixturePolicy {
            behavior: case
                .get("policy_behavior")
                .and_then(Value::as_str)
                .map(str::to_string),
            response,
        });
        let annotator = Arc::new(FixtureAnnotator {
            behavior: case
                .get("annotator_behavior")
                .and_then(Value::as_str)
                .map(str::to_string),
        });

        let runtime = Manifest::from_yaml_str(manifest_yaml)
            .and_then(|manifest| Runtime::new(manifest, annotator, policy));

        if case["operation"].as_str().unwrap() == "build" {
            let error = match runtime {
                Ok(_) => panic!("{id}: build fixture should fail closed"),
                Err(error) => error,
            };
            assert_eq!(extract_reason(&error), expected_reason, "{id}");
            continue;
        }

        let runtime = runtime.unwrap_or_else(|error| panic!("{id}: build failed: {error}"));
        let intervention_point =
            InterventionPoint::from_str(case["intervention_point"].as_str().unwrap()).unwrap();
        let result = runtime.evaluate_intervention_point(
            agent_control_specification::InterventionPointRequest {
                intervention_point,
                snapshot: case["snapshot"].clone(),
                mode: EnforcementMode::Enforce,
            },
        );
        assert_eq!(result.verdict.decision, Decision::Deny, "{id}");
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some(expected_reason),
            "{id}"
        );
    }
}
