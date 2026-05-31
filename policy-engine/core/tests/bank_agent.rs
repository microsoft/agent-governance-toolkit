#![cfg(feature = "opa")]

use agent_control_specification_core::{
    canonical_json, AnnotatorDispatcher, AnnotatorInvocation, EnforcementMode, InterventionPoint,
    InterventionPointRequest, InterventionPointResult, JsonValue, Manifest, OpaPolicyDispatcher,
    OpaRegoRunner, Runtime, RuntimeError,
};
use serde_json::json;
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    intervention_point: InterventionPoint,
    fixture_stem: &'static str,
    decision: &'static str,
    reason: Option<&'static str>,
    transform: ExpectedTransform,
}

#[derive(Clone, Copy)]
enum ExpectedTransform {
    None,
    AppendLargeTransferInstruction,
    ReplaceToolAccountId,
    RedactOutputAccountId,
}

const LARGE_TRANSFER_INSTRUCTION: &str =
    "Do not execute high-value transfers without explicit approval.";
const REDACTED_ACCOUNT_ID: &str = "ACCOUNT-REDACTED";

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "agent_startup",
        intervention_point: InterventionPoint::AgentStartup,
        fixture_stem: "agent_startup",
        decision: "allow",
        reason: None,
        transform: ExpectedTransform::None,
    },
    Scenario {
        name: "input",
        intervention_point: InterventionPoint::Input,
        fixture_stem: "input",
        decision: "allow",
        reason: None,
        transform: ExpectedTransform::None,
    },
    Scenario {
        name: "pre_model_call",
        intervention_point: InterventionPoint::PreModelCall,
        fixture_stem: "pre_model_call",
        decision: "transform",
        reason: Some("large_transfer_instruction_added"),
        transform: ExpectedTransform::AppendLargeTransferInstruction,
    },
    Scenario {
        name: "post_model_call",
        intervention_point: InterventionPoint::PostModelCall,
        fixture_stem: "post_model_call",
        decision: "allow",
        reason: None,
        transform: ExpectedTransform::None,
    },
    Scenario {
        name: "pre_tool_call_large_transfer",
        intervention_point: InterventionPoint::PreToolCall,
        fixture_stem: "pre_tool_call",
        decision: "escalate",
        reason: Some("large_wire_transfer_requires_review"),
        transform: ExpectedTransform::None,
    },
    Scenario {
        name: "pre_tool_call_safe",
        intervention_point: InterventionPoint::PreToolCall,
        fixture_stem: "pre_tool_call.safe",
        decision: "allow",
        reason: None,
        transform: ExpectedTransform::None,
    },
    Scenario {
        name: "post_tool_call",
        intervention_point: InterventionPoint::PostToolCall,
        fixture_stem: "post_tool_call",
        decision: "transform",
        reason: Some("tool_result_account_identifier_redacted"),
        transform: ExpectedTransform::ReplaceToolAccountId,
    },
    Scenario {
        name: "output",
        intervention_point: InterventionPoint::Output,
        fixture_stem: "output",
        decision: "transform",
        reason: Some("output_account_identifier_redacted"),
        transform: ExpectedTransform::RedactOutputAccountId,
    },
    Scenario {
        name: "agent_shutdown",
        intervention_point: InterventionPoint::AgentShutdown,
        fixture_stem: "agent_shutdown",
        decision: "warn",
        reason: Some("shutdown_audit_contains_blocked_action"),
        transform: ExpectedTransform::None,
    },
];

struct FixtureAnnotator {
    policy_input: JsonValue,
}

impl FixtureAnnotator {
    fn new(policy_input: JsonValue) -> Self {
        Self { policy_input }
    }
}

impl AnnotatorDispatcher for FixtureAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        let mut expected_preliminary = self.policy_input.clone();
        expected_preliminary["annotations"] = json!({});
        assert_eq!(
            canonical_json(preliminary_policy_input).unwrap(),
            canonical_json(&expected_preliminary).unwrap(),
            "preliminary policy input drifted for {annotator_name}"
        );

        Ok(self.policy_input["annotations"]
            .get(annotator_name)
            .cloned()
            .unwrap_or_else(|| panic!("missing fixture annotation for annotator {annotator_name}")))
    }
}

#[test]
fn bank_agent_committed_assets_evaluate_end_to_end_with_opa() {
    let Some(runner) = require_opa_or_skip() else {
        return;
    };
    let bank_dir = bank_agent_dir();
    let _working_dir = WorkingDir::push(&bank_dir);
    let manifest = Manifest::from_path(bank_dir.join("manifest.yaml")).unwrap();
    assert_eq!(manifest.intervention_points.len(), 8);

    for scenario in SCENARIOS {
        let expected_policy_input = read_policy_input(scenario.fixture_stem);
        let snapshot = read_snapshot(scenario.fixture_stem);
        let runtime = Runtime::new(
            manifest.clone(),
            Arc::new(FixtureAnnotator::new(expected_policy_input.clone())),
            Arc::new(OpaPolicyDispatcher::with_runner(runner.clone())),
        )
        .unwrap();

        let result = runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: scenario.intervention_point,
            snapshot,
            mode: EnforcementMode::Enforce,
        });

        assert_policy_input(scenario, &result, &expected_policy_input);
        assert_result(scenario, &result, &expected_policy_input);
    }
}

fn assert_policy_input(
    scenario: &Scenario,
    result: &InterventionPointResult,
    expected_policy_input: &JsonValue,
) {
    assert_eq!(
        canonical_json(result.policy_input.as_ref().unwrap()).unwrap(),
        canonical_json(expected_policy_input).unwrap(),
        "{} policy input",
        scenario.name
    );
}

fn assert_result(
    scenario: &Scenario,
    result: &InterventionPointResult,
    expected_policy_input: &JsonValue,
) {
    assert_eq!(
        result.verdict.decision.as_str(),
        scenario.decision,
        "{} decision",
        scenario.name
    );
    assert_eq!(
        result.verdict.reason.as_deref(),
        scenario.reason,
        "{} reason",
        scenario.name
    );

    match scenario.transform {
        ExpectedTransform::None => {
            assert!(
                result.verdict.transform.is_none(),
                "{} transform",
                scenario.name
            );
            assert!(
                result.transformed_policy_target.is_none(),
                "{} transformed policy_target",
                scenario.name
            );
        }
        ExpectedTransform::AppendLargeTransferInstruction => {
            let transform = result
                .verdict
                .transform
                .as_ref()
                .unwrap_or_else(|| panic!("{} transform missing", scenario.name));
            assert_eq!(transform.path, "$policy_target.messages");
            let mut expected_messages = expected_policy_input["policy_target"]["value"]["messages"]
                .as_array()
                .unwrap()
                .clone();
            expected_messages.push(json!({
                "role": "system",
                "content": LARGE_TRANSFER_INSTRUCTION
            }));
            assert_eq!(transform.value, JsonValue::Array(expected_messages.clone()));

            let mut transformed = expected_policy_input["policy_target"]["value"].clone();
            transformed["messages"] = JsonValue::Array(expected_messages);
            assert_eq!(
                result.transformed_policy_target.as_ref(),
                Some(&transformed)
            );
        }
        ExpectedTransform::ReplaceToolAccountId => {
            let transform = result
                .verdict
                .transform
                .as_ref()
                .unwrap_or_else(|| panic!("{} transform missing", scenario.name));
            assert_eq!(transform.path, "$policy_target.account_id");
            assert_eq!(transform.value, json!(REDACTED_ACCOUNT_ID));

            let mut transformed = expected_policy_input["policy_target"]["value"].clone();
            transformed["account_id"] = json!(REDACTED_ACCOUNT_ID);
            assert_eq!(
                result.transformed_policy_target.as_ref(),
                Some(&transformed)
            );
        }
        ExpectedTransform::RedactOutputAccountId => {
            let transform = result
                .verdict
                .transform
                .as_ref()
                .unwrap_or_else(|| panic!("{} transform missing", scenario.name));
            assert_eq!(transform.path, "$policy_target.text");
            let original_text = expected_policy_input["policy_target"]["value"]["text"]
                .as_str()
                .unwrap();
            let expected_text = original_text.replace("CHK-00112233", REDACTED_ACCOUNT_ID);
            assert_eq!(transform.value, json!(expected_text));

            let mut transformed = expected_policy_input["policy_target"]["value"].clone();
            transformed["text"] = json!(expected_text);
            assert_eq!(
                result.transformed_policy_target.as_ref(),
                Some(&transformed)
            );
        }
    }
}

fn require_opa_or_skip() -> Option<OpaRegoRunner> {
    let runner = OpaRegoRunner::new();
    if runner.is_available() {
        Some(runner)
    } else if env::var("AGENT_CONTROL_REQUIRE_OPA").as_deref() == Ok("1") {
        panic!("AGENT_CONTROL_REQUIRE_OPA=1 but the 'opa' executable is not available on PATH");
    } else {
        eprintln!("skipping OPA-dependent test; set AGENT_CONTROL_REQUIRE_OPA=1 to fail when OPA is missing");
        None
    }
}

fn read_snapshot(stem: &str) -> JsonValue {
    read_json(
        &bank_agent_dir()
            .join("snapshots")
            .join(format!("{stem}.json")),
    )
}

fn read_policy_input(stem: &str) -> JsonValue {
    read_json(
        &bank_agent_dir()
            .join("policy_input")
            .join(format!("{stem}.canonical.json")),
    )
}

fn read_json(path: &Path) -> JsonValue {
    serde_json::from_str(
        &fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())),
    )
    .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn bank_agent_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("examples")
        .join("bank_agent")
}

struct WorkingDir {
    previous: PathBuf,
}

impl WorkingDir {
    fn push(path: &Path) -> Self {
        let previous = env::current_dir().unwrap();
        env::set_current_dir(path)
            .unwrap_or_else(|err| panic!("failed to enter {}: {err}", path.display()));
        Self { previous }
    }
}

impl Drop for WorkingDir {
    fn drop(&mut self) {
        env::set_current_dir(&self.previous)
            .unwrap_or_else(|err| panic!("failed to restore {}: {err}", self.previous.display()));
    }
}
