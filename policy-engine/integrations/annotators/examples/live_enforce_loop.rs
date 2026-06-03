// Full live enforcement loop. A real Azure Content Safety classifier annotation
// drives a real OPA-evaluated Rego decision through the runtime. Benign input is
// allowed and violent input is blocked, proving the annotator to policy to enforce
// path end to end against a live service rather than a stub.

use agent_control_specification::{
    AgentControl, AgentControlInterruption, EnforcementMode, InterventionPoint,
    InterventionPointRequest, InterventionPointResult, JsonValue, Manifest, OpaRegoRunner,
    PolicyDispatcher, PreparedPolicyInvocation, Runtime, RuntimeError,
};
use agent_control_specification_annotators::ClassifierAnnotator;
use serde_json::json;
use std::{fs, path::PathBuf, sync::Arc};

struct OpaPolicy {
    runner: OpaRegoRunner,
}

impl PolicyDispatcher for OpaPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let PreparedPolicyInvocation::Rego(rego) = invocation else {
            return Err(RuntimeError::PolicyInvocationFailed(
                "live loop only supports Rego policies".to_string(),
            ));
        };
        self.runner.evaluate(rego)
    }
}

fn opa_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/bin/opa")
}

fn evaluate(control: &AgentControl, snapshot: JsonValue) -> InterventionPointResult {
    control
        .runtime()
        .evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Input,
            snapshot,
            mode: EnforcementMode::Enforce,
        })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(endpoint) = std::env::var("AZURE_CONTENT_SAFETY_ENDPOINT") else {
        eprintln!("skipping live loop because AZURE_CONTENT_SAFETY_ENDPOINT is not set");
        return Ok(());
    };
    if std::env::var("AZURE_CONTENT_SAFETY_KEY").is_err() {
        eprintln!("skipping live loop because AZURE_CONTENT_SAFETY_KEY is not set");
        return Ok(());
    }

    let opa = OpaRegoRunner::new().with_executable(opa_path());
    if !opa.is_available() {
        return Err(format!("OPA not available at {}", opa.executable().display()).into());
    }

    let bundle_dir = std::env::temp_dir().join("acs_live_loop_policy");
    fs::create_dir_all(&bundle_dir)?;
    fs::write(
        bundle_dir.join("policy.rego"),
        r#"package agent_control_specification.live_loop

import rego.v1

default input_verdict := {"decision": "allow"}

input_verdict := {
    "decision": "deny",
    "reason": "content_safety_flagged",
    "message": "Azure Content Safety flagged the input as harmful."
} if {
    input.annotations.content_safety.flagged == true
}
"#,
    )?;

    let manifest_yaml = format!(
        r#"agent_control_specification_version: "0.3.1-beta"
metadata:
  name: "live-content-safety-loop"
policies:
  live_loop:
    type: rego
    bundle: {bundle}
    query: data.agent_control_specification.live_loop.input_verdict
annotators:
  content_safety:
    type: classifier
    provider: aacs
    endpoint: "{endpoint}"
    api_key_env: AZURE_CONTENT_SAFETY_KEY
    threshold: 0.5
    provider_config:
      api_version: "2024-09-01"
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    annotations:
      content_safety:
        from: "$.input.text"
    policy:
      id: live_loop
      query: data.agent_control_specification.live_loop.input_verdict
"#,
        bundle = bundle_dir.display(),
        endpoint = endpoint,
    );

    let manifest = Manifest::from_yaml_str(&manifest_yaml)?;
    let runtime = Runtime::new(
        manifest,
        Arc::new(ClassifierAnnotator::new()),
        Arc::new(OpaPolicy { runner: opa }),
    )?;
    let control = AgentControl::new(runtime);

    println!("ACS live enforcement loop (Azure Content Safety + OPA Rego)\n");

    println!("=== benign input ===");
    let benign = json!({"input": {"text": "Summarize the standup notes."}});
    let benign_result = evaluate(&control, benign.clone());
    println!(
        "  decision => {} reason={}",
        benign_result.verdict.decision,
        benign_result.verdict.reason.as_deref().unwrap_or("ok")
    );
    control.enforce(
        InterventionPoint::Input,
        &benign_result,
        EnforcementMode::Enforce,
        None,
    )?;
    assert_eq!(
        benign_result.verdict.decision.to_string(),
        "allow",
        "benign input must be allowed"
    );

    println!("\n=== harmful input ===");
    let harmful = json!({"input": {"text": "I will find where you live and hurt your family until they bleed."}});
    let harmful_result = evaluate(&control, harmful);
    println!(
        "  decision => {} reason={}",
        harmful_result.verdict.decision,
        harmful_result.verdict.reason.as_deref().unwrap_or("ok")
    );
    match control.enforce(
        InterventionPoint::Input,
        &harmful_result,
        EnforcementMode::Enforce,
        None,
    ) {
        Err(AgentControlInterruption::Blocked(blocked)) => {
            println!("  blocked => {blocked}");
        }
        other => panic!("expected harmful input to be blocked, got {other:?}"),
    }
    assert_eq!(
        harmful_result.verdict.decision.to_string(),
        "deny",
        "harmful input must be denied"
    );

    println!("\nlive loop verification: PASS");
    Ok(())
}
