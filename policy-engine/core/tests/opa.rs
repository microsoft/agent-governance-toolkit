use agent_control_specification_core::{
    canonical_json, AnnotatorDispatcher, AnnotatorInvocation, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Manifest, OpaPolicyDispatcher, OpaRegoRunner,
    PolicyDispatcher, PreparedPolicyInvocation, RegoPolicyInvocation, Runtime, RuntimeError,
    TestPolicyInvocation,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
    sync::Arc,
};

struct NoopAnnotator;

impl AnnotatorDispatcher for NoopAnnotator {
    fn dispatch(
        &self,
        _annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(json!({}))
    }
}

#[test]
fn opa_dispatcher_errors_clearly_when_executable_is_missing() {
    let dispatcher = OpaPolicyDispatcher::with_runner(
        OpaRegoRunner::new().with_executable(fixture_path("missing-opa")),
    );
    let invocation = rego_invocation(
        "data.agent_control_specification.input.verdict",
        None,
        BTreeMap::new(),
        json!({"policy_target": {"value": {"text": "hello"}}}),
    );

    let error = dispatcher.evaluate(&invocation).unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error.detail().contains("OPA executable"),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains("was not found"),
        "{}",
        error.detail()
    );
}

#[test]
fn opa_dispatcher_rejects_non_rego_invocations() {
    let input = json!({"policy_target": {"value": {"text": "hello"}}});
    let invocation = PreparedPolicyInvocation::Test(TestPolicyInvocation {
        adapter_config: BTreeMap::new(),
        canonical_input: canonical_json(&input).unwrap(),
        input,
    });

    let error = OpaPolicyDispatcher::new()
        .evaluate(&invocation)
        .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(error.detail().contains("only supports Rego"));
    assert!(error.detail().contains("test invocation"));
}

#[test]
fn opa_dispatcher_evaluates_rego_query_with_data_paths_from_adapter_config() {
    let Some(runner) = require_opa_or_skip() else {
        return;
    };
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert("data_paths".to_string(), json!([fixture("verdict.rego")]));
    let dispatcher = OpaPolicyDispatcher::with_runner(runner);

    let allow = dispatcher
        .evaluate(&rego_invocation(
            "data.agent_control_specification.input.verdict",
            None,
            adapter_config.clone(),
            json!({"policy_target": {"value": {"text": "hello"}}}),
        ))
        .unwrap();
    let deny = dispatcher
        .evaluate(&rego_invocation(
            "data.agent_control_specification.input.verdict",
            None,
            adapter_config,
            json!({"policy_target": {"value": {"text": "please block this"}}}),
        ))
        .unwrap();

    assert_eq!(allow, json!({"decision": "allow"}));
    assert_eq!(
        deny,
        json!({
            "decision": "deny",
            "reason": "blocked_text",
            "message": "Input contained blocked text."
        })
    );
}

#[test]
fn runtime_can_use_opa_policy_dispatcher_for_rego_policy() {
    let Some(runner) = require_opa_or_skip() else {
        return;
    };
    let manifest = Manifest::from_yaml_str(&format!(
        r#"agent_control_specification_version: 0.3.0-alpha
policies:
  input_rego_policy:
    type: rego
    data_paths:
      - "{}"
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_rego_policy
      query: data.agent_control_specification.input.verdict
    policy_target: $snap.input"#,
        yaml_double_quoted(&fixture_path("verdict.rego"))
    ))
    .unwrap();
    let runtime = Runtime::new(
        manifest,
        Arc::new(NoopAnnotator),
        Arc::new(OpaPolicyDispatcher::with_runner(runner)),
    )
    .unwrap();

    let allow = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": {"text": "hello"}}),
        mode: EnforcementMode::Enforce,
    });
    let deny = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": {"text": "please block this"}}),
        mode: EnforcementMode::Enforce,
    });

    assert_eq!(allow.verdict.decision.as_str(), "allow");
    assert_eq!(deny.verdict.decision.as_str(), "deny");
    assert_eq!(deny.verdict.reason.as_deref(), Some("blocked_text"));
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

fn rego_invocation(
    query: &str,
    bundle: Option<String>,
    adapter_config: BTreeMap<String, JsonValue>,
    input: JsonValue,
) -> PreparedPolicyInvocation {
    PreparedPolicyInvocation::Rego(RegoPolicyInvocation {
        query: query.to_string(),
        bundle,
        adapter_config,
        canonical_input: canonical_json(&input).unwrap(),
        input,
    })
}

fn fixture(name: &str) -> String {
    fixture_path(name).display().to_string()
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("opa")
        .join(name)
}

fn yaml_double_quoted(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
