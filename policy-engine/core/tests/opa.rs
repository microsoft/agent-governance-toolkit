#![cfg(feature = "opa")]

use agent_control_specification_core::{
    canonical_json, AnnotatorDispatcher, AnnotatorInvocation, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Manifest, OpaPolicyDispatcher, OpaRegoRunner,
    PolicyDispatcher, PreparedPolicyInvocation, RegoPolicyInvocation, Runtime, RuntimeError,
    TestPolicyInvocation,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());

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
fn opa_dispatcher_times_out_pathological_eval() {
    let Some(runner) = require_opa_or_skip() else {
        return;
    };
    let dispatcher =
        OpaPolicyDispatcher::with_runner(runner.with_eval_timeout(Duration::from_millis(50)));
    let invocation = rego_invocation(
        "x := numbers.range(1, 100000000)",
        None,
        BTreeMap::new(),
        json!({"policy_target": {"value": {"text": "hello"}}}),
    );

    let started = Instant::now();
    let error = dispatcher.evaluate(&invocation).unwrap_err();

    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error.detail().contains("OPA eval exceeded timeout"),
        "{}",
        error.detail()
    );
}

#[test]
fn opa_default_timeout_allows_nontrivial_policy_input() {
    let Some(runner) = require_opa_or_skip() else {
        return;
    };
    let dir = test_artifact_dir("opa-default-timeout-nontrivial");
    let policy_path = dir.join("nontrivial.rego");
    fs::write(
        &policy_path,
        r#"package agent_control_specification.heavy

import rego.v1

matching_numbers := [n | some n in input.policy_target.value.numbers; n % 3 == 0]

verdict := {"decision": "allow", "matched": count(matching_numbers)} if {
    count(matching_numbers) >= 1000
}
"#,
    )
    .unwrap();
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert(
        "data_paths".to_string(),
        json!([policy_path.display().to_string()]),
    );
    let input = json!({"policy_target": {"value": {"numbers": (1..=5000).collect::<Vec<_>>()}}});

    let started = Instant::now();
    let output = OpaPolicyDispatcher::with_runner(runner)
        .evaluate(&rego_invocation(
            "data.agent_control_specification.heavy.verdict",
            None,
            adapter_config,
            input,
        ))
        .unwrap();

    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(output["decision"], json!("allow"));
    assert_eq!(output["matched"], json!(1666));
}

#[test]
fn opa_timeout_env_override_tiny_times_out_and_large_allows_completion() {
    let Some(runner) = require_opa_or_skip() else {
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap();
    let old_path = env::var_os("ACS_OPA_PATH");
    let old_timeout = env::var_os("ACS_OPA_TIMEOUT_MS");
    env::set_var("ACS_OPA_PATH", runner.executable());
    env::set_var("ACS_OPA_TIMEOUT_MS", "1");
    let tiny_runner = OpaRegoRunner::from_environment();
    assert_eq!(tiny_runner.eval_timeout(), Duration::from_millis(1));
    let slow = rego_invocation(
        "x := numbers.range(1, 100000000)",
        None,
        BTreeMap::new(),
        json!({"policy_target": {"value": {"text": "hello"}}}),
    );
    let tiny_error = OpaPolicyDispatcher::with_runner(tiny_runner)
        .evaluate(&slow)
        .unwrap_err();
    assert_eq!(
        tiny_error.reason(),
        "runtime_error:policy_invocation_failed"
    );
    assert!(tiny_error.detail().contains("OPA eval exceeded timeout"));

    env::set_var("ACS_OPA_TIMEOUT_MS", "5000");
    let large_runner = OpaRegoRunner::from_environment();
    assert_eq!(large_runner.eval_timeout(), Duration::from_secs(5));
    let output = OpaPolicyDispatcher::with_runner(large_runner)
        .evaluate(&rego_invocation(
            "count(numbers.range(1, 5000))",
            None,
            BTreeMap::new(),
            json!({"policy_target": {"value": {"text": "hello"}}}),
        ))
        .unwrap();
    assert_eq!(output, json!(5000));
    restore_env("ACS_OPA_PATH", old_path);
    restore_env("ACS_OPA_TIMEOUT_MS", old_timeout);
}

#[cfg(unix)]
#[test]
fn opa_timeout_kills_child_process_without_lingering() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = test_artifact_dir("opa-timeout-kills-child");
    let pid_file = dir.join("fake-opa.pid");
    let fake_opa = dir.join("opa");
    fs::write(
        &fake_opa,
        r#"#!/bin/sh
echo $$ > "$ACS_FAKE_OPA_PID_FILE"
exec sleep 30
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_opa).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_opa, permissions).unwrap();
    let old_pid_file = env::var_os("ACS_FAKE_OPA_PID_FILE");
    env::set_var("ACS_FAKE_OPA_PID_FILE", &pid_file);

    let dispatcher = OpaPolicyDispatcher::with_runner(
        OpaRegoRunner::new()
            .with_executable(&fake_opa)
            .with_eval_timeout(Duration::from_millis(30)),
    );
    let error = dispatcher
        .evaluate(&rego_invocation(
            "data.agent_control_specification.input.verdict",
            None,
            BTreeMap::new(),
            json!({"policy_target": {"value": {"text": "hello"}}}),
        ))
        .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(error.detail().contains("OPA eval exceeded timeout"));
    let pid = fs::read_to_string(&pid_file).unwrap().trim().to_string();
    assert!(
        !Path::new("/proc").join(pid).exists(),
        "timed-out fake OPA child process should be gone"
    );
    restore_env("ACS_FAKE_OPA_PID_FILE", old_pid_file);
}

#[test]
fn runtime_can_use_opa_policy_dispatcher_for_rego_policy() {
    let Some(runner) = require_opa_or_skip() else {
        return;
    };
    let manifest = Manifest::from_yaml_str(&format!(
        r#"agent_control_specification_version: 0.3.1-beta
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

fn test_artifact_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("opa-tests")
        .join(format!("{name}-{}-{unique}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}

fn restore_env(key: &str, value: Option<std::ffi::OsString>) {
    match value {
        Some(value) => env::set_var(key, value),
        None => env::remove_var(key),
    }
}

fn yaml_double_quoted(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
