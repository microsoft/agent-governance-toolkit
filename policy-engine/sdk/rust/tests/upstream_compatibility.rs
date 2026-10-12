// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use agent_control_specification::{
    default_host_annotator_dispatcher, AgentControl, Decision, EnforcementMode, InterceptionPoint,
    Manifest, Runtime, TelemetryEvent, TelemetryEventType,
};
use agent_control_specification_core::{
    manifest_yaml::SUPPORTED_MANIFEST_VERSIONS, validate_manifest_yaml, TelemetryEventExt,
};
use serde_json::json;
use std::{env, process::Command};

const MANIFEST: &str = r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  rule:
    type: rego
    query: '{"decision": "allow"}'
intervention_points:
  input:
    policy_target: $.input
    policy:
      id: rule
"#;

#[test]
#[cfg(all(feature = "bundled-dispatchers", feature = "opa"))]
fn ffi_enforces_url_fetch_limits_on_bundled_dispatchers() {
    use agent_control_specification::ffi;
    use std::ffi::{CStr, CString};

    let bundle = MANIFEST.replace(
        "    type: rego",
        &format!(
            "    type: rego\n    bundle_url:\n      url: https://bundles.example/policy.tar.gz\n      sha256: {}",
            "a".repeat(64)
        ),
    );
    let prompt = format!(
        "{MANIFEST}annotators:\n  judge:\n    type: llm\n    provider: openai\n    api_key: test-key\n\
         \x20   system_prompt_url:\n      url: https://prompts.example/prompt.txt\n      sha256: {}\n",
        "a".repeat(64)
    )
    .replace("    policy:\n", "    annotations:\n      judge:\n        from: $target\n    policy:\n");
    for (source, expected_reason) in [
        (bundle, "runtime_error:policy_invocation_failed"),
        (prompt, "runtime_error:annotation_failed"),
    ] {
        let manifest = CString::new(source).unwrap();
        let request = CString::new(
            json!({"intervention_point":"input","snapshot":{"input":"hello"}}).to_string(),
        )
        .unwrap();
        let mut error = std::ptr::null_mut();
        unsafe {
            let builder = ffi::acs_builder_from_yaml(manifest.as_ptr(), &mut error);
            assert!(!builder.is_null());
            assert!(error.is_null(), "builder construction failed");

            assert_eq!(
                ffi::acs_builder_set_url_fetch_limits(builder, 4096, 0, 0, &mut error),
                0
            );
            assert!(error.is_null());
            assert_eq!(
                ffi::acs_builder_enable_default_annotator_dispatcher(builder, &mut error),
                0
            );
            assert_eq!(
                ffi::acs_builder_enable_default_policy_dispatcher(builder, &mut error),
                0
            );
            let runtime = ffi::acs_builder_build(builder, &mut error);
            assert!(!runtime.is_null());
            let output = ffi::acs_runtime_evaluate(runtime, request.as_ptr(), &mut error);
            assert!(!output.is_null());
            let result: serde_json::Value =
                serde_json::from_slice(CStr::from_ptr(output).to_bytes()).unwrap();
            ffi::acs_free_string(output);
            ffi::acs_runtime_free(runtime);
            assert_eq!(result["verdict"]["decision"], "deny");
            assert_eq!(result["verdict"]["reason"], expected_reason);
        }
    }
}

#[test]
fn engine_release_and_manifest_grammar_have_distinct_versions() {
    const LEGACY_ARRAY: [&str; 1] = SUPPORTED_MANIFEST_VERSIONS;
    assert_eq!(LEGACY_ARRAY, ["0.4.0-alpha.1"]);
    for version in agent_control_spec::SUPPORTED_VERSIONS {
        validate_manifest_yaml(&MANIFEST.replace("0.4.0-alpha.1", version)).unwrap();
    }
    assert!(validate_manifest_yaml(&MANIFEST.replace("0.4.0-alpha.1", "0.4.0-alpha.4")).is_err());
}

#[test]
fn host_policy_dispatcher_honors_download_timeout() {
    let source = MANIFEST.replace(
        "    type: rego",
        &format!(
            "    type: rego\n    bundle_url:\n      url: https://bundles.example/policy.tar.gz\n      sha256: {}",
            "a".repeat(64)
        ),
    );
    let control = AgentControl::from_manifest_with_dispatchers_and_limits(
        Manifest::from_yaml_str(&source).unwrap(),
        None,
        None,
        agent_control_specification::Limits {
            manifest_url_timeout_ms: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let result = control.evaluate_intervention_point(
        InterceptionPoint::Input,
        json!({"input":"hello"}),
        EnforcementMode::Enforce,
    );
    assert_eq!(result.verdict.decision, Decision::Deny);
    let invocation = agent_control_specification::PreparedPolicyInvocation::Rego(
        agent_control_specification::RegoPolicyInvocation {
            query: "data.policy.verdict".into(),
            bundle: None,
            inline_bundle: None,
            adapter_config: std::collections::BTreeMap::from([(
                "bundle_url".into(),
                json!({"url":"https://bundles.example/policy.tar.gz","sha256":"a".repeat(64)}),
            )]),
            input: json!({}),
            canonical_input: "{}".into(),
        },
    );
    let error = control
        .runtime()
        .policy_dispatcher()
        .evaluate(&invocation)
        .unwrap_err();
    assert!(error.detail().contains("timeout of 0 ms"), "{error}");
}

#[test]
fn newer_manifest_orders_dependencies_and_preserves_url_provenance() {
    use agent_control_specification::{
        AnnotatorDispatcher, AnnotatorInvocation, JsonValue, PolicyDispatcher,
        PreparedPolicyInvocation, RuntimeError,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Annotations(Mutex<Vec<(String, bool)>>);
    impl AnnotatorDispatcher for Annotations {
        fn dispatch(
            &self,
            name: &str,
            invocation: &AnnotatorInvocation,
            input: &JsonValue,
        ) -> Result<JsonValue, RuntimeError> {
            self.0
                .lock()
                .unwrap()
                .push((name.into(), invocation.url_sourced));
            if name == "a_second" {
                assert_eq!(input["annotations"]["z_first"], json!({"label":"safe"}));
            }
            Ok(json!({"label":"safe"}))
        }
    }
    struct Policy;
    impl PolicyDispatcher for Policy {
        fn evaluate(
            &self,
            invocation: &PreparedPolicyInvocation,
        ) -> Result<JsonValue, RuntimeError> {
            let input = invocation.policy_input().unwrap();
            assert_eq!(input["annotations"]["a_second"]["label"], "safe");
            Ok(json!({"decision":"allow"}))
        }
    }

    let source = r#"agent_control_specification_version: 0.5.0-alpha.1
policies:
  rule: {type: test}
annotators:
  z_first: {type: classifier}
  a_second: {type: classifier}
intervention_points:
  input:
    policy_target: $.input
    policy: {id: rule}
    annotations:
      z_first: {from: $target}
      a_second:
        from: $pi.annotations.z_first
        needs: [z_first]
"#;
    validate_manifest_yaml(source).unwrap();
    let marked = Manifest::parse_yaml_str(source)
        .unwrap()
        .mark_url_sourced()
        .unwrap();
    let overlay = Manifest::parse_yaml_str(
        "agent_control_specification_version: 0.5.0-alpha.1\nmetadata: {name: host}",
    )
    .unwrap();
    let merged = Manifest::merge_chain(vec![marked, overlay]).unwrap();
    let annotations = Arc::new(Annotations::default());
    let control = AgentControl::from_manifest_with_dispatchers(
        merged,
        Some(annotations.clone()),
        Some(Arc::new(Policy)),
    )
    .unwrap();
    assert!(control.runtime().manifest().url_sourced());
    let result = control.evaluate_intervention_point(
        InterceptionPoint::Input,
        json!({"input":"hello"}),
        EnforcementMode::Enforce,
    );
    assert_eq!(result.verdict.decision, Decision::Allow);
    assert_eq!(
        *annotations.0.lock().unwrap(),
        vec![("z_first".into(), true), ("a_second".into(), true)],
    );
    let cycle = source.replace(
        "z_first: {from: $target}",
        "z_first: {from: $target, needs: [a_second]}",
    );
    assert!(validate_manifest_yaml(&cycle).is_err());
    let sensitive = source.replace(
        "z_first: {type: classifier}",
        "z_first: {type: classifier, api_key_env: AGT_TEST_SECRET}",
    );
    assert!(Manifest::parse_yaml_str(&sensitive)
        .unwrap()
        .mark_url_sourced()
        .is_err());
}

#[test]
fn compatibility_host_still_uses_opa() {
    // Isolate executable selection from the other tests' process environment.
    if env::var_os("AGT_OPA_BACKEND_CHILD").is_none() {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new(env::current_exe().unwrap())
            .args(["--exact", "compatibility_host_still_uses_opa"])
            .env("AGT_OPA_BACKEND_CHILD", "1")
            .env("ACS_OPA_PATH", directory.path().join("missing-opa"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let manifest = Manifest::from_yaml_str(MANIFEST).unwrap();
    if env::var_os("AGT_EXPECT_UPSTREAM_REGO").is_some() {
        let upstream = Runtime::new(
            manifest.clone(),
            default_host_annotator_dispatcher(&manifest).unwrap(),
            agent_control_spec::dispatchers::default_policy_dispatcher(&manifest).unwrap(),
        )
        .unwrap();
        assert_eq!(
            upstream
                .evaluate_point(InterceptionPoint::Input, json!({"input": "hello"}))
                .verdict
                .decision,
            Decision::Allow,
            "the upstream in-process backend must not need the missing OPA executable",
        );
    }

    let control = AgentControl::from_manifest(manifest).unwrap();
    let result = control.evaluate_intervention_point(
        InterceptionPoint::Input,
        json!({"input": "hello"}),
        EnforcementMode::Enforce,
    );
    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:policy_invocation_failed")
    );
    #[cfg(all(feature = "bundled-dispatchers", feature = "opa"))]
    assert_ffi_uses_opa();
}

#[cfg(all(feature = "bundled-dispatchers", feature = "opa"))]
fn assert_ffi_uses_opa() {
    use agent_control_specification::ffi;
    use std::ffi::{CStr, CString};

    let manifest = CString::new(MANIFEST).unwrap();
    let request = CString::new(
        json!({"intervention_point": "input", "snapshot": {"input": "hello"}}).to_string(),
    )
    .unwrap();
    let mut error = std::ptr::null_mut();
    // Buffers outlive the calls; each native allocation is consumed or freed once.
    unsafe {
        let builder = ffi::acs_builder_from_yaml(manifest.as_ptr(), &mut error);
        assert!(!builder.is_null());
        assert_eq!(
            ffi::acs_builder_enable_default_policy_dispatcher(builder, &mut error),
            0
        );
        let runtime = ffi::acs_builder_build(builder, &mut error);
        assert!(!runtime.is_null());
        let output = ffi::acs_runtime_evaluate(runtime, request.as_ptr(), &mut error);
        assert!(!output.is_null());
        let result: serde_json::Value =
            serde_json::from_slice(CStr::from_ptr(output).to_bytes()).unwrap();
        ffi::acs_free_string(output);
        ffi::acs_runtime_free(runtime);
        assert_eq!(result["verdict"]["decision"], "deny");
        assert_eq!(
            result["verdict"]["reason"],
            "runtime_error:policy_invocation_failed"
        );
    }
}

#[test]
fn telemetry_keeps_agent_hooks_wire_names() {
    for point in [
        InterceptionPoint::AgentStartup,
        InterceptionPoint::PreToolCall,
    ] {
        let event = TelemetryEvent::new(TelemetryEventType::Decision, point)
            .with_decision(Decision::Allow)
            .with_enforcement_mode(EnforcementMode::EvaluateOnly);
        let wire = event.to_json();
        assert_eq!(wire["intervention_point"], point.as_str());
        assert_eq!(wire["enforcement_mode"], "evaluate_only");
    }
}
