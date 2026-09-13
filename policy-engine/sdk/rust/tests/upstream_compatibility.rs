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
fn engine_release_and_manifest_grammar_have_distinct_versions() {
    const LEGACY_ARRAY: [&str; 1] = SUPPORTED_MANIFEST_VERSIONS;
    assert_eq!(
        LEGACY_ARRAY.as_slice(),
        agent_control_spec::SUPPORTED_VERSIONS
    );
    validate_manifest_yaml(MANIFEST).unwrap();
    assert!(validate_manifest_yaml(&MANIFEST.replace("0.4.0-alpha.1", "0.4.0-alpha.3")).is_err());
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
