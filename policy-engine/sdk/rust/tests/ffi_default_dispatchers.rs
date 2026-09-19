// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(all(feature = "bundled-dispatchers", feature = "opa"))]

use agent_control_specification::ffi::{
    acs_builder_build, acs_builder_enable_default_annotator_dispatcher,
    acs_builder_enable_default_policy_dispatcher, acs_builder_from_yaml,
    acs_builder_set_url_fetch_limits, acs_free_string, acs_runtime_evaluate, acs_runtime_free,
};
use serde_json::{json, Value};
use std::{
    env,
    ffi::{CStr, CString},
    os::raw::c_char,
    ptr,
    sync::{Mutex, OnceLock},
};

const REGO_MANIFEST: &str = r#"agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: defaults-rego
policies:
  input_policy:
    type: rego
    query: data.acs.verdict
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_policy
    policy_target: $.input
    annotations:
      prompt_classifier:
        from: $.input.text
annotators:
  prompt_classifier:
    type: classifier"#;

const REGO_MANIFEST_NO_ANNOTATIONS: &str = r#"agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: defaults-rego-no-annotations
policies:
  input_policy:
    type: rego
    query: data.acs.verdict
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_policy
    policy_target: $.input"#;

const CUSTOM_POLICY_MANIFEST: &str = r#"agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: defaults-custom
policies:
  input_policy:
    type: custom
    adapter: host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_policy
    policy_target: $.input"#;

fn take_err(err: *mut c_char) -> String {
    if err.is_null() {
        return "<no error>".to_string();
    }
    let message = unsafe { CStr::from_ptr(err) }
        .to_string_lossy()
        .into_owned();
    unsafe { acs_free_string(err) };
    message
}

#[test]
fn zero_config_defaults_build_a_runtime_for_rego_and_classifier() {
    let yaml = CString::new(REGO_MANIFEST).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let builder = unsafe { acs_builder_from_yaml(yaml.as_ptr(), &mut err) };
    assert!(!builder.is_null(), "builder construction failed");

    assert_eq!(
        unsafe { acs_builder_enable_default_policy_dispatcher(builder, &mut err) },
        0
    );
    assert_eq!(
        unsafe { acs_builder_enable_default_annotator_dispatcher(builder, &mut err) },
        0
    );

    let runtime = unsafe { acs_builder_build(builder, &mut err) };
    assert!(
        !runtime.is_null(),
        "expected zero-config build to succeed, got {}",
        take_err(err)
    );
    unsafe { acs_runtime_free(runtime) };
}

#[test]
fn default_policy_dispatcher_fails_closed_for_bad_explicit_opa_path() {
    let _guard = opa_env_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let missing_opa = directory.path().join("missing-opa");
    let _saved = EnvVarGuard::set("ACS_OPA_PATH", &missing_opa);
    let yaml = CString::new(REGO_MANIFEST_NO_ANNOTATIONS).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let builder = unsafe { acs_builder_from_yaml(yaml.as_ptr(), &mut err) };
    assert!(!builder.is_null(), "builder construction failed");

    assert_eq!(
        unsafe { acs_builder_enable_default_policy_dispatcher(builder, &mut err) },
        0
    );
    assert_eq!(
        unsafe { acs_builder_enable_default_annotator_dispatcher(builder, &mut err) },
        0
    );

    let runtime = unsafe { acs_builder_build(builder, &mut err) };
    assert!(
        !runtime.is_null(),
        "bad explicit OPA path must fail closed during evaluation, got build error: {}",
        take_err(err)
    );

    let request = CString::new(
        json!({
            "intervention_point": "input",
            "snapshot": {"input": {"text": "hello"}},
            "mode": "enforce"
        })
        .to_string(),
    )
    .unwrap();
    let out = unsafe { acs_runtime_evaluate(runtime, request.as_ptr(), &mut err) };
    assert!(!out.is_null(), "evaluate error: {}", take_err(err));
    let result: Value = serde_json::from_str(
        unsafe { CStr::from_ptr(out) }
            .to_str()
            .expect("runtime output is UTF-8"),
    )
    .expect("runtime output is JSON");
    unsafe { acs_free_string(out) };
    unsafe { acs_runtime_free(runtime) };
    assert_eq!(result["verdict"]["decision"], "deny");
    assert_eq!(
        result["verdict"]["reason"],
        "runtime_error:policy_invocation_failed"
    );
}

#[test]
fn default_policy_dispatcher_rejects_non_rego_policies() {
    let yaml = CString::new(CUSTOM_POLICY_MANIFEST).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let builder = unsafe { acs_builder_from_yaml(yaml.as_ptr(), &mut err) };
    assert!(!builder.is_null());

    assert_eq!(
        unsafe { acs_builder_enable_default_policy_dispatcher(builder, &mut err) },
        0
    );
    assert_eq!(
        unsafe { acs_builder_enable_default_annotator_dispatcher(builder, &mut err) },
        0
    );

    let runtime = unsafe { acs_builder_build(builder, &mut err) };
    assert!(runtime.is_null(), "non-rego policy must fail the build");
    let message = take_err(err);
    assert!(
        message.contains("only Rego"),
        "unexpected error message: {message}"
    );
}

#[test]
fn build_without_enabling_defaults_still_requires_a_policy_dispatcher() {
    let yaml = CString::new(CUSTOM_POLICY_MANIFEST).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let builder = unsafe { acs_builder_from_yaml(yaml.as_ptr(), &mut err) };
    assert!(!builder.is_null());

    let runtime = unsafe { acs_builder_build(builder, &mut err) };
    assert!(runtime.is_null());
    let message = take_err(err);
    assert!(
        message.contains("not registered"),
        "unexpected error message: {message}"
    );
}

#[test]
fn set_url_fetch_limits_validates_and_threads_through_build() {
    let mut err: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { acs_builder_set_url_fetch_limits(ptr::null_mut(), 4096, 1000, 0, &mut err) },
        -1,
        "null builder must fail closed"
    );
    let _ = take_err(err);

    let yaml = CString::new(REGO_MANIFEST).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let builder = unsafe { acs_builder_from_yaml(yaml.as_ptr(), &mut err) };
    assert!(!builder.is_null(), "builder construction failed");
    assert_eq!(
        unsafe { acs_builder_set_url_fetch_limits(builder, 4096, 1000, 2, &mut err) },
        0,
        "setting url fetch limits must succeed"
    );
    assert_eq!(
        unsafe { acs_builder_enable_default_policy_dispatcher(builder, &mut err) },
        0
    );
    assert_eq!(
        unsafe { acs_builder_enable_default_annotator_dispatcher(builder, &mut err) },
        0
    );
    let runtime = unsafe { acs_builder_build(builder, &mut err) };
    assert!(
        !runtime.is_null(),
        "build with url fetch limits must succeed, got {}",
        take_err(err)
    );
    unsafe { acs_runtime_free(runtime) };
}

fn opa_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = env::var_os(key);
        env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => env::set_var(self.key, value),
            None => env::remove_var(self.key),
        }
    }
}
