#![cfg(feature = "default-dispatchers")]

#[cfg(feature = "opa")]
use agent_control_specification_core::ffi::acs_runtime_evaluate;
use agent_control_specification_core::ffi::{
    acs_builder_build, acs_builder_enable_default_annotator_dispatcher,
    acs_builder_enable_default_policy_dispatcher, acs_builder_free, acs_builder_from_yaml,
    acs_builder_set_url_fetch_limits, acs_free_string, acs_runtime_free,
};
#[cfg(feature = "opa")]
use serde_json::{json, Value};
#[cfg(feature = "opa")]
use std::env;
#[cfg(feature = "opa")]
use std::sync::{Mutex, OnceLock};
use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    ptr,
};

#[cfg(feature = "opa")]
const REGO_MANIFEST: &str = r#"agent_control_specification_version: 0.3.1-beta
metadata:
  name: defaults-rego
policies:
  input_policy:
    type: rego
    query: data.acs.verdict
    bundle: ./policy
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

#[cfg(feature = "opa")]
const REGO_MANIFEST_NO_ANNOTATIONS: &str = r#"agent_control_specification_version: 0.3.1-beta
metadata:
  name: defaults-rego-no-annotations
policies:
  input_policy:
    type: rego
    query: data.acs.verdict
    bundle: ./policy
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_policy
    policy_target: $.input"#;

const CUSTOM_POLICY_MANIFEST: &str = r#"agent_control_specification_version: 0.3.1-beta
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
    assert!(!err.is_null(), "expected an error message");
    let message = unsafe { CStr::from_ptr(err) }
        .to_string_lossy()
        .into_owned();
    unsafe { acs_free_string(err) };
    message
}

#[cfg(feature = "opa")]
#[test]
fn zero_config_defaults_build_a_runtime_for_rego_and_classifier() {
    let _guard = opa_env_lock().lock().unwrap();
    let saved = EnvVarGuard::remove("ACS_OPA_PATH");
    if !opa_available() {
        eprintln!("skipping: opa binary not available");
        drop(saved);
        return;
    }
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
        "expected zero-config build to succeed, got {:?}",
        (!err.is_null()).then(|| take_err(err))
    );
    unsafe { acs_runtime_free(runtime) };
}

#[cfg(feature = "opa")]
#[test]
fn default_policy_dispatcher_fails_closed_for_bad_explicit_opa_path() {
    let _guard = opa_env_lock().lock().unwrap();
    let _saved = EnvVarGuard::set("ACS_OPA_PATH", "/definitely/not/a/real/opa");
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

    // No enable calls and no registered dispatcher: build must fail closed.
    let runtime = unsafe { acs_builder_build(builder, &mut err) };
    assert!(runtime.is_null());
    let message = take_err(err);
    assert!(
        message.contains("not registered"),
        "unexpected error message: {message}"
    );
    // builder is consumed by build; nothing to free.
    let _ = acs_builder_free;
}

#[test]
fn set_url_fetch_limits_validates_and_threads_through_build() {
    // The setter mutates the builder limits used for dispatch time fetches. A
    // null builder fails closed; a live builder accepts the values. The build
    // then succeeds with the configured limits in place (opa-gated, since the
    // default policy dispatcher needs the opa binary to evaluate later).
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

    #[cfg(feature = "opa")]
    {
        let _guard = opa_env_lock().lock().unwrap();
        let saved = EnvVarGuard::remove("ACS_OPA_PATH");
        if !opa_available() {
            eprintln!("skipping build assertion: opa binary not available");
            unsafe { acs_builder_free(builder) };
            drop(saved);
            return;
        }
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
            "build with url fetch limits must succeed, got {:?}",
            (!err.is_null()).then(|| take_err(err))
        );
        unsafe { acs_runtime_free(runtime) };
        drop(saved);
    }
    #[cfg(not(feature = "opa"))]
    {
        unsafe { acs_builder_free(builder) };
    }
}

#[cfg(feature = "opa")]
fn opa_available() -> bool {
    std::process::Command::new("opa")
        .arg("version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(feature = "opa")]
fn opa_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(feature = "opa")]
struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

#[cfg(feature = "opa")]
impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = env::var_os(key);
        env::set_var(key, value);
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = env::var_os(key);
        env::remove_var(key);
        Self { key, previous }
    }
}

#[cfg(feature = "opa")]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => env::set_var(self.key, value),
            None => env::remove_var(self.key),
        }
    }
}
