#![cfg(feature = "default-dispatchers")]

use agent_control_specification_core::ffi::{
    acs_builder_build, acs_builder_enable_default_annotator_dispatcher,
    acs_builder_enable_default_policy_dispatcher, acs_builder_free, acs_builder_from_yaml,
    acs_free_string, acs_runtime_free,
};
use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    ptr,
};

#[cfg(feature = "opa")]
const REGO_MANIFEST: &str = r#"agent_control_specification_version: 0.3.0-alpha
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

const CUSTOM_POLICY_MANIFEST: &str = r#"agent_control_specification_version: 0.3.0-alpha
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
    if !opa_available() {
        eprintln!("skipping: opa binary not available");
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

#[cfg(feature = "opa")]
fn opa_available() -> bool {
    std::process::Command::new("opa")
        .arg("version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
