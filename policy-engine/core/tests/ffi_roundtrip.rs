use agent_control_specification_core::ffi::{
    acs_builder_build, acs_builder_from_path, acs_builder_from_yaml, acs_builder_from_yaml_chain,
    acs_builder_register_annotator_dispatcher, acs_builder_register_policy_dispatcher,
    acs_free_string, acs_runtime_evaluate, acs_runtime_free,
};
use serde_json::{json, Value};
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_void},
    path::Path,
    ptr,
};

const MANIFEST_YAML: &str = r#"agent_control_specification_version: 0.3.0-alpha
metadata:
  name: basic-host-example
policies:
  input_custom_policy:
    type: custom
    adapter: basic_host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input
    annotations:
      prompt_classifier:
        from: $.input.text
annotators:
  prompt_classifier:
    type: classifier"#;

const BASE_CHAIN_YAML: &str = r#"agent_control_specification_version: 0.3.0-alpha
policies:
  input_custom_policy:
    type: custom
    adapter: basic_host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input"#;

const OVERLAY_CHAIN_YAML: &str = r#"agent_control_specification_version: 0.3.0-alpha
metadata:
  name: ffi-chain-test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input
    annotations:
      prompt_classifier:
        from: $.input.text
annotators:
  prompt_classifier:
    type: classifier"#;

const UNRESOLVED_EXTENDS_YAML: &str = r#"agent_control_specification_version: 0.3.0-alpha
extends:
  - ./base.yaml
policies:
  input_custom_policy:
    type: custom
    adapter: basic_host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input"#;

unsafe extern "C" fn free_result(ptr: *mut c_char, _user_data: *mut c_void) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

unsafe extern "C" fn annotator_callback(
    annotator_name: *const c_char,
    _annotator_json: *const c_char,
    preliminary_policy_input_json: *const c_char,
    _user_data: *mut c_void,
) -> *mut c_char {
    let annotator_name = unsafe { CStr::from_ptr(annotator_name) }
        .to_str()
        .expect("annotator name is UTF-8");
    let preliminary: Value = serde_json::from_str(
        unsafe { CStr::from_ptr(preliminary_policy_input_json) }
            .to_str()
            .expect("preliminary input is UTF-8"),
    )
    .expect("preliminary input is JSON");
    let text = preliminary["policy_target"]["value"]["text"]
        .as_str()
        .unwrap_or_default();
    CString::new(
        json!({
            "annotator": annotator_name,
            "contains_account_number": text.contains("1234"),
        })
        .to_string(),
    )
    .expect("JSON contains no NUL")
    .into_raw()
}

unsafe extern "C" fn policy_callback(
    prepared_invocation_json: *const c_char,
    _user_data: *mut c_void,
) -> *mut c_char {
    let invocation: Value = serde_json::from_str(
        unsafe { CStr::from_ptr(prepared_invocation_json) }
            .to_str()
            .expect("policy invocation is UTF-8"),
    )
    .expect("policy invocation is JSON");
    let contains_account_number = invocation["input"]["annotations"]["prompt_classifier"]
        ["contains_account_number"]
        .as_bool()
        .unwrap_or(false);

    let output = if contains_account_number {
        json!({
            "decision": "transform",
            "reason": "account_number_redacted",
            "message": "Account number was redacted before continuing.",
            "transform": {
                "path": "$policy_target.text",
                "value": "Please summarize account [REDACTED]."
            }
        })
    } else {
        json!({ "decision": "allow" })
    };

    CString::new(output.to_string())
        .expect("JSON contains no NUL")
        .into_raw()
}

unsafe fn build_runtime() -> *mut agent_control_specification_core::ffi::AcsRuntime {
    let manifest = CString::new(MANIFEST_YAML).expect("manifest contains no NUL");
    let mut err = ptr::null_mut();
    let builder = unsafe { acs_builder_from_yaml(manifest.as_ptr(), &mut err) };
    assert!(!builder.is_null(), "builder error: {}", take_err(err));
    build_runtime_from_builder(builder)
}

unsafe fn build_runtime_from_builder(
    builder: *mut agent_control_specification_core::ffi::AcsBuilder,
) -> *mut agent_control_specification_core::ffi::AcsRuntime {
    let mut err = ptr::null_mut();

    let registered = unsafe {
        acs_builder_register_annotator_dispatcher(
            builder,
            Some(annotator_callback),
            Some(free_result),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(registered, 0, "annotator error: {}", take_err(err));

    let registered = unsafe {
        acs_builder_register_policy_dispatcher(
            builder,
            Some(policy_callback),
            Some(free_result),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(registered, 0, "policy error: {}", take_err(err));

    let runtime = unsafe { acs_builder_build(builder, &mut err) };
    assert!(!runtime.is_null(), "build error: {}", take_err(err));
    runtime
}

#[test]
fn ffi_roundtrip_transforms_policy_target() {
    unsafe {
        let runtime = build_runtime();
        let request = CString::new(
            json!({
                "intervention_point": "input",
                "snapshot": {
                    "input": {"text": "Please summarize account 1234."},
                    "actor": {"id": "user-123"},
                    "transport": {"kind": "api_gateway", "route": "/chat"}
                },
                "mode": "enforce"
            })
            .to_string(),
        )
        .expect("request contains no NUL");
        let mut err = ptr::null_mut();
        let out = acs_runtime_evaluate(runtime, request.as_ptr(), &mut err);
        assert!(!out.is_null(), "evaluate error: {}", take_err(err));

        let result: Value = serde_json::from_str(
            CStr::from_ptr(out)
                .to_str()
                .expect("runtime output is UTF-8"),
        )
        .expect("runtime output is JSON");
        assert_eq!(result["verdict"]["decision"], "transform");
        assert_eq!(
            result["transformed_policy_target"]["text"],
            "Please summarize account [REDACTED]."
        );

        acs_free_string(out);
        acs_runtime_free(runtime);
    }
}

#[test]
fn ffi_evaluate_rejects_unknown_intervention_point() {
    unsafe {
        let runtime = build_runtime();
        let request = CString::new(
            json!({
                "intervention_point": "not_a_point",
                "snapshot": {},
                "mode": "enforce"
            })
            .to_string(),
        )
        .expect("request contains no NUL");
        let mut err = ptr::null_mut();
        let out = acs_runtime_evaluate(runtime, request.as_ptr(), &mut err);
        assert!(out.is_null());
        assert!(!err.is_null());
        acs_free_string(err);
        acs_runtime_free(runtime);
    }
}

#[test]
fn ffi_builder_from_path_resolves_extends_and_builds_runtime() {
    unsafe {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/extends/ordered/child.yaml");
        let path = CString::new(path.to_string_lossy().as_bytes()).expect("path contains no NUL");
        let mut err = ptr::null_mut();
        let builder = acs_builder_from_path(path.as_ptr(), &mut err);
        assert!(!builder.is_null(), "builder error: {}", take_err(err));
        let runtime = build_runtime_from_builder(builder);
        acs_runtime_free(runtime);
    }
}

#[test]
fn ffi_yaml_chain_merges_positionally_and_builds_runtime() {
    unsafe {
        let base = CString::new(BASE_CHAIN_YAML).expect("manifest contains no NUL");
        let overlay = CString::new(OVERLAY_CHAIN_YAML).expect("manifest contains no NUL");
        let yamls = [base.as_ptr(), overlay.as_ptr()];
        let mut err = ptr::null_mut();
        let builder = acs_builder_from_yaml_chain(yamls.as_ptr(), yamls.len(), &mut err);
        assert!(!builder.is_null(), "builder error: {}", take_err(err));
        let runtime = build_runtime_from_builder(builder);

        let request = CString::new(
            json!({
                "intervention_point": "input",
                "snapshot": {"input": {"text": "Please summarize account 1234."}},
                "mode": "enforce"
            })
            .to_string(),
        )
        .expect("request contains no NUL");
        let out = acs_runtime_evaluate(runtime, request.as_ptr(), &mut err);
        assert!(!out.is_null(), "evaluate error: {}", take_err(err));
        let result: Value = serde_json::from_str(
            CStr::from_ptr(out)
                .to_str()
                .expect("runtime output is UTF-8"),
        )
        .expect("runtime output is JSON");
        assert_eq!(result["verdict"]["decision"], "transform");
        acs_free_string(out);
        acs_runtime_free(runtime);
    }
}

#[test]
fn ffi_yaml_chain_rejects_entries_with_extends() {
    unsafe {
        let manifest = CString::new(UNRESOLVED_EXTENDS_YAML).expect("manifest contains no NUL");
        let yamls = [manifest.as_ptr()];
        let mut err = ptr::null_mut();
        let builder = acs_builder_from_yaml_chain(yamls.as_ptr(), yamls.len(), &mut err);
        assert!(builder.is_null());
        let message = take_err(err);
        assert!(
            message.contains("unresolved extends"),
            "error should explain unresolved extends, got {message:?}"
        );
    }
}

#[test]
fn ffi_single_string_loader_preserves_extends_and_build_fails_closed() {
    unsafe {
        let manifest = CString::new(UNRESOLVED_EXTENDS_YAML).expect("manifest contains no NUL");
        let mut err = ptr::null_mut();
        let builder = acs_builder_from_yaml(manifest.as_ptr(), &mut err);
        assert!(!builder.is_null(), "builder error: {}", take_err(err));
        let registered = acs_builder_register_annotator_dispatcher(
            builder,
            Some(annotator_callback),
            Some(free_result),
            ptr::null_mut(),
            &mut err,
        );
        assert_eq!(registered, 0, "annotator error: {}", take_err(err));
        let registered = acs_builder_register_policy_dispatcher(
            builder,
            Some(policy_callback),
            Some(free_result),
            ptr::null_mut(),
            &mut err,
        );
        assert_eq!(registered, 0, "policy error: {}", take_err(err));
        let runtime = acs_builder_build(builder, &mut err);
        assert!(runtime.is_null());
        let message = take_err(err);
        assert!(
            message.contains("extends"),
            "error should explain unresolved extends, got {message:?}"
        );
    }
}

unsafe fn take_err(err: *mut c_char) -> String {
    if err.is_null() {
        return "<no error>".to_string();
    }
    let message = unsafe { CStr::from_ptr(err) }
        .to_string_lossy()
        .into_owned();
    unsafe { acs_free_string(err) };
    message
}
