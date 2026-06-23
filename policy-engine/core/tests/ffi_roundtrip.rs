use agent_control_specification_core::ffi::{
    acs_builder_build, acs_builder_from_path, acs_builder_from_url, acs_builder_from_yaml,
    acs_builder_from_yaml_chain, acs_builder_register_annotator_dispatcher,
    acs_builder_register_policy_dispatcher, acs_free_string, acs_runtime_evaluate,
    acs_runtime_free,
};
use serde_json::{json, Value};
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_void},
    path::Path,
    ptr,
};

const MANIFEST_YAML: &str = r#"agent_control_specification_version: 0.3.1-beta
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

const BASE_CHAIN_YAML: &str = r#"agent_control_specification_version: 0.3.1-beta
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

const OVERLAY_CHAIN_YAML: &str = r#"agent_control_specification_version: 0.3.1-beta
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

const UNRESOLVED_EXTENDS_YAML: &str = r#"agent_control_specification_version: 0.3.1-beta
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
            },
            "evidence": {
                "artefact": "sha256:proofblob",
                "verification_pointers": {
                    "issuer_pubkey": "https://example.com/keys/2026.pem",
                    "policy_registry": "https://example.com/policies/v1/"
                }
            }
        })
    } else {
        json!({
            "decision": "allow",
            "evidence": {
                "artefact": "sha256:allow-proof",
                "verification_pointers": {
                    "policy_registry": "https://example.com/policies/v1/"
                }
            }
        })
    };

    CString::new(output.to_string())
        .expect("JSON contains no NUL")
        .into_raw()
}

unsafe extern "C" fn null_transform_policy_callback(
    _prepared_invocation_json: *const c_char,
    _user_data: *mut c_void,
) -> *mut c_char {
    CString::new(
        json!({
            "decision": "transform",
            "transform": {"path": "$policy_target", "value": null}
        })
        .to_string(),
    )
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
    unsafe { build_runtime_from_builder_with_policy(builder, policy_callback) }
}

unsafe fn build_runtime_from_builder_with_policy(
    builder: *mut agent_control_specification_core::ffi::AcsBuilder,
    policy: agent_control_specification_core::ffi::AcsPolicyCallback,
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
            Some(policy),
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
        assert_eq!(result["transformed_policy_target_applied"], true);
        assert_eq!(
            result["transformed_policy_target"]["text"],
            "Please summarize account [REDACTED]."
        );
        // AGT D1: the verdict carries the canonical transform payload so
        // bindings can persist what the policy actually asked for.
        assert_eq!(
            result["verdict"]["transform"]["path"],
            "$policy_target.text"
        );
        assert_eq!(
            result["verdict"]["transform"]["value"],
            "Please summarize account [REDACTED]."
        );
        // AGT D2: evidence rides through the FFI response verbatim.
        assert_eq!(
            result["verdict"]["evidence"]["artefact"],
            "sha256:proofblob"
        );
        assert_eq!(
            result["verdict"]["evidence"]["verification_pointers"]["issuer_pubkey"],
            "https://example.com/keys/2026.pem"
        );
        // AGT D1.4: bisected identity. The transform mutates the policy
        // target so enforced_identity must differ from input_identity, and
        // action_identity must remain a backwards-compatible alias for
        // enforced_identity.
        let input_identity = result["input_identity"]
            .as_str()
            .expect("input_identity is a string");
        let enforced_identity = result["enforced_identity"]
            .as_str()
            .expect("enforced_identity is a string");
        let action_identity = result["action_identity"]
            .as_str()
            .expect("action_identity is a string");
        assert!(input_identity.starts_with("sha256:"));
        assert!(enforced_identity.starts_with("sha256:"));
        assert_ne!(input_identity, enforced_identity);
        assert_eq!(action_identity, enforced_identity);

        acs_free_string(out);
        acs_runtime_free(runtime);
    }
}

#[test]
fn ffi_roundtrip_allow_carries_evidence_and_matched_identities() {
    unsafe {
        let runtime = build_runtime();
        let request = CString::new(
            json!({
                "intervention_point": "input",
                "snapshot": {
                    "input": {"text": "Please summarize the morning briefing."},
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
        // The dispatcher returns allow plus an evidence artefact.
        assert_eq!(result["verdict"]["decision"], "allow");
        assert!(result["verdict"]["transform"].is_null());
        assert_eq!(
            result["verdict"]["evidence"]["artefact"],
            "sha256:allow-proof"
        );
        assert_eq!(
            result["verdict"]["evidence"]["verification_pointers"]["policy_registry"],
            "https://example.com/policies/v1/"
        );
        // AGT D1.4: non-transform verdicts MUST report equal identities, and
        // action_identity MUST alias enforced_identity.
        let input_identity = result["input_identity"]
            .as_str()
            .expect("input_identity is a string");
        let enforced_identity = result["enforced_identity"]
            .as_str()
            .expect("enforced_identity is a string");
        let action_identity = result["action_identity"]
            .as_str()
            .expect("action_identity is a string");
        assert_eq!(input_identity, enforced_identity);
        assert_eq!(action_identity, enforced_identity);

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
        assert!(!out.is_null(), "evaluate error: {}", take_err(err));
        let result: Value = serde_json::from_str(
            CStr::from_ptr(out)
                .to_str()
                .expect("runtime output is UTF-8"),
        )
        .expect("runtime output is JSON");
        assert_eq!(result["verdict"]["decision"], "deny");
        assert_eq!(
            result["verdict"]["reason"],
            "runtime_error:intervention_point_unknown"
        );
        assert_eq!(result["transformed_policy_target_applied"], false);
        acs_free_string(out);
        acs_runtime_free(runtime);
    }
}

#[test]
fn ffi_malformed_request_envelopes_fail_closed() {
    unsafe {
        let runtime = build_runtime();
        let cases = [
            "{".to_string(),
            "[]".to_string(),
            json!({"snapshot": {"input": {"text": "hello"}}, "mode": "enforce"}).to_string(),
            json!({"intervention_point": "input", "mode": "enforce"}).to_string(),
            json!({"intervention_point": "input", "snapshot": [], "mode": "enforce"}).to_string(),
            json!({"intervention_point": "input", "snapshot": {"input": {"text": "hello"}}, "mode": "bogus"}).to_string(),
            json!({"intervention_point": "input", "snapshot": {"input": {"text": "hello"}}, "mode": 1}).to_string(),
        ];

        for request in cases {
            let result = evaluate_raw_request(runtime, &request);
            assert_eq!(result["verdict"]["decision"], "deny");
            assert_eq!(result["verdict"]["reason"], "runtime_error:request_invalid");
            assert_eq!(result["policy_input"], Value::Null);
        }

        let default_mode = evaluate_raw_request(
            runtime,
            &json!({
                "intervention_point": "input",
                "snapshot": {"input": {"text": "hello"}}
            })
            .to_string(),
        );
        assert_eq!(default_mode["verdict"]["decision"], "allow");
        acs_runtime_free(runtime);
    }
}

#[test]
fn ffi_marks_explicit_null_policy_target_transform() {
    unsafe {
        let manifest = CString::new(BASE_CHAIN_YAML).expect("manifest contains no NUL");
        let mut err = ptr::null_mut();
        let builder = acs_builder_from_yaml(manifest.as_ptr(), &mut err);
        assert!(!builder.is_null(), "builder error: {}", take_err(err));
        let runtime =
            build_runtime_from_builder_with_policy(builder, null_transform_policy_callback);
        let request = CString::new(
            json!({
                "intervention_point": "input",
                "snapshot": {"input": {"text": "clear me"}},
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
        assert_eq!(result["transformed_policy_target"], Value::Null);
        assert_eq!(result["transformed_policy_target_applied"], true);
        acs_free_string(out);
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
fn ffi_builder_from_url_threads_pin_and_fails_closed_on_non_https() {
    // The URL loader requires HTTPS, so a non-https URL fails closed before any
    // network access. Exercise both the NULL (unpinned) and a supplied pin to
    // confirm the optional `sha256` argument threads through the FFI boundary.
    unsafe {
        let url = CString::new("http://policy.example/manifest.yaml").expect("url contains no NUL");
        let pin = CString::new("00".repeat(32)).expect("pin contains no NUL");
        for sha256 in [ptr::null(), pin.as_ptr()] {
            let mut err = ptr::null_mut();
            let builder = acs_builder_from_url(url.as_ptr(), sha256, &mut err);
            assert!(builder.is_null(), "non-https URL must fail closed");
            let detail = take_err(err);
            assert!(
                detail.contains("from_url failed") && detail.contains("unsupported URL scheme"),
                "unexpected error detail: {detail}"
            );
        }
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

unsafe fn evaluate_raw_request(
    runtime: *mut agent_control_specification_core::ffi::AcsRuntime,
    request_json: &str,
) -> Value {
    let request = CString::new(request_json).expect("request contains no NUL");
    let mut err = ptr::null_mut();
    let out = unsafe { acs_runtime_evaluate(runtime, request.as_ptr(), &mut err) };
    assert!(!out.is_null(), "evaluate error: {}", take_err(err));
    assert!(err.is_null(), "unexpected error: {}", take_err(err));
    let result: Value =
        serde_json::from_str(unsafe { CStr::from_ptr(out).to_str().expect("UTF-8") })
            .expect("runtime output is JSON");
    unsafe { acs_free_string(out) };
    result
}
