//! Minimal C ABI for Agent Control Specification.
//!
//! Strings crossing the ABI boundary are NUL-terminated UTF-8. Strings
//! returned by ACS (`acs_runtime_evaluate` and error out-parameters) must be
//! released with `acs_free_string`. Strings returned by host callbacks are
//! released with the paired host-provided `AcsFreeResultCallback`.

use crate::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Limits, Manifest, PerfTelemetry, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError, Verdict,
};
use serde_json::json;
#[cfg(feature = "opa")]
use std::collections::BTreeMap;
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_void},
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    str::FromStr,
    sync::Arc,
};

macro_rules! ffi_guard {
    (ptr_with_err, $err:expr, $body:block) => {{
        match catch_unwind(AssertUnwindSafe(|| $body)) {
            Ok(value) => value,
            Err(payload) => {
                let msg = panic_message(&payload);
                // SAFETY: `write_err` null-checks the caller-provided out pointer.
                unsafe { write_err($err, &format!("panic crossing ACS FFI boundary: {msg}")) };
                std::ptr::null_mut()
            }
        }
    }};
    (code_with_err, $err:expr, $sentinel:expr, $body:block) => {{
        match catch_unwind(AssertUnwindSafe(|| $body)) {
            Ok(value) => value,
            Err(payload) => {
                let msg = panic_message(&payload);
                // SAFETY: `write_err` null-checks the caller-provided out pointer.
                unsafe { write_err($err, &format!("panic crossing ACS FFI boundary: {msg}")) };
                $sentinel
            }
        }
    }};
    (void, $body:block) => {{
        let _ = catch_unwind(AssertUnwindSafe(|| $body));
    }};
}

pub struct AcsBuilder {
    manifest: Option<Manifest>,
    annotations: Option<Arc<dyn AnnotatorDispatcher>>,
    policy: Option<Arc<dyn PolicyDispatcher>>,
    perf_telemetry: PerfTelemetry,
    enable_default_annotations: bool,
    enable_default_policy: bool,
    limits: Limits,
}

pub struct AcsRuntime {
    runtime: Runtime,
}

pub type AcsFreeResultCallback = unsafe extern "C" fn(ptr: *mut c_char, user_data: *mut c_void);
pub type AcsAnnotatorCallback = unsafe extern "C" fn(
    annotator_name: *const c_char,
    annotator_json: *const c_char,
    preliminary_policy_input_json: *const c_char,
    user_data: *mut c_void,
) -> *mut c_char;
pub type AcsPolicyCallback = unsafe extern "C" fn(
    prepared_invocation_json: *const c_char,
    user_data: *mut c_void,
) -> *mut c_char;

/// Holds a host callback, its matching free callback, and opaque host state.
///
/// Panic/thread-safety contract: the host callback must be safe to invoke from
/// any thread for the lifetime of the runtime, and `user_data` must either be
/// null or point to thread-safe state. If host code panics or unwinds, it must
/// not leave `user_data` in a torn state.
struct CallbackHolder<F> {
    cb: F,
    free: AcsFreeResultCallback,
    user_data: *mut c_void,
}

// SAFETY: The C ABI contract above requires callbacks and `user_data` to be
// thread-safe while registered. The raw pointer is opaque to Rust.
unsafe impl<F> Send for CallbackHolder<F> {}
// SAFETY: Same contract as `Send`; host-owned callback state must be shareable
// across threads for the runtime lifetime.
unsafe impl<F> Sync for CallbackHolder<F> {}

impl<F> CallbackHolder<F> {
    unsafe fn read_and_free(&self, ptr: *mut c_char) -> Result<String, &'static str> {
        if ptr.is_null() {
            return Err("callback returned null");
        }
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().map(str::to_owned);
        unsafe { (self.free)(ptr, self.user_data) };
        result.map_err(|_| "callback returned non-UTF8 string")
    }
}

struct CAnnotatorDispatcher {
    holder: Arc<CallbackHolder<AcsAnnotatorCallback>>,
}

impl AnnotatorDispatcher for CAnnotatorDispatcher {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        let annotator_json = serde_json::to_string(annotator)
            .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))?;
        let preliminary_json = serde_json::to_string(preliminary_policy_input)
            .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))?;
        let annotator_name_c = cstring_lossy(annotator_name);
        let annotator_json_c = cstring_lossy(&annotator_json);
        let preliminary_json_c = cstring_lossy(&preliminary_json);

        let raw = unsafe {
            (self.holder.cb)(
                annotator_name_c.as_ptr(),
                annotator_json_c.as_ptr(),
                preliminary_json_c.as_ptr(),
                self.holder.user_data,
            )
        };
        let returned = unsafe { self.holder.read_and_free(raw) }
            .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))?;
        if returned == crate::reserved_reason::ANNOTATION_TIMEOUT {
            return Err(RuntimeError::AnnotationTimeout(returned));
        }
        if returned == crate::reserved_reason::ANNOTATION_FAILED {
            return Err(RuntimeError::AnnotationFailed(returned));
        }
        serde_json::from_str(&returned)
            .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))
    }
}

struct CPolicyDispatcher {
    holder: Arc<CallbackHolder<AcsPolicyCallback>>,
}

impl PolicyDispatcher for CPolicyDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let invocation_json = serde_json::to_string(invocation)
            .map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))?;
        let invocation_json_c = cstring_lossy(&invocation_json);
        let raw = unsafe { (self.holder.cb)(invocation_json_c.as_ptr(), self.holder.user_data) };
        let returned = unsafe { self.holder.read_and_free(raw) }
            .map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))?;
        serde_json::from_str(&returned)
            .map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))
    }
}

fn builder_from_manifest(manifest: Manifest) -> *mut AcsBuilder {
    Box::into_raw(Box::new(AcsBuilder {
        manifest: Some(manifest),
        annotations: None,
        policy: None,
        perf_telemetry: PerfTelemetry::default(),
        enable_default_annotations: false,
        enable_default_policy: false,
        limits: Limits::default(),
    }))
}

/// Construct an ACS builder from a filesystem manifest path.
///
/// # Safety
/// `path` must be a valid pointer to a NUL-terminated UTF-8 string. If `err` is
/// non-null, it must point to writable storage for a `char*`; populated errors
/// must be freed with `acs_free_string`.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_from_path(
    path: *const c_char,
    err: *mut *mut c_char,
) -> *mut AcsBuilder {
    ffi_guard!(ptr_with_err, err, {
        let path = match unsafe { cstr_to_str(path) } {
            Some(value) => value,
            None => {
                unsafe { write_err(err, "null or non-UTF8 path") };
                return std::ptr::null_mut();
            }
        };
        match Manifest::from_path(Path::new(path)) {
            Ok(manifest) => builder_from_manifest(manifest),
            Err(error) => {
                unsafe { write_err(err, &format!("from_path failed: {error}")) };
                std::ptr::null_mut()
            }
        }
    })
}

/// Construct an ACS builder from a top level manifest fetched from an HTTPS
/// URL. `sha256` is optional and MAY be null. When supplied it MUST be a 64
/// character hexadecimal SHA-256 digest over the fetched bytes. A non HTTPS
/// URL, a malformed pin, a fetch error, a body size breach, or a hash mismatch
/// fails closed.
///
/// # Safety
/// `url` must be a valid pointer to a NUL-terminated UTF-8 string. `sha256` may
/// be null or a valid pointer to a NUL-terminated UTF-8 string. If `err` is
/// non-null, it must point to writable storage for a `char*`; populated errors
/// must be freed with `acs_free_string`.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_from_url(
    url: *const c_char,
    sha256: *const c_char,
    err: *mut *mut c_char,
) -> *mut AcsBuilder {
    ffi_guard!(ptr_with_err, err, {
        let url = match unsafe { cstr_to_str(url) } {
            Some(value) => value,
            None => {
                unsafe { write_err(err, "null or non-UTF8 url") };
                return std::ptr::null_mut();
            }
        };
        let sha256 = if sha256.is_null() {
            None
        } else {
            match unsafe { cstr_to_str(sha256) } {
                Some(value) => Some(value),
                None => {
                    unsafe { write_err(err, "non-UTF8 sha256") };
                    return std::ptr::null_mut();
                }
            }
        };
        match Manifest::from_url(url, sha256) {
            Ok(manifest) => builder_from_manifest(manifest),
            Err(error) => {
                unsafe { write_err(err, &format!("from_url failed: {error}")) };
                std::ptr::null_mut()
            }
        }
    })
}

/// Construct an ACS builder from an ordered chain of YAML manifest strings.
///
/// # Safety
/// `yamls` must point to `n` valid NUL-terminated UTF-8 string pointers. If
/// `err` is non-null, it must point to writable storage for a `char*`; populated
/// errors must be freed with `acs_free_string`.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_from_yaml_chain(
    yamls: *const *const c_char,
    n: usize,
    err: *mut *mut c_char,
) -> *mut AcsBuilder {
    ffi_guard!(ptr_with_err, err, {
        if yamls.is_null() {
            unsafe { write_err(err, "null yamls array") };
            return std::ptr::null_mut();
        }
        if n == 0 {
            unsafe { write_err(err, "empty yamls array") };
            return std::ptr::null_mut();
        }

        let mut owned: Vec<&str> = Vec::with_capacity(n);
        for index in 0..n {
            let entry = unsafe { *yamls.add(index) };
            let yaml = match unsafe { cstr_to_str(entry) } {
                Some(value) => value,
                None => {
                    unsafe { write_err(err, &format!("yamls[{index}] is null or non-UTF8")) };
                    return std::ptr::null_mut();
                }
            };
            owned.push(yaml);
        }

        match Manifest::from_yaml_chain(&owned) {
            Ok(manifest) => builder_from_manifest(manifest),
            Err(error) => {
                unsafe { write_err(err, &format!("from_yaml_chain failed: {error}")) };
                std::ptr::null_mut()
            }
        }
    })
}

/// Construct an ACS builder from a YAML manifest string.
///
/// # Safety
/// `yaml` must be a valid pointer to a NUL-terminated UTF-8 string. If `err` is
/// non-null, it must point to writable storage for a `char*`; populated errors
/// must be freed with `acs_free_string`.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_from_yaml(
    yaml: *const c_char,
    err: *mut *mut c_char,
) -> *mut AcsBuilder {
    ffi_guard!(ptr_with_err, err, {
        let yaml = match unsafe { cstr_to_str(yaml) } {
            Some(value) => value,
            None => {
                unsafe { write_err(err, "null or non-UTF8 yaml") };
                return std::ptr::null_mut();
            }
        };
        match Manifest::from_yaml_str(yaml) {
            Ok(manifest) => builder_from_manifest(manifest),
            Err(error) => {
                unsafe { write_err(err, &format!("from_yaml failed: {error}")) };
                std::ptr::null_mut()
            }
        }
    })
}

/// Construct an ACS builder from a JSON manifest string.
///
/// # Safety
/// `json` must be a valid pointer to a NUL-terminated UTF-8 string. If `err` is
/// non-null, it must point to writable storage for a `char*`; populated errors
/// must be freed with `acs_free_string`.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_from_json(
    json: *const c_char,
    err: *mut *mut c_char,
) -> *mut AcsBuilder {
    ffi_guard!(ptr_with_err, err, {
        let json = match unsafe { cstr_to_str(json) } {
            Some(value) => value,
            None => {
                unsafe { write_err(err, "null or non-UTF8 json") };
                return std::ptr::null_mut();
            }
        };
        match Manifest::from_json_str(json) {
            Ok(manifest) => builder_from_manifest(manifest),
            Err(error) => {
                unsafe { write_err(err, &format!("from_json failed: {error}")) };
                std::ptr::null_mut()
            }
        }
    })
}

/// Register the host annotator dispatcher callback.
///
/// # Safety
/// `b` must be a live builder returned by ACS and not concurrently mutated.
/// `cb` and `free_result` must be non-null callbacks that remain valid for the
/// built runtime lifetime. `user_data` must satisfy the thread-safety contract
/// documented on `CallbackHolder`. If `err` is non-null it must be writable.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_register_annotator_dispatcher(
    b: *mut AcsBuilder,
    cb: Option<AcsAnnotatorCallback>,
    free_result: Option<AcsFreeResultCallback>,
    user_data: *mut c_void,
    err: *mut *mut c_char,
) -> i32 {
    ffi_guard!(code_with_err, err, -1, {
        let Some(cb) = require_callback(cb, err, "annotator_dispatcher") else {
            return -1;
        };
        let Some(free) = require_callback(free_result, err, "free_result") else {
            return -1;
        };
        let Some(builder) = (unsafe { b.as_mut() }) else {
            unsafe { write_err(err, "null builder") };
            return -1;
        };
        builder.annotations = Some(Arc::new(CAnnotatorDispatcher {
            holder: Arc::new(CallbackHolder {
                cb,
                free,
                user_data,
            }),
        }));
        0
    })
}

/// Register the host policy dispatcher callback.
///
/// # Safety
/// `b` must be a live builder returned by ACS and not concurrently mutated.
/// `cb` and `free_result` must be non-null callbacks that remain valid for the
/// built runtime lifetime. `user_data` must satisfy the thread-safety contract
/// documented on `CallbackHolder`. If `err` is non-null it must be writable.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_register_policy_dispatcher(
    b: *mut AcsBuilder,
    cb: Option<AcsPolicyCallback>,
    free_result: Option<AcsFreeResultCallback>,
    user_data: *mut c_void,
    err: *mut *mut c_char,
) -> i32 {
    ffi_guard!(code_with_err, err, -1, {
        let Some(cb) = require_callback(cb, err, "policy_dispatcher") else {
            return -1;
        };
        let Some(free) = require_callback(free_result, err, "free_result") else {
            return -1;
        };
        let Some(builder) = (unsafe { b.as_mut() }) else {
            unsafe { write_err(err, "null builder") };
            return -1;
        };
        builder.policy = Some(Arc::new(CPolicyDispatcher {
            holder: Arc::new(CallbackHolder {
                cb,
                free,
                user_data,
            }),
        }));
        0
    })
}

/// Enable the bundled native annotator dispatcher as the build-time default.
///
/// When enabled and no explicit annotator dispatcher is registered, the runtime
/// routes each annotator to the matching bundled reference dispatcher (classifier
/// /llm/endpoint) using configuration carried in the manifest. An explicitly
/// registered host dispatcher always overrides this default.
///
/// # Safety
/// `b` must be a live builder returned by ACS and not concurrently mutated. If
/// `err` is non-null it must be writable.
#[cfg(feature = "default-dispatchers")]
#[no_mangle]
pub unsafe extern "C" fn acs_builder_enable_default_annotator_dispatcher(
    b: *mut AcsBuilder,
    err: *mut *mut c_char,
) -> i32 {
    ffi_guard!(code_with_err, err, -1, {
        let Some(builder) = (unsafe { b.as_mut() }) else {
            unsafe { write_err(err, "null builder") };
            return -1;
        };
        builder.enable_default_annotations = true;
        0
    })
}

/// Enable the bundled native OPA policy dispatcher as the build-time default.
///
/// When enabled and no explicit policy dispatcher is registered, the runtime
/// evaluates Rego policies through the bundled OPA dispatcher. An explicitly
/// registered host dispatcher always overrides this default. `build` fails fast
/// if the manifest declares a non-Rego policy. OPA process failures happen
/// during evaluation and are normalized to fail-closed verdicts.
///
/// # Safety
/// `b` must be a live builder returned by ACS and not concurrently mutated. If
/// `err` is non-null it must be writable.
#[cfg(feature = "default-dispatchers")]
#[no_mangle]
pub unsafe extern "C" fn acs_builder_enable_default_policy_dispatcher(
    b: *mut AcsBuilder,
    err: *mut *mut c_char,
) -> i32 {
    ffi_guard!(code_with_err, err, -1, {
        let Some(builder) = (unsafe { b.as_mut() }) else {
            unsafe { write_err(err, "null builder") };
            return -1;
        };
        builder.enable_default_policy = true;
        0
    })
}

/// Set the perf telemetry level with wire values 0, 1, or 2.
///
/// # Safety
/// `b` must be a live builder returned by ACS and not concurrently mutated.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_set_perf_telemetry(
    b: *mut AcsBuilder,
    level: i32,
    err: *mut *mut c_char,
) -> i32 {
    ffi_guard!(code_with_err, err, -1, {
        let Some(builder) = (unsafe { b.as_mut() }) else {
            unsafe { write_err(err, "null builder") };
            return -1;
        };
        if !(0..=2).contains(&level) {
            unsafe { write_err(err, "perf telemetry level must be 0, 1, or 2") };
            return -1;
        }
        let perf_telemetry = PerfTelemetry::from_u8(level as u8)
            .expect("range check ensures valid perf telemetry level");
        builder.perf_telemetry = perf_telemetry;
        0
    })
}

/// Set the URL fetch limits the bundled default dispatchers use for dispatch
/// time fetches of a `system_prompt_url` prompt and a file sourced `bundle_url`
/// rego bundle. `max_bytes` caps the fetched body, `timeout_ms` bounds each
/// request, and `max_redirects` caps the validated redirect chain. A `max_bytes`
/// or `timeout_ms` of 0 keeps the built in default for that field; `max_redirects`
/// is applied as given so 0 forbids redirects. Has no effect unless a bundled
/// default dispatcher is also enabled.
///
/// # Safety
/// `b` must be a live builder returned by ACS and not concurrently mutated. If
/// `err` is non-null it must be writable.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_set_url_fetch_limits(
    b: *mut AcsBuilder,
    max_bytes: u64,
    timeout_ms: u64,
    max_redirects: u32,
    err: *mut *mut c_char,
) -> i32 {
    ffi_guard!(code_with_err, err, -1, {
        let Some(builder) = (unsafe { b.as_mut() }) else {
            unsafe { write_err(err, "null builder") };
            return -1;
        };
        if max_bytes != 0 {
            builder.limits.max_manifest_url_bytes = max_bytes as usize;
        }
        if timeout_ms != 0 {
            builder.limits.manifest_url_timeout_ms = timeout_ms;
        }
        builder.limits.max_manifest_url_redirects = max_redirects as usize;
        0
    })
}

fn resolve_default_annotator_dispatcher(
    builder: &AcsBuilder,
    _manifest: &Manifest,
) -> Result<Option<Arc<dyn AnnotatorDispatcher>>, String> {
    if !builder.enable_default_annotations {
        return Ok(None);
    }
    #[cfg(feature = "default-dispatchers")]
    {
        Ok(Some(crate::dispatchers::default_annotator_dispatcher_for(
            _manifest,
            builder.limits,
        )))
    }
    #[cfg(not(feature = "default-dispatchers"))]
    {
        Err("default annotator dispatcher is unavailable; rebuild with the 'default-dispatchers' feature".to_string())
    }
}

fn resolve_default_policy_dispatcher(
    builder: &AcsBuilder,
    manifest: &Manifest,
) -> Result<Option<Arc<dyn PolicyDispatcher>>, String> {
    if !builder.enable_default_policy {
        return Ok(None);
    }
    #[cfg(all(feature = "default-dispatchers", feature = "opa"))]
    {
        crate::dispatchers::default_policy_dispatcher_with_limits(manifest, builder.limits)
            .map(Some)
            .map_err(|error| error.to_string())
    }
    #[cfg(not(all(feature = "default-dispatchers", feature = "opa")))]
    {
        let _ = manifest;
        Err("default policy dispatcher is unavailable; rebuild with the 'default-dispatchers' and 'opa' features".to_string())
    }
}

/// Build an ACS runtime, consuming and freeing the builder.
///
/// # Safety
/// `b` must be a builder returned by ACS and not already freed. On success or
/// failure this function consumes `b`; do not use it afterwards. If `err` is
/// non-null it must be writable and populated errors must be freed with
/// `acs_free_string`.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_build(
    b: *mut AcsBuilder,
    err: *mut *mut c_char,
) -> *mut AcsRuntime {
    ffi_guard!(ptr_with_err, err, {
        if b.is_null() {
            unsafe { write_err(err, "null builder") };
            return std::ptr::null_mut();
        }
        let mut builder = unsafe { Box::from_raw(b) };
        let manifest = match builder.manifest.take() {
            Some(manifest) => manifest,
            None => {
                unsafe { write_err(err, "builder already consumed") };
                return std::ptr::null_mut();
            }
        };
        let annotations = match builder.annotations.take() {
            Some(dispatcher) => dispatcher,
            None => match resolve_default_annotator_dispatcher(&builder, &manifest) {
                Ok(Some(dispatcher)) => dispatcher,
                Ok(None) => {
                    unsafe { write_err(err, "annotator dispatcher not registered") };
                    return std::ptr::null_mut();
                }
                Err(message) => {
                    unsafe { write_err(err, &message) };
                    return std::ptr::null_mut();
                }
            },
        };
        let policy = match builder.policy.take() {
            Some(dispatcher) => dispatcher,
            None => match resolve_default_policy_dispatcher(&builder, &manifest) {
                Ok(Some(dispatcher)) => dispatcher,
                Ok(None) => {
                    unsafe { write_err(err, "policy dispatcher not registered") };
                    return std::ptr::null_mut();
                }
                Err(message) => {
                    unsafe { write_err(err, &message) };
                    return std::ptr::null_mut();
                }
            },
        };
        match Runtime::with_perf_telemetry(manifest, annotations, policy, builder.perf_telemetry) {
            Ok(runtime) => Box::into_raw(Box::new(AcsRuntime { runtime })),
            Err(error) => {
                unsafe { write_err(err, &format!("build failed: {error}")) };
                std::ptr::null_mut()
            }
        }
    })
}

/// Free an ACS builder. Null-safe.
///
/// # Safety
/// `b` must be null or a builder pointer returned by ACS that has not already
/// been freed or consumed by `acs_builder_build`.
#[no_mangle]
pub unsafe extern "C" fn acs_builder_free(b: *mut AcsBuilder) {
    ffi_guard!(void, {
        if !b.is_null() {
            unsafe { drop(Box::from_raw(b)) };
        }
    })
}

/// Evaluate one intervention point request.
///
/// # Safety
/// `r` must be a live runtime returned by ACS. `request_json` must be a valid
/// pointer to a NUL-terminated UTF-8 string. If the string is not a valid
/// request JSON object, ACS returns a deny verdict with
/// `runtime_error:request_invalid`. A missing `mode` defaults to `enforce`. If
/// `err` is non-null it must be writable; populated errors and the returned
/// string must be freed with `acs_free_string`.
#[no_mangle]
pub unsafe extern "C" fn acs_runtime_evaluate(
    r: *const AcsRuntime,
    request_json: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    ffi_guard!(ptr_with_err, err, {
        let Some(runtime) = (unsafe { r.as_ref() }) else {
            unsafe { write_err(err, "null runtime") };
            return std::ptr::null_mut();
        };
        let request_str = match unsafe { cstr_to_str(request_json) } {
            Some(value) => value,
            None => {
                unsafe { write_err(err, "null or non-UTF8 request_json") };
                return std::ptr::null_mut();
            }
        };
        let request_value: JsonValue = match serde_json::from_str(request_str) {
            Ok(value) => value,
            Err(_) => return request_invalid_response(),
        };
        let Some(object) = request_value.as_object() else {
            return request_invalid_response();
        };
        let Some(intervention_point_str) =
            object.get("intervention_point").and_then(JsonValue::as_str)
        else {
            return request_invalid_response();
        };
        let intervention_point = match InterventionPoint::from_str(intervention_point_str) {
            Ok(value) => value,
            Err(_) => {
                let error =
                    RuntimeError::InterventionPointUnknown(intervention_point_str.to_string());
                return json_to_c(&json!({
                    "verdict": Verdict::runtime_error(&error),
                    "transformed_policy_target": null,
                    "transformed_policy_target_applied": false,
                    "policy_input": null,
                    "action_identity": null,
                }));
            }
        };
        let mode = match object.get("mode") {
            None => EnforcementMode::Enforce,
            Some(JsonValue::String(mode_str)) => match EnforcementMode::from_str(mode_str) {
                Ok(value) => value,
                Err(_) => return request_invalid_response(),
            },
            Some(_) => return request_invalid_response(),
        };
        let Some(snapshot) = object.get("snapshot").cloned() else {
            return request_invalid_response();
        };
        if !snapshot.is_object() {
            return request_invalid_response();
        }

        let result = runtime
            .runtime
            .evaluate_intervention_point(InterventionPointRequest {
                intervention_point,
                snapshot,
                mode,
            });
        // AGT D1.4: surface both `input_identity` and `enforced_identity` so
        // SDKs can persist them in audit records. `action_identity` is kept
        // as a backwards-compatible alias for `enforced_identity` so older
        // SDK bindings continue to work without a breaking shape change.
        // AGT D1 + D2: `verdict.transform` and `verdict.evidence` already
        // serialize via serde on the Verdict struct, so they ride through
        // this response verbatim when present.
        let response = json!({
            "verdict": result.verdict,
            "transformed_policy_target": result.transformed_policy_target,
            "transformed_policy_target_applied": result.transformed_policy_target.is_some(),
            "policy_input": result.policy_input,
            "action_identity": result.action_identity,
            "input_identity": result.input_identity,
            "enforced_identity": result.enforced_identity,
        });
        json_to_c(&response)
    })
}

/// Resolved `policy_id` and configured annotator names per intervention point,
/// from the merged manifest, as a JSON string owned by the caller (free with
/// `acs_free_string`). The .NET SDK telemetry layer reads this once at
/// construction so events are labelled on every constructor, including
/// `FromManifestChain`.
///
/// # Safety
/// `r` must be null or a runtime pointer returned by ACS that has not been
/// freed. `err` must be null or a valid pointer to a `*mut c_char`.
#[no_mangle]
pub unsafe extern "C" fn acs_runtime_policy_labels(
    r: *const AcsRuntime,
    err: *mut *mut c_char,
) -> *mut c_char {
    ffi_guard!(ptr_with_err, err, {
        let Some(runtime) = (unsafe { r.as_ref() }) else {
            unsafe { write_err(err, "null runtime") };
            return std::ptr::null_mut();
        };
        json_to_c(&runtime.runtime.policy_labels())
    })
}

/// Free an ACS runtime. Null-safe.
///
/// # Safety
/// `r` must be null or a runtime pointer returned by ACS that has not already
/// been freed.
#[no_mangle]
pub unsafe extern "C" fn acs_runtime_free(r: *mut AcsRuntime) {
    ffi_guard!(void, {
        if !r.is_null() {
            unsafe { drop(Box::from_raw(r)) };
        }
    })
}

/// Validate ACS manifest and Rego strings and return a JSON validation result.
///
/// # Safety
/// `manifest_yaml` and `rego_modules_json` must be valid NUL-terminated UTF-8
/// strings. `rego_modules_json` must be a JSON object mapping source names to
/// Rego module strings. `opa_path` may be null. The returned string and any
/// populated error must be released with `acs_free_string`.
#[no_mangle]
#[cfg(feature = "opa")]
pub unsafe extern "C" fn acs_validate_artifacts(
    manifest_yaml: *const c_char,
    rego_modules_json: *const c_char,
    opa_path: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    ffi_guard!(ptr_with_err, err, {
        let Some(manifest_yaml) = (unsafe { cstr_to_str(manifest_yaml) }) else {
            unsafe { write_err(err, "null or non-UTF8 manifest YAML") };
            return std::ptr::null_mut();
        };
        let Some(rego_modules_json) = (unsafe { cstr_to_str(rego_modules_json) }) else {
            unsafe { write_err(err, "null or non-UTF8 Rego modules JSON") };
            return std::ptr::null_mut();
        };
        if rego_modules_json.len() > 8_388_608 {
            let result = crate::ArtifactValidationResult {
                valid: false,
                diagnostics: vec![crate::ValidationDiagnostic {
                    component: "rego".to_string(),
                    code: "rego_size_exceeded".to_string(),
                    message: "Encoded Rego module input exceeds the 8 MiB ABI limit.".to_string(),
                    source: "rego".to_string(),
                    path: None,
                    line: None,
                    column: None,
                    snippet: None,
                }],
            };
            return unsafe { validation_result_to_c(&result, err) };
        }
        let modules: BTreeMap<String, String> = match serde_json::from_str(rego_modules_json) {
            Ok(modules) => modules,
            Err(error) => {
                unsafe { write_err(err, &format!("invalid Rego modules JSON: {error}")) };
                return std::ptr::null_mut();
            }
        };
        let opa_path = unsafe { cstr_to_str(opa_path) }.map(Path::new);
        let result = crate::validate_acs_artifacts(manifest_yaml, &modules, opa_path);
        unsafe { validation_result_to_c(&result, err) }
    })
}

#[cfg(feature = "opa")]
unsafe fn validation_result_to_c(
    result: &crate::ArtifactValidationResult,
    err: *mut *mut c_char,
) -> *mut c_char {
    match serde_json::to_string(result) {
        Ok(json) => cstring_lossy(&json).into_raw(),
        Err(error) => {
            unsafe {
                write_err(
                    err,
                    &format!("failed to serialize validation result: {error}"),
                )
            };
            std::ptr::null_mut()
        }
    }
}

/// Free a Rust-allocated string returned by ACS. Null-safe.
///
/// # Safety
/// `s` must be null or a pointer returned by ACS from `CString::into_raw` that
/// has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn acs_free_string(s: *mut c_char) {
    ffi_guard!(void, {
        if !s.is_null() {
            unsafe { drop(CString::from_raw(s)) };
        }
    })
}

unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

fn string_to_c(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(cstring) => cstring.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn json_to_c(value: &JsonValue) -> *mut c_char {
    match serde_json::to_string(value) {
        Ok(serialized) => string_to_c(&serialized),
        Err(_) => string_to_c(r#"{"error":"serialization failed"}"#),
    }
}

fn request_invalid_response() -> *mut c_char {
    json_to_c(&json!({
        "verdict": {
            "decision": Decision::Deny,
            "reason": "runtime_error:request_invalid",
            "message": "Request blocked by Agent Control Specification."
        },
        "transformed_policy_target": null,
        "transformed_policy_target_applied": false,
        "policy_input": null,
        "action_identity": null,
    }))
}

unsafe fn write_err(err: *mut *mut c_char, msg: &str) {
    if !err.is_null() {
        unsafe { *err = string_to_c(msg) };
    }
}

fn require_callback<F>(cb: Option<F>, err_out: *mut *mut c_char, slot: &str) -> Option<F> {
    match cb {
        Some(callback) => Some(callback),
        None => {
            unsafe { write_err(err_out, &format!("required callback `{slot}` is null")) };
            None
        }
    }
}

fn cstring_lossy(s: &str) -> CString {
    let cleaned = s.replace('\0', " ");
    CString::new(cleaned).unwrap_or_else(|_| CString::new("").expect("empty string has no NUL"))
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}
