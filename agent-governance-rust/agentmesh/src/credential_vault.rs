// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Credential vault, scoping, and injection for agent tool calls.
//!
//! Rust port of the Python `agent_os.credential_vault` primitive
//! (issue #2481, PR #2534). Tracking issue: #2535.
//!
//! Agents reference secrets via opaque `{{cred:NAME}}` placeholders only;
//! resolved values stay inside the trust boundary.
//!
//! Wire-format note: this SDK uses AES-256-GCM (`aes-gcm` crate) with a
//! 12-byte random nonce prefixed to the ciphertext. The Python SDK uses
//! Fernet. The two persistence formats are not currently interoperable —
//! the cross-language interop spec is tracked in #2535.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

/// Stable string returned in audit/deny records when a request is refused.
pub const DENY_REASON: &str = "credential_denied";

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;

// Lazy because the regex needs runtime construction. Compiled once on first use.
fn placeholder_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\{\s*cred:([A-Za-z0-9_.\-]{1,128})\s*\}\}").unwrap())
}

fn name_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_.\-]{1,128}$").unwrap())
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Outcome of a credential resolution attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialDecision {
    /// Allowed.
    Allow,
    /// Denied.
    Deny,
}

/// Errors from credential vault operations.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// Invalid credential name.
    #[error("invalid credential name: must match [A-Za-z0-9_.-]{{1,128}}")]
    InvalidName,
    /// The named credential does not exist.
    #[error("unknown credential: {0}")]
    Unknown(String),
    /// Encryption / decryption failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// I/O error (persistence).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization error.
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// Encryption key not supplied for a persistent vault.
    #[error("encryption key required when persistence is configured")]
    KeyRequired,
    /// Encryption key has wrong length.
    #[error("encryption key must be exactly {KEY_LENGTH} bytes")]
    BadKeyLength,
}

/// An internal credential entry. Never exposed to agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Handle name.
    pub name: String,
    /// Resolved value. Confined to the trust boundary.
    pub value: String,
    /// Type label (e.g. `bearer_token`).
    pub cred_type: String,
    /// Rotation version (1 on first write).
    pub version: u32,
    /// Seconds since UNIX epoch.
    pub created_at: f64,
    /// Seconds since UNIX epoch, if this credential has ever been rotated.
    pub rotated_at: Option<f64>,
}

/// Non-secret metadata for a credential (exposed by `metadata()`).
#[derive(Debug, Clone, Serialize)]
pub struct CredentialMetadata {
    /// Handle name.
    pub name: String,
    /// Type label.
    pub cred_type: String,
    /// Rotation version.
    pub version: u32,
    /// Seconds since UNIX epoch.
    pub created_at: f64,
    /// Seconds since UNIX epoch, if rotated.
    pub rotated_at: Option<f64>,
}

/// Opaque handle an agent may reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialHandle {
    /// Handle name.
    pub name: String,
}

impl CredentialHandle {
    /// Return the `{{cred:NAME}}` placeholder for this handle.
    #[must_use]
    pub fn placeholder(&self) -> String {
        format!("{{{{cred:{}}}}}", self.name)
    }
}

/// Per-agent capability binding.
#[derive(Debug, Clone)]
pub struct CredentialProfile {
    /// Agent DID.
    pub agent_did: String,
    bindings: BTreeMap<String, String>,
}

impl CredentialProfile {
    /// Construct a profile mapping action classes to handle names.
    #[must_use]
    pub fn new(agent_did: impl Into<String>, bindings: BTreeMap<String, String>) -> Self {
        Self {
            agent_did: agent_did.into(),
            bindings,
        }
    }

    /// Return the handle name bound to the action class, or `None`.
    #[must_use]
    pub fn capability_for(&self, action_class: &str) -> Option<&str> {
        self.bindings.get(action_class).map(String::as_str)
    }

    /// Read-only view of the bindings.
    #[must_use]
    pub fn bindings(&self) -> &BTreeMap<String, String> {
        &self.bindings
    }
}

/// A single audit record. Contains the agent identity, handle name,
/// target service, action class, decision, and policy version. Does NOT
/// contain the resolved credential value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAuditEvent {
    /// Seconds since UNIX epoch.
    pub timestamp: f64,
    /// Agent DID.
    pub agent_did: String,
    /// Handle name.
    pub handle_name: String,
    /// Downstream service.
    pub target_service: String,
    /// Action class.
    pub action_class: String,
    /// Allow / Deny.
    pub decision: CredentialDecision,
    /// Workflow policy version at decision time.
    pub policy_version: String,
    /// Empty on allow; `DENY_REASON` on deny.
    pub reason: String,
}

/// Deterministic deny output returned in place of a rendered payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DenyReceipt {
    /// Always `credential_denied`.
    pub reason: String,
    /// Action class for which the request was denied.
    pub action_class: String,
    /// Target service for which the request was denied.
    pub target_service: String,
}

impl DenyReceipt {
    fn new(action_class: impl Into<String>, target_service: impl Into<String>) -> Self {
        Self {
            reason: DENY_REASON.to_string(),
            action_class: action_class.into(),
            target_service: target_service.into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PersistPayload {
    records: Vec<CredentialRecord>,
}

/// Encrypted-at-rest credential store and scoped resolver.
pub struct CredentialVault {
    inner: Mutex<VaultInner>,
    persist_path: Option<PathBuf>,
    key: Option<[u8; KEY_LENGTH]>,
}

struct VaultInner {
    records: HashMap<String, CredentialRecord>,
    profiles: HashMap<String, CredentialProfile>,
    audit: Vec<VaultAuditEvent>,
    loaded: bool,
}

impl CredentialVault {
    /// Create an in-memory vault.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VaultInner {
                records: HashMap::new(),
                profiles: HashMap::new(),
                audit: Vec::new(),
                loaded: true, // memory-only is always "loaded"
            }),
            persist_path: None,
            key: None,
        }
    }

    /// Create a vault with encrypted-at-rest persistence.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::BadKeyLength`] if the key is not exactly 32 bytes.
    pub fn with_persistence(
        persist_path: PathBuf,
        encryption_key: &[u8],
    ) -> Result<Self, CredentialError> {
        if encryption_key.len() != KEY_LENGTH {
            return Err(CredentialError::BadKeyLength);
        }
        let mut k = [0u8; KEY_LENGTH];
        k.copy_from_slice(encryption_key);
        let vault = Self {
            inner: Mutex::new(VaultInner {
                records: HashMap::new(),
                profiles: HashMap::new(),
                audit: Vec::new(),
                loaded: false,
            }),
            persist_path: Some(persist_path),
            key: Some(k),
        };
        vault.ensure_loaded()?;
        Ok(vault)
    }

    /// Generate a fresh AES-256-GCM key (32 random bytes).
    #[must_use]
    pub fn generate_key() -> [u8; KEY_LENGTH] {
        let mut k = [0u8; KEY_LENGTH];
        rand::thread_rng().fill_bytes(&mut k);
        k
    }

    // -- Admin surface ------------------------------------------------------

    /// Store or replace a credential.
    ///
    /// # Errors
    ///
    /// - [`CredentialError::InvalidName`] if the name doesn't match the pattern.
    /// - I/O / crypto errors on persistence failure.
    pub fn put(
        &self,
        name: &str,
        value: &str,
        cred_type: &str,
    ) -> Result<CredentialHandle, CredentialError> {
        if !name_re().is_match(name) {
            return Err(CredentialError::InvalidName);
        }
        self.ensure_loaded()?;
        let mut inner = self.inner.lock().unwrap();
        let now = now_seconds();
        let (version, created_at) = match inner.records.get(name) {
            Some(existing) => (existing.version + 1, existing.created_at),
            None => (1, now),
        };
        let record = CredentialRecord {
            name: name.to_string(),
            value: value.to_string(),
            cred_type: cred_type.to_string(),
            version,
            created_at,
            rotated_at: if version > 1 { Some(now) } else { None },
        };
        inner.records.insert(name.to_string(), record);
        self.flush_locked(&inner)?;
        Ok(CredentialHandle {
            name: name.to_string(),
        })
    }

    /// Rotate a credential's value while preserving the handle name.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Unknown`] if the credential does not exist.
    pub fn rotate(&self, name: &str, new_value: &str) -> Result<CredentialHandle, CredentialError> {
        self.ensure_loaded()?;
        let mut inner = self.inner.lock().unwrap();
        let old = inner
            .records
            .get(name)
            .cloned()
            .ok_or_else(|| CredentialError::Unknown(name.to_string()))?;
        inner.records.insert(
            name.to_string(),
            CredentialRecord {
                value: new_value.to_string(),
                version: old.version + 1,
                rotated_at: Some(now_seconds()),
                ..old
            },
        );
        self.flush_locked(&inner)?;
        Ok(CredentialHandle {
            name: name.to_string(),
        })
    }

    /// Delete a credential. Returns `true` if it existed.
    ///
    /// # Errors
    ///
    /// I/O / crypto errors on persistence failure.
    pub fn delete(&self, name: &str) -> Result<bool, CredentialError> {
        self.ensure_loaded()?;
        let mut inner = self.inner.lock().unwrap();
        let present = inner.records.remove(name).is_some();
        if present {
            self.flush_locked(&inner)?;
        }
        Ok(present)
    }

    /// List all credential handle names.
    ///
    /// # Errors
    ///
    /// I/O / crypto errors on lazy-load failure.
    pub fn list_handles(&self) -> Result<Vec<String>, CredentialError> {
        self.ensure_loaded()?;
        let inner = self.inner.lock().unwrap();
        let mut names: Vec<String> = inner.records.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    /// Return non-secret metadata for a credential, or `None`.
    ///
    /// # Errors
    ///
    /// I/O / crypto errors on lazy-load failure.
    pub fn metadata(&self, name: &str) -> Result<Option<CredentialMetadata>, CredentialError> {
        self.ensure_loaded()?;
        let inner = self.inner.lock().unwrap();
        Ok(inner.records.get(name).map(|r| CredentialMetadata {
            name: r.name.clone(),
            cred_type: r.cred_type.clone(),
            version: r.version,
            created_at: r.created_at,
            rotated_at: r.rotated_at,
        }))
    }

    /// Register or replace a per-agent profile.
    pub fn register_profile(&self, profile: CredentialProfile) {
        let mut inner = self.inner.lock().unwrap();
        inner.profiles.insert(profile.agent_did.clone(), profile);
    }

    /// Revoke a profile by agent DID. Returns `true` if it existed.
    pub fn revoke_profile(&self, agent_did: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.profiles.remove(agent_did).is_some()
    }

    // -- Resolver surface ---------------------------------------------------

    /// True iff `agent_did` may use `handle_name` for `action_class`.
    #[must_use]
    pub fn check_access(&self, agent_did: &str, handle_name: &str, action_class: &str) -> bool {
        let inner = self.inner.lock().unwrap();
        Self::check_access_inner(&inner, agent_did, handle_name, action_class)
    }

    fn check_access_inner(
        inner: &VaultInner,
        agent_did: &str,
        handle_name: &str,
        action_class: &str,
    ) -> bool {
        let Some(profile) = inner.profiles.get(agent_did) else {
            return false;
        };
        let Some(bound) = profile.capability_for(action_class) else {
            return false;
        };
        bound == handle_name && inner.records.contains_key(handle_name)
    }

    /// Internal: resolve a credential value and emit an audit event.
    /// Returns `(value, event)`; on deny `value` is `None`.
    fn resolve_internal(
        &self,
        agent_did: &str,
        handle_name: &str,
        action_class: &str,
        target_service: &str,
        policy_version: &str,
    ) -> (Option<String>, VaultAuditEvent) {
        let mut inner = self.inner.lock().unwrap();
        let allowed = Self::check_access_inner(&inner, agent_did, handle_name, action_class);
        if allowed {
            let value = inner.records.get(handle_name).unwrap().value.clone();
            let event = VaultAuditEvent {
                timestamp: now_seconds(),
                agent_did: agent_did.to_string(),
                handle_name: handle_name.to_string(),
                target_service: target_service.to_string(),
                action_class: action_class.to_string(),
                decision: CredentialDecision::Allow,
                policy_version: policy_version.to_string(),
                reason: String::new(),
            };
            inner.audit.push(event.clone());
            (Some(value), event)
        } else {
            let event = VaultAuditEvent {
                timestamp: now_seconds(),
                agent_did: agent_did.to_string(),
                handle_name: handle_name.to_string(),
                target_service: target_service.to_string(),
                action_class: action_class.to_string(),
                decision: CredentialDecision::Deny,
                policy_version: policy_version.to_string(),
                reason: DENY_REASON.to_string(),
            };
            inner.audit.push(event.clone());
            (None, event)
        }
    }

    fn record_reject(&self, event: VaultAuditEvent) {
        let mut inner = self.inner.lock().unwrap();
        inner.audit.push(event);
    }

    /// Snapshot of audit events.
    #[must_use]
    pub fn audit_log(&self) -> Vec<VaultAuditEvent> {
        self.inner.lock().unwrap().audit.clone()
    }

    /// Clear all audit events.
    pub fn clear_audit(&self) {
        self.inner.lock().unwrap().audit.clear();
    }

    // -- Persistence --------------------------------------------------------

    fn ensure_loaded(&self) -> Result<(), CredentialError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.loaded {
            return Ok(());
        }
        inner.loaded = true;
        let (Some(path), Some(key)) = (self.persist_path.as_ref(), self.key.as_ref()) else {
            return Ok(());
        };
        if !path.exists() {
            return Ok(());
        }
        let blob = fs::read(path)?;
        if blob.is_empty() {
            return Ok(());
        }
        let plaintext = decrypt(key, &blob)?;
        let payload: PersistPayload = serde_json::from_slice(&plaintext)?;
        for r in payload.records {
            inner.records.insert(r.name.clone(), r);
        }
        Ok(())
    }

    fn flush_locked(&self, inner: &VaultInner) -> Result<(), CredentialError> {
        let (Some(path), Some(key)) = (self.persist_path.as_ref(), self.key.as_ref()) else {
            return Ok(());
        };
        let payload = PersistPayload {
            records: inner.records.values().cloned().collect(),
        };
        let plaintext = serde_json::to_vec(&payload)?;
        let blob = encrypt(key, &plaintext)?;
        let tmp = path.with_extension("tmp");
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir)?;
            }
        }
        fs::write(&tmp, &blob)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

impl Default for CredentialVault {
    fn default() -> Self {
        Self::new()
    }
}

fn encrypt(key: &[u8; KEY_LENGTH], plaintext: &[u8]) -> Result<Vec<u8>, CredentialError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CredentialError::Crypto(format!("encrypt: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LENGTH + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(key: &[u8; KEY_LENGTH], blob: &[u8]) -> Result<Vec<u8>, CredentialError> {
    if blob.len() < NONCE_LENGTH {
        return Err(CredentialError::Crypto(
            "persisted vault is corrupt (too short)".into(),
        ));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let (nonce_bytes, ct) = blob.split_at(NONCE_LENGTH);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| CredentialError::Crypto(format!("decrypt: {e}")))
}

// ---------------------------------------------------------------------------
// Injector
// ---------------------------------------------------------------------------

/// Information presented to the workflow policy before resolution.
#[derive(Debug, Clone)]
pub struct InjectionContext {
    /// Agent DID.
    pub agent_did: String,
    /// Action class.
    pub action_class: String,
    /// Target downstream service.
    pub target_service: String,
    /// Sorted set of handle names referenced by the payload.
    pub requested_handles: Vec<String>,
    /// Workflow policy version.
    pub policy_version: String,
}

/// Result returned by the workflow policy callback.
#[derive(Debug, Clone)]
pub struct PolicyOutcome {
    /// True to allow, false to deny.
    pub allow: bool,
    /// Optional reason for logging (never surfaced to the agent on deny).
    pub reason: String,
}

impl PolicyOutcome {
    /// Allow.
    #[must_use]
    pub fn allow() -> Self {
        Self {
            allow: true,
            reason: String::new(),
        }
    }

    /// Deny with reason (kept in audit log only).
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            reason: reason.into(),
        }
    }
}

/// Outcome of an injection call.
#[derive(Debug, Clone)]
pub struct InjectionResult {
    /// True if the payload was rendered with all placeholders replaced.
    pub allowed: bool,
    /// On allow: a JSON value with placeholders replaced. On deny: `null`.
    pub payload: Option<serde_json::Value>,
    /// On deny: the deterministic deny receipt.
    pub deny_receipt: Option<DenyReceipt>,
    /// Audit events emitted by this call.
    pub audit_events: Vec<VaultAuditEvent>,
}

/// Workflow-policy callback type.
pub type PolicyCheck<'a> = Box<dyn Fn(&InjectionContext) -> PolicyOutcome + Send + Sync + 'a>;

/// Options for an injection call.
pub struct InjectionOptions<'a> {
    /// Action class.
    pub action_class: &'a str,
    /// Target downstream service.
    pub target_service: &'a str,
    /// Workflow-policy allowlist of handle names eligible for substitution.
    pub allowed_handles: &'a [&'a str],
    /// Workflow policy version (recorded in audit).
    pub policy_version: &'a str,
    /// Optional policy callback. Invoked BEFORE any vault read.
    pub policy_check: Option<PolicyCheck<'a>>,
}

impl<'a> InjectionOptions<'a> {
    /// Construct minimal options.
    #[must_use]
    pub fn new(
        action_class: &'a str,
        target_service: &'a str,
        allowed_handles: &'a [&'a str],
    ) -> Self {
        Self {
            action_class,
            target_service,
            allowed_handles,
            policy_version: "v0",
            policy_check: None,
        }
    }
}

/// Renders `{{cred:NAME}}` placeholders into JSON-shaped payloads.
///
/// The injector is the only component that ever holds resolved credential
/// values, and only long enough to render an outbound payload.
pub struct CredentialInjector<'v> {
    vault: &'v CredentialVault,
}

impl<'v> CredentialInjector<'v> {
    /// Construct an injector backed by the given vault.
    #[must_use]
    pub fn new(vault: &'v CredentialVault) -> Self {
        Self { vault }
    }

    /// Inject placeholders in an HTTP header map.
    pub fn inject_headers(
        &self,
        agent_did: &str,
        headers: &HashMap<String, String>,
        options: &InjectionOptions<'_>,
    ) -> InjectionResult {
        let payload = serde_json::to_value(headers).unwrap_or(serde_json::Value::Null);
        self.inject(agent_did, payload, options)
    }

    /// Inject placeholders in MCP tool arguments (nested JSON).
    pub fn inject_tool_args(
        &self,
        agent_did: &str,
        args: serde_json::Value,
        options: &InjectionOptions<'_>,
    ) -> InjectionResult {
        self.inject(agent_did, args, options)
    }

    /// Inject placeholders in a subprocess environment map.
    pub fn inject_env(
        &self,
        agent_did: &str,
        env: &HashMap<String, String>,
        options: &InjectionOptions<'_>,
    ) -> InjectionResult {
        let payload = serde_json::to_value(env).unwrap_or(serde_json::Value::Null);
        self.inject(agent_did, payload, options)
    }

    fn inject(
        &self,
        agent_did: &str,
        payload: serde_json::Value,
        options: &InjectionOptions<'_>,
    ) -> InjectionResult {
        let allowlist: BTreeSet<&str> = options.allowed_handles.iter().copied().collect();
        let requested = collect_placeholders(&payload);

        // 1. Reject anything outside the workflow-supplied allowlist.
        let outside: Vec<&String> = requested.iter().filter(|n| !allowlist.contains(n.as_str())).collect();
        if !outside.is_empty() {
            let event = VaultAuditEvent {
                timestamp: now_seconds(),
                agent_did: agent_did.to_string(),
                handle_name: outside[0].clone(),
                target_service: options.target_service.to_string(),
                action_class: options.action_class.to_string(),
                decision: CredentialDecision::Deny,
                policy_version: options.policy_version.to_string(),
                reason: DENY_REASON.to_string(),
            };
            self.vault.record_reject(event.clone());
            let receipt = DenyReceipt::new(options.action_class, options.target_service);
            return InjectionResult {
                allowed: false,
                payload: None,
                deny_receipt: Some(receipt),
                audit_events: vec![event],
            };
        }

        // 2. Run policy BEFORE any vault read.
        if let Some(check) = &options.policy_check {
            let ctx = InjectionContext {
                agent_did: agent_did.to_string(),
                action_class: options.action_class.to_string(),
                target_service: options.target_service.to_string(),
                requested_handles: requested.iter().cloned().collect(),
                policy_version: options.policy_version.to_string(),
            };
            let outcome = check(&ctx);
            if !outcome.allow {
                let event = VaultAuditEvent {
                    timestamp: now_seconds(),
                    agent_did: agent_did.to_string(),
                    handle_name: requested.iter().next().cloned().unwrap_or_default(),
                    target_service: options.target_service.to_string(),
                    action_class: options.action_class.to_string(),
                    decision: CredentialDecision::Deny,
                    policy_version: options.policy_version.to_string(),
                    reason: DENY_REASON.to_string(),
                };
                self.vault.record_reject(event.clone());
                let receipt = DenyReceipt::new(options.action_class, options.target_service);
                return InjectionResult {
                    allowed: false,
                    payload: None,
                    deny_receipt: Some(receipt),
                    audit_events: vec![event],
                };
            }
        }

        // 3. Resolve. Any single deny aborts the whole call.
        let mut resolved: HashMap<String, String> = HashMap::new();
        let mut events: Vec<VaultAuditEvent> = Vec::new();
        for name in &requested {
            let (value, ev) = self.vault.resolve_internal(
                agent_did,
                name,
                options.action_class,
                options.target_service,
                options.policy_version,
            );
            events.push(ev);
            match value {
                Some(v) => {
                    resolved.insert(name.clone(), v);
                }
                None => {
                    let receipt = DenyReceipt::new(options.action_class, options.target_service);
                    return InjectionResult {
                        allowed: false,
                        payload: None,
                        deny_receipt: Some(receipt),
                        audit_events: events,
                    };
                }
            }
        }

        let rendered = substitute(payload, &resolved);
        InjectionResult {
            allowed: true,
            payload: Some(rendered),
            deny_receipt: None,
            audit_events: events,
        }
    }
}

fn collect_placeholders(payload: &serde_json::Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    walk(payload, &mut |s| {
        for cap in placeholder_re().captures_iter(s) {
            out.insert(cap[1].to_string());
        }
    });
    out
}

fn walk<F: FnMut(&str)>(payload: &serde_json::Value, visit: &mut F) {
    match payload {
        serde_json::Value::String(s) => visit(s),
        serde_json::Value::Array(arr) => {
            for v in arr {
                walk(v, visit);
            }
        }
        serde_json::Value::Object(obj) => {
            for (k, v) in obj {
                visit(k);
                walk(v, visit);
            }
        }
        _ => {}
    }
}

fn substitute(payload: serde_json::Value, resolved: &HashMap<String, String>) -> serde_json::Value {
    map_strings(payload, &|s| {
        placeholder_re()
            .replace_all(s, |caps: &regex::Captures<'_>| {
                resolved
                    .get(&caps[1])
                    .cloned()
                    .unwrap_or_else(|| caps[0].to_string())
            })
            .to_string()
    })
}

fn map_strings<F: Fn(&str) -> String>(
    payload: serde_json::Value,
    fn_: &F,
) -> serde_json::Value {
    match payload {
        serde_json::Value::String(s) => serde_json::Value::String(fn_(&s)),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(|v| map_strings(v, fn_)).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut out = serde_json::Map::new();
            for (k, v) in obj {
                out.insert(fn_(&k), map_strings(v, fn_));
            }
            serde_json::Value::Object(out)
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Audit-log integrity helper
// ---------------------------------------------------------------------------

/// Stable HMAC-SHA256 digest of an audit-event sequence.
///
/// The digest covers handle names and decisions but never references
/// resolved credential values.
#[must_use]
pub fn audit_digest(events: &[VaultAuditEvent], key: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    for ev in events {
        let json = serde_json::to_vec(ev).unwrap_or_default();
        mac.update(&json);
        mac.update(&[0x1fu8]);
    }
    let bytes = mac.finalize().into_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes.iter() {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}
