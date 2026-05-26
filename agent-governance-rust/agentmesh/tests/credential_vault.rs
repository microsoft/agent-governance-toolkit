// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use agentmesh::credential_vault::{
    audit_digest, CredentialDecision, CredentialInjector, CredentialProfile, CredentialVault,
    InjectionContext, InjectionOptions, PolicyOutcome, DENY_REASON,
};

fn make_stack() -> CredentialVault {
    let v = CredentialVault::new();
    v.put("github_pat", "GHP-RESOLVED-VALUE", "bearer_token").unwrap();
    v.put("db_password", "DBP-VALUE", "password").unwrap();
    let mut ci = BTreeMap::new();
    ci.insert("github:read_issues".to_string(), "github_pat".to_string());
    ci.insert("github:push_code".to_string(), "github_pat".to_string());
    v.register_profile(CredentialProfile::new("did:web:agent-ci", ci));
    let mut an = BTreeMap::new();
    an.insert("db:query".to_string(), "db_password".to_string());
    v.register_profile(CredentialProfile::new("did:web:agent-analytics", an));
    v
}

#[test]
fn put_returns_handle_with_placeholder() {
    let v = CredentialVault::new();
    let h = v.put("k1", "v1", "secret").unwrap();
    assert_eq!(h.name, "k1");
    assert_eq!(h.placeholder(), "{{cred:k1}}");
}

#[test]
fn put_rejects_bad_names() {
    let v = CredentialVault::new();
    assert!(v.put("", "v", "secret").is_err());
    assert!(v.put("bad name", "v", "secret").is_err());
    assert!(v.put(&"a".repeat(200), "v", "secret").is_err());
}

#[test]
fn list_handles_no_value_leak() {
    let v = make_stack();
    let names = v.list_handles().unwrap();
    assert_eq!(names, vec!["db_password".to_string(), "github_pat".to_string()]);
    for n in &names {
        let meta = v.metadata(n).unwrap().unwrap();
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("GHP-RESOLVED-VALUE"));
        assert!(!json.contains("value"));
    }
}

#[test]
fn rotate_preserves_handle_bumps_version() {
    let v = make_stack();
    let before = v.metadata("github_pat").unwrap().unwrap();
    assert_eq!(before.version, 1);
    let h = v.rotate("github_pat", "ghp_new").unwrap();
    let after = v.metadata("github_pat").unwrap().unwrap();
    assert_eq!(h.name, "github_pat");
    assert_eq!(after.version, 2);
    assert!(after.rotated_at.is_some());
}

#[test]
fn rotate_unknown_errors() {
    let v = make_stack();
    assert!(v.rotate("nope", "x").is_err());
}

#[test]
fn delete_returns_presence_flag() {
    let v = make_stack();
    assert!(v.delete("db_password").unwrap());
    assert!(!v.delete("db_password").unwrap());
}

#[test]
fn check_access_allows_bound_action() {
    let v = make_stack();
    assert!(v.check_access("did:web:agent-ci", "github_pat", "github:read_issues"));
}

#[test]
fn check_access_denies_unknown_agent() {
    let v = make_stack();
    assert!(!v.check_access("did:web:rogue", "github_pat", "github:read_issues"));
}

#[test]
fn check_access_denies_unbound_action() {
    let v = make_stack();
    assert!(!v.check_access("did:web:agent-ci", "db_password", "db:query"));
}

#[test]
fn check_access_denies_cross_action_reuse() {
    let v = make_stack();
    assert!(!v.check_access("did:web:agent-analytics", "db_password", "db:admin"));
}

#[test]
fn inject_headers_happy_path() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer {{cred:github_pat}}".to_string(),
    );
    headers.insert("Accept".to_string(), "application/json".to_string());
    let opts = InjectionOptions {
        action_class: "github:read_issues",
        target_service: "api.github.com",
        allowed_handles: &["github_pat"],
        policy_version: "v1",
        policy_check: None,
    };
    let r = injector.inject_headers("did:web:agent-ci", &headers, &opts);
    assert!(r.allowed);
    let p = r.payload.unwrap();
    assert_eq!(
        p.get("Authorization").and_then(|v| v.as_str()),
        Some("Bearer GHP-RESOLVED-VALUE")
    );
    assert!(r.deny_receipt.is_none());
    assert_eq!(r.audit_events.len(), 1);
    assert_eq!(r.audit_events[0].decision, CredentialDecision::Allow);
}

#[test]
fn inject_tool_args_nested() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);
    let args = serde_json::json!({
        "repo": "octo/hello",
        "secrets": ["{{cred:github_pat}}", "literal"],
        "nested": { "token": "{{cred:github_pat}}" }
    });
    let opts = InjectionOptions::new("github:push_code", "api.github.com", &["github_pat"]);
    let r = injector.inject_tool_args("did:web:agent-ci", args, &opts);
    assert!(r.allowed);
    let p = r.payload.unwrap();
    assert_eq!(
        p["secrets"][0].as_str(),
        Some("GHP-RESOLVED-VALUE")
    );
    assert_eq!(
        p["nested"]["token"].as_str(),
        Some("GHP-RESOLVED-VALUE")
    );
}

#[test]
fn inject_env_renders_values() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);
    let mut env = HashMap::new();
    env.insert("PATH".to_string(), "/usr/bin".to_string());
    env.insert("GITHUB_TOKEN".to_string(), "{{cred:github_pat}}".to_string());
    let opts = InjectionOptions::new("github:read_issues", "subprocess", &["github_pat"]);
    let r = injector.inject_env("did:web:agent-ci", &env, &opts);
    assert!(r.allowed);
    let p = r.payload.unwrap();
    assert_eq!(p["GITHUB_TOKEN"].as_str(), Some("GHP-RESOLVED-VALUE"));
}

#[test]
fn unauthorized_placeholder_denies_whole_call() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);
    let args = serde_json::json!({"sql": "SELECT 1", "auth": "{{cred:github_pat}}"});
    let opts = InjectionOptions::new("db:query", "pg", &["db_password"]);
    let r = injector.inject_tool_args("did:web:agent-analytics", args, &opts);
    assert!(!r.allowed);
    assert_eq!(r.deny_receipt.as_ref().unwrap().reason, DENY_REASON);
}

#[test]
fn missing_and_out_of_scope_return_identical_deny() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);

    let mut h1 = HashMap::new();
    h1.insert("X".to_string(), "{{cred:does_not_exist}}".to_string());
    let opts1 = InjectionOptions::new("github:read_issues", "svc", &["does_not_exist"]);
    let missing = injector.inject_headers("did:web:agent-ci", &h1, &opts1);

    let mut h2 = HashMap::new();
    h2.insert("X".to_string(), "{{cred:db_password}}".to_string());
    let opts2 = InjectionOptions::new("github:read_issues", "svc", &["db_password"]);
    let out_of_scope = injector.inject_headers("did:web:agent-ci", &h2, &opts2);

    assert!(!missing.allowed);
    assert!(!out_of_scope.allowed);
    assert_eq!(missing.deny_receipt, out_of_scope.deny_receipt);
}

#[test]
fn policy_runs_before_vault_read() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);
    let seen: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let opts = InjectionOptions {
        action_class: "github:push_code",
        target_service: "api.github.com",
        allowed_handles: &["github_pat"],
        policy_version: "v7",
        policy_check: Some(Box::new(|ctx: &InjectionContext| {
            seen.lock().unwrap().extend(ctx.requested_handles.clone());
            PolicyOutcome::deny("workflow denied")
        })),
    };
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer {{cred:github_pat}}".to_string(),
    );
    let r = injector.inject_headers("did:web:agent-ci", &headers, &opts);
    assert!(!r.allowed);
    let seen_vec = seen.lock().unwrap().clone();
    assert_eq!(seen_vec, vec!["github_pat".to_string()]);
}

#[test]
fn same_deny_across_surfaces() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);
    let opts = InjectionOptions::new("db:query", "svc", &["github_pat"]);

    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "{{cred:github_pat}}".to_string(),
    );
    let h = injector.inject_headers("did:web:agent-analytics", &headers, &opts);

    let args = serde_json::json!({"x": "{{cred:github_pat}}"});
    let a = injector.inject_tool_args("did:web:agent-analytics", args, &opts);

    let mut env = HashMap::new();
    env.insert("TOKEN".to_string(), "{{cred:github_pat}}".to_string());
    let e = injector.inject_env("did:web:agent-analytics", &env, &opts);

    for r in [&h, &a, &e] {
        assert!(!r.allowed);
        assert_eq!(r.deny_receipt.as_ref().unwrap().reason, DENY_REASON);
    }
}

#[test]
fn payload_without_placeholders_passes_through() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);
    let mut headers = HashMap::new();
    headers.insert("Accept".to_string(), "application/json".to_string());
    let opts = InjectionOptions::new("github:read_issues", "svc", &[]);
    let r = injector.inject_headers("did:web:agent-ci", &headers, &opts);
    assert!(r.allowed);
}

#[test]
fn audit_records_no_value_leak() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer {{cred:github_pat}}".to_string(),
    );
    let opts = InjectionOptions::new("github:read_issues", "svc", &["github_pat"]);
    let _ = injector.inject_headers("did:web:agent-ci", &headers, &opts);
    let events = v.audit_log();
    let json = serde_json::to_string(&events).unwrap();
    assert!(!json.contains("GHP-RESOLVED-VALUE"));
}

#[test]
fn audit_digest_stable_and_key_dependent() {
    let v = make_stack();
    let injector = CredentialInjector::new(&v);
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer {{cred:github_pat}}".to_string(),
    );
    let opts = InjectionOptions::new("github:read_issues", "svc", &["github_pat"]);
    let _ = injector.inject_headers("did:web:agent-ci", &headers, &opts);
    let events = v.audit_log();
    assert_eq!(audit_digest(&events, b"k"), audit_digest(&events, b"k"));
    assert_ne!(audit_digest(&events, b"k"), audit_digest(&events, b"other"));
}

#[test]
fn rotation_does_not_require_prompt_changes() {
    let v = CredentialVault::new();
    v.put("github_pat", "GHP-V1", "secret").unwrap();
    let mut bindings = BTreeMap::new();
    bindings.insert("github:read_issues".to_string(), "github_pat".to_string());
    v.register_profile(CredentialProfile::new("did:web:agent-ci", bindings));
    let injector = CredentialInjector::new(&v);
    let mut saved = HashMap::new();
    saved.insert(
        "Authorization".to_string(),
        "Bearer {{cred:github_pat}}".to_string(),
    );
    let opts = InjectionOptions::new("github:read_issues", "svc", &["github_pat"]);

    let before = injector.inject_headers("did:web:agent-ci", &saved, &opts);
    assert_eq!(
        before.payload.unwrap()["Authorization"].as_str(),
        Some("Bearer GHP-V1")
    );

    v.rotate("github_pat", "GHP-V2").unwrap();

    let after = injector.inject_headers("did:web:agent-ci", &saved, &opts);
    assert_eq!(
        after.payload.unwrap()["Authorization"].as_str(),
        Some("Bearer GHP-V2")
    );
}

#[test]
fn encrypted_persistence_round_trip() {
    let key = CredentialVault::generate_key();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.bin");
    let secret = "distinctive rotated fixture not a real key"; // gitleaks:allow

    let v1 = CredentialVault::with_persistence(path.clone(), &key).unwrap();
    v1.put("k", "original", "secret").unwrap();
    v1.rotate("k", secret).unwrap();
    drop(v1);

    let blob = std::fs::read(&path).unwrap();
    assert!(!blob.windows(secret.len()).any(|w| w == secret.as_bytes()));
    assert!(!blob.windows(7).any(|w| w == b"\"value\""));

    let v2 = CredentialVault::with_persistence(path, &key).unwrap();
    assert_eq!(v2.list_handles().unwrap(), vec!["k".to_string()]);
    let meta = v2.metadata("k").unwrap().unwrap();
    assert_eq!(meta.version, 2);
}

#[test]
fn persistence_requires_correct_key_length() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.bin");
    assert!(CredentialVault::with_persistence(path, &[0u8; 16]).is_err());
}
