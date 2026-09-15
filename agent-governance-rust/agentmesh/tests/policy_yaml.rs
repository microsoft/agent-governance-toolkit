// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use agentmesh::policy_data::Context;
use agentmesh::{
    AgentMeshClient, ClientOptions, PolicyDecision, PolicyEngine, PolicyError,
    PromptInjectionDetector,
};
use serde_json::json;

fn policy(conditions: &str) -> String {
    format!(
        "version: \"1\"\nagent: test\npolicies:\n- name: gate\n  type: capability\n  denied_actions: [\"*\"]\n  conditions:\n{conditions}\n"
    )
}

fn context(value: serde_json::Value) -> Context {
    serde_json::from_value(value).unwrap()
}

#[test]
fn yaml_and_json_policies_make_the_same_authorization_decisions() {
    let json_policy = json!({
        "version": "1", "agent": "test", "policies": [{
            "name": "gate", "type": "capability", "denied_actions": ["*"],
            "conditions": {"environment": ["prod", "staging"]}
        }]
    });
    for source in [
        policy("    environment: [prod, staging]"),
        json_policy.to_string(),
    ] {
        let client = AgentMeshClient::with_options(
            "yaml-test",
            ClientOptions {
                policy_yaml: Some(source),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            !client
                .execute_with_governance("deploy", Some(&context(json!({"environment": "prod"}))))
                .allowed
        );
        assert!(
            client
                .execute_with_governance("deploy", Some(&context(json!({"environment": "dev"}))))
                .allowed
        );
    }
}

#[test]
fn aliases_nested_values_and_literal_merge_keys_preserve_matching() {
    let engine = PolicyEngine::new();
    engine
        .load_from_yaml(&policy(
            "    original: &data {name: prod, flags: [true, null, 7, 1.5]}\n    copy: *data\n    scope: {<<: {tenant: prod}}",
        ))
        .unwrap();
    let data = json!({"name": "prod", "flags": [true, null, 7, 1.5]});
    let ctx = context(json!({
        "original": data, "copy": data, "scope": {"<<": {"tenant": "prod"}}
    }));
    assert!(matches!(
        engine.evaluate("deploy", Some(&ctx)),
        PolicyDecision::Deny(_)
    ));
    let mut changed = ctx;
    changed.insert("scope".into(), json!({"tenant": "prod"}));
    assert_eq!(
        engine.evaluate("deploy", Some(&changed)),
        PolicyDecision::Allow
    );
}

#[test]
fn scalar_types_and_case_are_not_coerced_during_matching() {
    for (yaml, matching, different) in [
        ("true", json!(true), json!("true")),
        ("7", json!(7), json!(7.0)),
        ("7.0", json!(7.0), json!(7)),
        ("null", json!(null), json!("null")),
        ("\"yes\"", json!("yes"), json!(true)),
        ("yes", json!("yes"), json!(true)),
        ("on", json!("on"), json!(true)),
        ("0x10", json!(16), json!("0x10")),
        ("DROP", json!("DROP"), json!("drop")),
        ("!!str 7", json!("7"), json!(7)),
    ] {
        let engine = PolicyEngine::new();
        engine
            .load_from_yaml(&policy(&format!("    value: {yaml}")))
            .unwrap();
        assert!(matches!(
            engine.evaluate("run", Some(&context(json!({"value": matching})))),
            PolicyDecision::Deny(_)
        ));
        assert_eq!(
            engine.evaluate("run", Some(&context(json!({"value": different})))),
            PolicyDecision::Allow
        );
    }
}

#[test]
fn unsupported_values_and_ambiguous_maps_are_errors_not_default_policies() {
    for conditions in [
        "    value: .nan",
        "    value: .inf",
        "    value: !custom prod",
        "    value: {1: prod}",
        "    value: {true: prod}",
        "    value: {[a, b]: prod}",
        "    value: {nested: !custom prod}",
        "    value: {key: one, key: two}",
        "    value: prod\n    value: dev",
    ] {
        let source = policy(conditions);
        let engine = PolicyEngine::new();
        assert!(
            matches!(
                engine.load_from_yaml(&source),
                Err(PolicyError::InvalidYaml(_))
            ),
            "accepted {conditions}"
        );
        assert!(!engine.is_loaded());
        assert!(AgentMeshClient::with_options(
            "yaml-test",
            ClientOptions {
                policy_yaml: Some(source),
                ..Default::default()
            },
        )
        .is_err());
    }
}

#[test]
fn invalid_reload_keeps_the_previous_deny_policy() {
    let source = policy("    environment: prod");
    let engine = PolicyEngine::new();
    engine.load_from_yaml(&source).unwrap();
    for invalid in [
        String::new(),
        "{{invalid".into(),
        "[]".into(),
        format!("{source}\n---\n{source}"),
        source.replace("version: \"1\"", "version: \"1\"\nversion: \"2\""),
        source.replace(
            "type: capability",
            "type: rate_limit\n  max_calls: 1\n  window: broken",
        ),
    ] {
        assert!(engine.load_from_yaml(&invalid).is_err());
        assert!(matches!(
            engine.evaluate("run", Some(&context(json!({"environment": "prod"})))),
            PolicyDecision::Deny(_)
        ));
    }
}

#[test]
fn parser_errors_retain_locations_without_source_snippets() {
    let engine = PolicyEngine::new();
    let Err(PolicyError::InvalidYaml(error)) =
        engine.load_from_yaml("version: \"1\"\nagent: [ # SECRET_SENTINEL\n")
    else {
        panic!("expected a parse error");
    };
    assert!(error.location().is_some());
    assert!(!error.to_string().contains("SECRET_SENTINEL"));
}

#[test]
fn source_depth_nodes_and_alias_expansion_are_bounded() {
    let mut aliases = String::from("    a0: &a0 [x, x]\n");
    for i in 1..20 {
        aliases.push_str(&format!("    a{i}: &a{i} [*a{}, *a{}]\n", i - 1, i - 1));
    }
    for source in [
        " ".repeat(1_048_577),
        policy(&format!("    value: {}0{}", "[".repeat(70), "]".repeat(70))),
        policy(&format!("    value: [{}]", vec!["null"; 100_001].join(","))),
        policy(&aliases),
    ] {
        assert!(PolicyEngine::new().load_from_yaml(&source).is_err());
    }
}

#[test]
fn oversized_files_and_detector_configs_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, " ".repeat(1_048_577)).unwrap();
    assert!(PolicyEngine::new()
        .load_from_file(path.to_str().unwrap())
        .is_err());
    assert!(PromptInjectionDetector::from_yaml_file(&path).is_err());
    assert!(PromptInjectionDetector::from_yaml_str("detection: !custom {}").is_err());
}
