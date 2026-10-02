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
fn typed_strings_require_quotes_for_number_boolean_and_null_scalars() {
    let source = policy("    environment: prod");
    for (field, scalar, kind) in [
        ("version: \"1\"", "version: 1", "integer"),
        ("version: \"1\"", "version: 1.0", "floating point"),
        ("agent: test", "agent: 7", "integer"),
        ("name: gate", "name: TRUE", "boolean"),
        ("agent: test", "agent: null", "null"),
        ("agent: test", "agent:", "null"),
    ] {
        let engine = PolicyEngine::new();
        let error = engine
            .load_from_yaml(&source.replace(field, scalar))
            .unwrap_err()
            .to_string();
        assert!(error.contains(&format!("invalid type: {kind}")), "{error}");
        assert!(error.contains("expected a string"), "{error}");
        assert!(!engine.is_loaded());
    }
    for scalar in ["\"1\"", "\"1.0\"", "\"TRUE\"", "\"null\""] {
        assert!(PolicyEngine::new()
            .load_from_yaml(&source.replace("version: \"1\"", &format!("version: {scalar}")))
            .is_ok());
    }
}

#[test]
fn mapping_colon_tabs_preserve_policy_conditions() {
    for (conditions, value) in [
        ("    value:\tprod", json!("prod")),
        ("    value:\t7", json!(7)),
        ("    value: {nested:\tprod}", json!({"nested": "prod"})),
        ("    value:\n      nested:\tprod", json!({"nested": "prod"})),
    ] {
        let engine = PolicyEngine::new();
        engine.load_from_yaml(&policy(conditions)).unwrap();
        assert!(matches!(
            engine.evaluate("deploy", Some(&context(json!({"value": value})))),
            PolicyDecision::Deny(_)
        ));
    }
    assert!(PolicyEngine::new()
        .load_from_yaml(&policy("    value:\n\t nested: prod"))
        .is_err());
}

#[test]
fn documented_parser_relaxations_preserve_deny_decisions() {
    let source = policy("    value: {b: c}");
    for input in [
        format!("%FOO bar\n---\n{source}"),
        source.replace("- name: gate", "-\tname: gate"),
        source.replace("    value: {b: c}", "    value:\n     \tb: c"),
        format!("{source}\n{}", "#\n".repeat(301_000)),
    ] {
        let engine = PolicyEngine::new();
        engine.load_from_yaml(&input).unwrap();
        assert!(matches!(
            engine.evaluate("deploy", Some(&context(json!({"value": {"b": "c"}})))),
            PolicyDecision::Deny(_)
        ));
    }
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
            "    original: &data {name: prod, flags: [true, null, 7, 1.5]}\n    copy: *data\n    scope: {<<: {tenant: prod}}\n    flag: !!bool &flag \"TRUE\"\n    copied_flag: *flag",
        ))
        .unwrap();
    let data = json!({"name": "prod", "flags": [true, null, 7, 1.5]});
    let ctx = context(json!({
        "original": data, "copy": data, "scope": {"<<": {"tenant": "prod"}},
        "flag": true, "copied_flag": true
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
fn tagged_boolean_blocks_keep_deny_conditions_and_siblings() {
    for header in [
        "!!bool |-",
        "!!bool &flag |- # comment with >",
        "&flag !!bool >-",
    ] {
        let mut conditions = format!("    value: {header}\n      TRUE\n    required: true");
        if header.contains("&flag") {
            conditions.push_str("\n    copy: *flag");
        }
        let engine = PolicyEngine::new();
        engine.load_from_yaml(&policy(&conditions)).unwrap();
        let ctx = context(json!({"value": true, "required": true, "copy": true}));
        assert!(
            matches!(engine.evaluate("run", Some(&ctx)), PolicyDecision::Deny(_)),
            "{header}"
        );
        let ctx = context(json!({"value": true, "required": false, "copy": true}));
        assert_eq!(
            engine.evaluate("run", Some(&ctx)),
            PolicyDecision::Allow,
            "{header}"
        );
    }
}

#[test]
fn scalar_types_and_case_are_not_coerced_during_matching() {
    for (yaml, matching, different) in [
        ("true", json!(true), json!("true")),
        ("True", json!(true), json!("True")),
        ("FALSE", json!(false), json!("FALSE")),
        ("tRuE", json!("tRuE"), json!(true)),
        ("!!bool TRUE", json!(true), json!("TRUE")),
        ("!!bool \"TRUE\"", json!(true), json!("TRUE")),
        ("!!str True", json!("True"), json!(true)),
        ("!!str null", json!("null"), json!(null)),
        ("!!str", json!(""), json!(null)),
        ("!!int \"7\"", json!(7), json!("7")),
        ("!!float \"7\"", json!(7.0), json!(7)),
        ("!!null NULL", json!(null), json!("NULL")),
        ("nUlL", json!("nUlL"), json!(null)),
        ("7", json!(7), json!(7.0)),
        ("7.0", json!(7.0), json!(7)),
        ("null", json!(null), json!("null")),
        ("\"yes\"", json!("yes"), json!(true)),
        ("yes", json!("yes"), json!(true)),
        ("on", json!("on"), json!(true)),
        ("0x10", json!(16), json!("0x10")),
        ("010", json!("010"), json!(10)),
        ("1_000", json!("1_000"), json!(1000)),
        ("-010", json!("-010"), json!(-10)),
        ("0X10", json!("0X10"), json!(16)),
        (
            "18446744073709551615",
            json!(u64::MAX),
            json!("18446744073709551615"),
        ),
        ("-9223372036854775808", json!(i64::MIN), json!(0)),
        ("DROP", json!("DROP"), json!("drop")),
        ("!!str 7", json!("7"), json!(7)),
    ] {
        let engine = PolicyEngine::new();
        engine
            .load_from_yaml(&policy(&format!("    value: {yaml}")))
            .unwrap_or_else(|error| panic!("{yaml}: {error}"));
        assert!(
            matches!(
                engine.evaluate("run", Some(&context(json!({"value": matching})))),
                PolicyDecision::Deny(_)
            ),
            "{yaml}"
        );
        assert_eq!(
            engine.evaluate("run", Some(&context(json!({"value": different})))),
            PolicyDecision::Allow
        );
    }
}

#[test]
fn legacy_numeric_limits_are_rejected_instead_of_enabling_a_rule() {
    for scalar in ["010", "1_000", "1:2:3"] {
        let source = format!(
            "version: \"1\"\nagent: test\npolicies:\n- name: rate\n  type: rate_limit\n  max_calls: {scalar}\n  window: 1m\n  actions: [\"*\"]\n"
        );
        assert!(PolicyEngine::new().load_from_yaml(&source).is_err());
    }
}

#[test]
fn unsupported_values_and_ambiguous_maps_are_errors_not_default_policies() {
    for conditions in [
        "    value: .nan",
        "    value: .inf",
        "    value: 18446744073709551616",
        "    value: -9223372036854775809",
        "    value: 0x10000000000000000",
        "    value: !!bool null",
        "    value: !!int null",
        "    value: !!null garbage",
        "    value: !custom null",
        "    value: !!float null",
        "    value: !!int \"1_000\"",
        "    value: !!bool \"tRuE\"",
        "    value: !custom prod",
        "    value: ! 7",
        "    value: ! {a: 1}",
        "    value: ! [1, 2]",
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
        "[\"1\", test, []]".into(),
        "version: \"1\"\nagent: test\npolicies: [[deny, capability, [], [], [\"*\"]]]".into(),
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
    for source in [
        "[]",
        "detection: []",
        "detection: {rule_overrides: {add: [[direct, name, pattern, high, 0.9]]}}",
        "detection: {threshold_overrides: {strict: [low, 0.1]}}",
    ] {
        assert!(
            PromptInjectionDetector::from_yaml_str(source).is_err(),
            "accepted positional config: {source}"
        );
    }
}
