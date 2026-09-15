// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use agent_control_specification_core::{
    parse_manifest_yaml_value, validate_manifest_yaml, RuntimeError,
};
use serde_json::json;

#[test]
fn json_compatible_values_aliases_and_literal_merge_keys_survive() {
    let value = parse_manifest_yaml_value(
        "first: &data {values: [null, true, 7, 1.5, \"7\"]}\nsecond: *data\nliteral: {<<: {key: value}}",
    )
    .unwrap();
    assert_eq!(value["first"], value["second"]);
    assert_eq!(value["first"]["values"], json!([null, true, 7, 1.5, "7"]));
    assert_eq!(value["literal"], json!({"<<": {"key": "value"}}));
    assert_eq!(
        parse_manifest_yaml_value(&value.to_string()).unwrap(),
        value
    );
}

#[test]
fn invalid_or_non_json_yaml_is_rejected_with_manifest_errors() {
    for input in [
        "",
        " \n ",
        "{bad",
        "key: one\nkey: two",
        "nested: {key: one, key: two}",
        "1: value",
        "nested: {false: value}",
        "nested: {[a, b]: value}",
        "nested: !custom value",
        "number: .nan",
        "number: .inf",
        "number: 18446744073709551616",
        "number: -9223372036854775809",
        "number: 0x10000000000000000",
        "value: !!bool null",
        "value: !!int null",
        "value: !!float null",
        "value: !!null garbage",
        "value: !custom null",
        "first: document\n---\nsecond: document",
    ] {
        assert!(
            matches!(
                parse_manifest_yaml_value(input),
                Err(RuntimeError::ManifestInvalid(_))
            ),
            "accepted {input}"
        );
    }
    assert!(validate_manifest_yaml("").is_err());
    assert!(validate_manifest_yaml("[]").is_err());
}

#[test]
fn source_and_expanded_byte_budgets_remain_enforced() {
    assert!(matches!(
        parse_manifest_yaml_value(&" ".repeat(1_048_577)),
        Err(RuntimeError::ResourceLimitExceeded(_))
    ));
    // Escaping these characters fits the input cap but exceeds serialized JSON size.
    let escaped = format!("value: \"{}\"", "\\0".repeat(180_000));
    assert!(matches!(
        parse_manifest_yaml_value(&escaped),
        Err(RuntimeError::ResourceLimitExceeded(_))
    ));
}

#[test]
fn implicit_numeric_strings_retain_their_type_in_keys_values_and_aliases() {
    let value = parse_manifest_yaml_value(
        "010: &digits 010\nseparated: 1_000\ncopy: *digits\nsigned: -010\n\
         literal: '1_000'\nexplicit: !!str 010\nbinary: 0b1010\noctal: 0o12\nhex: 0xA\n\
         unicode: é\nupper: 0X10\nnested: [010, {value: 1_000}]\n\
         booleans: [True, TRUE, False, FALSE, tRuE, !!bool TRUE, !!str TRUE, !!bool \"FALSE\"]\n\
         tagged: [!!str null, !!int \"7\", !!float \"7\", !!null NULL, nUlL]\n# ignored: 1_000\n",
    )
    .unwrap();
    assert_eq!(value["010"], "010");
    assert_eq!(value["separated"], "1_000");
    assert_eq!(value["copy"], "010");
    assert_eq!(value["signed"], "-010");
    assert_eq!(value["literal"], "1_000");
    assert_eq!(value["explicit"], "010");
    assert_eq!(value["upper"], "0X10");
    assert_eq!(value["tagged"], json!(["null", 7, 7.0, null, "nUlL"]));
    assert_eq!(value["nested"], json!(["010", {"value": "1_000"}]));
    assert_eq!(
        value["booleans"],
        json!([true, true, false, false, "tRuE", true, "TRUE", false])
    );
    for key in ["binary", "octal", "hex"] {
        assert_eq!(value[key], 10);
    }
}

#[cfg(feature = "opa")]
#[test]
fn legacy_number_rejection_retains_the_schema_diagnostic_path() {
    let manifest = r#"agent_control_specification_version: "0.4.0-alpha.1"
policies:
  minimal:
    type: custom
    adapter: test
intervention_points:
  input:
    policy_target: "$.input"
    policy:
      id: minimal
"#;
    for scalar in ["010", "1_000", "1:2:3"] {
        let source = format!("{manifest}approval:\n  timeout_seconds: {scalar}\n");
        let result = agent_control_specification_core::validate_acs_manifest(&source);
        assert!(!result.valid, "accepted {scalar}");
        assert!(
            result.diagnostics.iter().any(|diagnostic| {
                diagnostic.path.as_deref() == Some("/approval/timeout_seconds")
            }),
            "{:?}",
            result.diagnostics
        );
    }
}

#[test]
fn duplicate_key_diagnostic_keeps_the_manifest_context() {
    let error = parse_manifest_yaml_value("key: first\nkey: second\n").unwrap_err();
    assert!(error.to_string().contains("duplicate manifest mapping key"));
}

#[test]
fn depth_and_node_boundaries_fail_before_unbounded_expansion() {
    assert!(parse_manifest_yaml_value(&format!("{}0{}", "[".repeat(63), "]".repeat(63))).is_ok());
    for input in [
        format!("{}0{}", "[".repeat(65), "]".repeat(65)),
        format!("[{}]", vec!["null"; 100_001].join(",")),
    ] {
        assert!(
            matches!(
                parse_manifest_yaml_value(&input),
                Err(RuntimeError::ResourceLimitExceeded(_))
            ),
            "expected resource error"
        );
    }

    let mut bomb = String::from("a0: &a0 [x, x]\n");
    for i in 1..20 {
        bomb.push_str(&format!("a{i}: &a{i} [*a{}, *a{}]\n", i - 1, i - 1));
    }
    let result = parse_manifest_yaml_value(&bomb);
    assert!(
        matches!(result, Err(RuntimeError::ResourceLimitExceeded(_))),
        "{result:?}"
    );
}
