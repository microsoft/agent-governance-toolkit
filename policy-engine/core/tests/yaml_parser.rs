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
