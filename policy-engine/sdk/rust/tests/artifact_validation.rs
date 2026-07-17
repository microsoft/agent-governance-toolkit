// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use agent_control_specification::{validate_acs_artifacts, OpaRegoRunner};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::path::Path;

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    manifest: String,
    rego: BTreeMap<String, String>,
    valid: bool,
    codes: Vec<String>,
}

#[test]
fn artifact_validation_matches_shared_parity_corpus() {
    if !OpaRegoRunner::from_environment().is_available() {
        if env::var("AGENT_CONTROL_REQUIRE_OPA").as_deref() == Ok("1") {
            panic!("AGENT_CONTROL_REQUIRE_OPA=1 but the 'opa' executable is not available");
        }
        eprintln!(
            "skipping OPA-dependent test; set AGENT_CONTROL_REQUIRE_OPA=1 to fail when OPA is missing"
        );
        return;
    }
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/artifact-validation-cases.json");
    let corpus: Corpus = serde_json::from_str(&std::fs::read_to_string(fixture).unwrap()).unwrap();

    for case in corpus.cases {
        let result = validate_acs_artifacts(&case.manifest, &case.rego, None);
        let codes = result
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect::<Vec<_>>();
        assert_eq!(result.valid, case.valid, "{}", case.name);
        assert_eq!(codes, case.codes, "{}", case.name);
    }
}
