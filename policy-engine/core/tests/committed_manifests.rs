// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Every committed manifest must still parse under the supported grammar.
//!
//! The retarget narrowed `SUPPORTED_MANIFEST_VERSIONS` to a single value, so a
//! manifest left on an older version stops loading at parse time. Most manifests
//! in this tree are examples and reference bundles that no test executes, which
//! means the failure surfaces for a user rather than in CI. One of them reached
//! this branch through a merge and nothing went red.
//!
//! Overlay validation is the right depth here. It enforces the version and the
//! whole grammar while accepting a fragment that only becomes complete after
//! `extends` resolution, so bases and whole manifests can share one check.

use std::fs;
use std::path::{Path, PathBuf};

use agent_control_specification_core::manifest_yaml::validate_manifest_overlay_yaml;

fn policy_engine_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core lives directly under the policy-engine root")
        .to_path_buf()
}

fn collect_manifests(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), "target" | "node_modules" | ".git") {
                continue;
            }
            collect_manifests(&path, found);
            continue;
        }
        if !matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yaml") | Some("yml")
        ) {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        if source
            .lines()
            .any(|line| line.starts_with("agent_control_specification_version"))
        {
            found.push(path);
        }
    }
}

#[test]
fn every_committed_manifest_parses() {
    let root = policy_engine_root();
    let mut manifests = Vec::new();
    collect_manifests(&root, &mut manifests);
    manifests.sort();

    assert!(
        manifests.len() >= 30,
        "expected the manifest sweep to find the committed corpus, found {}",
        manifests.len()
    );

    let mut failures = Vec::new();
    for path in &manifests {
        let source = fs::read_to_string(path).expect("manifest readable");
        if let Err(error) = validate_manifest_overlay_yaml(&source) {
            let shown = path.strip_prefix(&root).unwrap_or(path);
            failures.push(format!("{}: {error}", shown.display()));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} committed manifests no longer parse:\n  {}",
        failures.len(),
        manifests.len(),
        failures.join("\n  ")
    );
}
